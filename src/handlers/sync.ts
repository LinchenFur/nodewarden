import { Env, SyncResponse, CipherResponse, FolderResponse, ProfileResponse } from '../types';
import { StorageService } from '../services/storage';
import { errorResponse } from '../utils/response';
import { cipherToResponse, isCipherResponseSyncCompatible, shouldPreserveRepairableCipherUris } from './ciphers';
import { sendToResponse } from './sends';
import { LIMITS } from '../config/limits';
import {
  buildUserDecryptionCompat,
  buildUserDecryptionOptions,
} from '../utils/user-decryption';
import { buildDomainsResponse } from '../services/domain-rules';
import { buildWebAuthnPrfOption } from '../utils/account-passkeys';
import { buildProfileResponse } from '../utils/profile-response';
import { buildProfileOrganizations, buildSyncCollections } from './organizations';

// CONTRACT:
// /api/sync reuses cipherToResponse() as the single cipher response shaper.
// Filtering invalid cipher responses here protects clients from stored rows that
// would otherwise make official apps fail after an HTTP 200 sync.
// Keep this aligned with src/handlers/ciphers.ts when adding new vault fields.
function buildSyncCacheRequest(
  request: Request,
  userId: string,
  revisionDate: string,
  accountPasskeyCacheTag: string,
  excludeDomains: boolean,
  excludeSends: boolean,
  preserveRepairableUris: boolean
): Request {
  const url = new URL(request.url);
  const cacheUrl = new URL(
    `/__nodewarden/cache/sync/${encodeURIComponent(userId)}/${encodeURIComponent(revisionDate)}/${encodeURIComponent(accountPasskeyCacheTag)}/${excludeDomains ? '1' : '0'}/${excludeSends ? '1' : '0'}/${preserveRepairableUris ? '1' : '0'}`,
    url.origin
  );
  return new Request(cacheUrl.toString(), { method: 'GET' });
}

async function readSyncCache(cacheRequest: Request): Promise<Response | null> {
  const hit = await caches.default.match(cacheRequest);
  if (!hit) return null;
  return new Response(hit.body, hit);
}

async function writeSyncCache(cacheRequest: Request, response: Response): Promise<void> {
  await caches.default.put(cacheRequest, response.clone());
}

// Downgrades an organization cipher response to match the requesting member's
// effective collection permissions. Without this the shaper hardcodes
// edit/viewPassword to true, so readOnly/hidePasswords collection flags would be
// silently ignored for shared ciphers.
function applyMemberRestrictions(
  response: CipherResponse,
  restriction: { readOnly: boolean; hidePasswords: boolean }
): void {
  const r = response as Record<string, unknown>;
  if (restriction.readOnly) {
    r.edit = false;
    const perms = r.permissions;
    if (perms && typeof perms === 'object' && !Array.isArray(perms)) {
      (perms as Record<string, unknown>).delete = false;
      (perms as Record<string, unknown>).restore = false;
    } else {
      r.permissions = { delete: false, restore: false };
    }
  }
  if (restriction.hidePasswords) {
    r.viewPassword = false;
    const login = r.login;
    if (login && typeof login === 'object' && !Array.isArray(login)) {
      // Strip the sensitive secrets so a hidePasswords member cannot read them,
      // even with a modified client. TOTP is a password-equivalent secret here.
      (login as Record<string, unknown>).password = null;
      (login as Record<string, unknown>).totp = null;
    }
  }
}

// GET /api/sync
export async function handleSync(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const excludeDomainsParam = url.searchParams.get('excludeDomains');
  const excludeDomains = excludeDomainsParam !== null && /^(1|true|yes)$/i.test(excludeDomainsParam);
  const excludeSendsParam = url.searchParams.get('excludeSends');
  const excludeSends = excludeSendsParam !== null && /^(1|true|yes)$/i.test(excludeSendsParam);
  const preserveRepairableUris = shouldPreserveRepairableCipherUris(request);

  const user = await storage.getUserById(userId);
  if (!user) {
    return errorResponse('User not found', 404);
  }

  const [revisionDate, accountPasskeys, twoFactorPasskeys] = await Promise.all([
    storage.getRevisionDate(userId),
    storage.getAccountPasskeyCredentialsByUserId(userId),
    storage.getAccountPasskeyCredentialsByUserId(userId, 'twoFactor'),
  ]);
  const accountPasskeyCacheTag = [
    ...accountPasskeys.map((credential) => [
      credential.id,
      credential.updatedAt,
      credential.supportsPrf ? '1' : '0',
      credential.encryptedUserKey && credential.encryptedPublicKey && credential.encryptedPrivateKey ? '1' : '0',
    ].join(':')),
    // The profile reports twoFactorEnabled, so the cached response must change
    // when a two-factor passkey is added or removed.
    ...twoFactorPasskeys.map((credential) => ['2fa', credential.id, credential.updatedAt].join(':')),
  ].join(',');
  const cacheRequest = buildSyncCacheRequest(request, userId, revisionDate, accountPasskeyCacheTag, excludeDomains, excludeSends, preserveRepairableUris);
  const cachedResponse = await readSyncCache(cacheRequest);
  if (cachedResponse) {
    return cachedResponse;
  }

  const [ciphers, folders, sends, attachmentsByCipher, domainSettings] = await Promise.all([
    storage.getAllCiphers(userId),
    storage.getAllFolders(userId),
    excludeSends ? Promise.resolve([]) : storage.getAllSends(userId),
    storage.getAttachmentsByUserId(userId),
    excludeDomains ? Promise.resolve(null) : storage.getUserDomainSettings(userId),
  ]);
  const [profileOrganizations, syncCollections] = await Promise.all([
    buildProfileOrganizations(storage, userId),
    buildSyncCollections(storage, userId),
  ]);

  // Map organization-owned ciphers to their collection ids (stored outside the blob).
  const orgCipherCollectionIds = new Map<string, string[]>();
  for (const cipher of ciphers) {
    if ((cipher as any).organizationId || (cipher as any).organization_id) {
      orgCipherCollectionIds.set(cipher.id, await storage.getCipherCollectionIds(cipher.id));
    }
  }

  // Deliver organization ciphers shared by OTHER members. Sync's base query only
  // returns ciphers the user personally owns, so without this a confirmed member
  // never receives items shared into their collections. Access is strictly
  // scoped to the collections the member can see (accessAll => all org
  // collections; otherwise only assigned collections), preserving confidentiality.
  const ownedCipherIds = new Set(ciphers.map((c) => c.id));
  const memberships = await storage.listMembershipsForUser(userId);
  const foreignOrgCipherIds = new Set<string>();
  // Tracks the accessible collections per cipher so the response only exposes
  // collection links the member is actually entitled to.
  const accessibleCollectionsByCipher = new Map<string, Set<string>>();
  // Per-collection access flags for the requesting member. accessAll members
  // have unrestricted access to every collection in that organization.
  const collectionFlagsById = new Map<string, { readOnly: boolean; hidePasswords: boolean }>();
  // Effective restrictions per shared cipher. Like Bitwarden, the most
  // permissive collection path wins: a restriction applies only when every
  // visible collection carrying the cipher is restricted.
  const restrictionsByCipher = new Map<string, { readOnly: boolean; hidePasswords: boolean }>();
  for (const membership of memberships) {
    if (membership.status !== 2) continue; // only confirmed members
    const orgCollections = await storage.listCollectionsForOrg(membership.organizationId);
    let accessibleCollectionIds: string[];
    if (membership.accessAll) {
      accessibleCollectionIds = orgCollections.map((c) => c.id);
      for (const c of orgCollections) collectionFlagsById.set(c.id, { readOnly: false, hidePasswords: false });
    } else {
      const access = await storage.listAccessForMembership(membership.id);
      const orgCollectionIdSet = new Set(orgCollections.map((c) => c.id));
      accessibleCollectionIds = access
        .map((a) => a.collectionId)
        .filter((id) => orgCollectionIdSet.has(id));
      for (const a of access) {
        if (!orgCollectionIdSet.has(a.collectionId)) continue;
        collectionFlagsById.set(a.collectionId, { readOnly: !!a.readOnly, hidePasswords: !!a.hidePasswords });
      }
    }
    if (!accessibleCollectionIds.length) continue;
    const accessibleSet = new Set(accessibleCollectionIds);
    const cipherIds = await storage.getCipherIdsForCollections(accessibleCollectionIds);
    for (const cid of cipherIds) {
      if (ownedCipherIds.has(cid)) continue; // user already has their own copy
      foreignOrgCipherIds.add(cid);
      const links = accessibleCollectionsByCipher.get(cid) || new Set<string>();
      for (const colId of accessibleSet) links.add(colId);
      accessibleCollectionsByCipher.set(cid, links);
    }
  }
  if (foreignOrgCipherIds.size) {
    const foreignCiphers = await storage.getCiphersByIdsAnyOwner(Array.from(foreignOrgCipherIds));
    const foreignAttachments = await storage.getAttachmentsByCipherIds(Array.from(foreignOrgCipherIds));
    for (const cipher of foreignCiphers) {
      // Only expose the collection links the member can access, intersected with
      // the cipher's actual collection memberships.
      const actualCollections = await storage.getCipherCollectionIds(cipher.id);
      const allowed = accessibleCollectionsByCipher.get(cipher.id) || new Set<string>();
      const visibleCollections = actualCollections.filter((c) => allowed.has(c));
      if (!visibleCollections.length) continue; // not actually visible to this member
      orgCipherCollectionIds.set(cipher.id, visibleCollections);
      const flags = visibleCollections.map((c) => collectionFlagsById.get(c) || { readOnly: false, hidePasswords: false });
      restrictionsByCipher.set(cipher.id, {
        readOnly: flags.every((f) => f.readOnly),
        hidePasswords: flags.every((f) => f.hidePasswords),
      });
      ciphers.push(cipher);
      const atts = foreignAttachments.get(cipher.id);
      if (atts && atts.length) attachmentsByCipher.set(cipher.id, atts);
    }
  }

  const webAuthnPrfOptions = accountPasskeys
    .map(buildWebAuthnPrfOption)
    .filter((option): option is NonNullable<typeof option> => !!option);
  const userDecryptionOptions = buildUserDecryptionOptions(user, webAuthnPrfOptions[0] || null);
  const validFolderIds = new Set(folders.map((folder) => folder.id));

  const profile: ProfileResponse = buildProfileResponse(user, env, profileOrganizations, {
    hasTwoFactorPasskey: twoFactorPasskeys.length > 0,
  });

  const cipherResponses: CipherResponse[] = [];
  for (const cipher of ciphers) {
    const response = cipherToResponse(cipher, attachmentsByCipher.get(cipher.id) || [], { preserveRepairableUris, validFolderIds });
    // For organization ciphers, expose only the collection links scoped to what
    // the member may access (set above). This prevents leaking collection
    // assignments the member is not entitled to see.
    if (orgCipherCollectionIds.has(cipher.id)) {
      (response as { collectionIds?: string[] }).collectionIds = orgCipherCollectionIds.get(cipher.id) || [];
    }
    const restriction = restrictionsByCipher.get(cipher.id);
    if (restriction) applyMemberRestrictions(response, restriction);
    if (isCipherResponseSyncCompatible(response)) {
      cipherResponses.push(response);
    }
  }

  const folderResponses: FolderResponse[] = [];
  for (const folder of folders) {
    folderResponses.push({
      id: folder.id,
      name: folder.name,
      revisionDate: folder.updatedAt,
      creationDate: folder.createdAt,
      object: 'folder',
    });
  }

  const sendResponses = sends.map(sendToResponse);
  const syncResponse: SyncResponse = {
    profile,
    folders: folderResponses,
    collections: syncCollections,
    ciphers: cipherResponses,
    domains: excludeDomains
      ? null
      : buildDomainsResponse(
          domainSettings?.equivalentDomains || [],
          domainSettings?.customEquivalentDomains || [],
          domainSettings?.excludedGlobalEquivalentDomains || [],
          { omitExcludedGlobals: true }
        ),
    policies: [],
    policiesNew: [],
    sends: sendResponses,
    UserDecryption: {
      MasterPasswordUnlock: userDecryptionOptions.MasterPasswordUnlock,
      TrustedDeviceOption: null,
      KeyConnectorOption: null,
      WebAuthnPrfOption: webAuthnPrfOptions[0] || null,
      WebAuthnPrfOptions: webAuthnPrfOptions,
      V2UpgradeToken: null,
      UserKeyId: user.userKeyId ?? null,
      Object: 'userDecryption',
    },
    UserDecryptionOptions: userDecryptionOptions,
    userDecryption: buildUserDecryptionCompat(user) as SyncResponse['userDecryption'],
    object: 'sync',
  };

  const response = new Response(JSON.stringify(syncResponse), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': `private, max-age=${Math.max(1, Math.floor(LIMITS.cache.syncResponseTtlMs / 1000))}`,
    },
  });
  await writeSyncCache(cacheRequest, response);
  return response;
}
