import type {
  Collection,
  Env,
  Organization,
  OrgMembership,
  OrgMembershipWithUser,
  OrgRole,
} from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';
import { deleteAllAttachmentsForCiphers } from './attachments';

// Bitwarden organization-user type enum.
const ORG_USER_TYPE: Record<OrgRole, number> = { owner: 0, admin: 1, user: 2 };
const ORG_USER_TYPE_REVERSE: Record<number, OrgRole> = { 0: 'owner', 1: 'admin', 2: 'user' };

// Bitwarden organization-user status enum maps 1:1 to our stored status
// (0 invited, 1 accepted, 2 confirmed). Values match upstream.
export function roleToType(role: OrgRole): number {
  return ORG_USER_TYPE[role] ?? 2;
}

export function typeToRole(type: number): OrgRole {
  return ORG_USER_TYPE_REVERSE[type] ?? 'user';
}

export function canManageOrg(membership: OrgMembership | null): boolean {
  return !!membership && membership.status === 2 && (membership.role === 'owner' || membership.role === 'admin');
}

export function isOwner(membership: OrgMembership | null): boolean {
  return !!membership && membership.status === 2 && membership.role === 'owner';
}

// --- Response serializers (Bitwarden-compatible shapes) ---

export function organizationResponse(org: Organization, membership: OrgMembership): Record<string, unknown> {
  return {
    id: org.id,
    name: org.name,
    businessName: null,
    billingEmail: org.billingEmail,
    key: membership.key,
    status: membership.status,
    type: roleToType(membership.role),
    enabled: true,
    usePolicies: false,
    useGroups: false,
    useDirectory: false,
    useEvents: false,
    useTotp: true,
    use2fa: true,
    useApi: false,
    useSso: false,
    useResetPassword: false,
    selfHost: true,
    seats: null,
    maxCollections: null,
    maxStorageGb: null,
    usersGetPremium: true,
    hasPublicAndPrivateKeys: !!(org.publicKey && org.privateKey),
    providerId: null,
    providerName: null,
    identifier: null,
    permissions: {},
    resetPasswordEnrolled: false,
    userId: membership.userId,
    organizationUserId: membership.id,
    object: 'profileOrganization',
  };
}

export function membershipResponse(m: OrgMembershipWithUser): Record<string, unknown> {
  return {
    id: m.id,
    userId: m.userId,
    organizationId: m.organizationId,
    name: m.name,
    email: m.email,
    type: roleToType(m.role),
    status: m.status,
    accessAll: m.accessAll,
    externalId: null,
    hasMasterPassword: true,
    object: 'organizationUserUserDetails',
  };
}

export function collectionResponse(c: Collection): Record<string, unknown> {
  return {
    id: c.id,
    organizationId: c.organizationId,
    name: c.name,
    externalId: c.externalId,
    readOnly: false,
    hidePasswords: false,
    manage: true,
    object: 'collectionDetails',
  };
}

async function writeOrgAudit(
  storage: StorageService,
  request: Request,
  userId: string,
  action: string,
  targetId: string | null,
  metadata: Record<string, unknown>
): Promise<void> {
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action,
    category: 'data',
    level: action.includes('delete') ? 'security' : 'info',
    targetType: 'organization',
    targetId,
    metadata: { ...metadata, ...auditRequestMetadata(request) },
  });
  // Bump the acting user revision so their next /sync bypasses the cached
  // snapshot and reflects the organization/collection change immediately.
  try { await storage.updateRevisionDate(userId); } catch { /* best-effort cache bust */ }
}

interface OrganizationCreateBody {
  name?: string;
  billingEmail?: string;
  BillingEmail?: string;
  collectionName?: string;
  CollectionName?: string;
  key?: string;
  Key?: string;
  keys?: { publicKey?: string; encryptedPrivateKey?: string; PublicKey?: string; EncryptedPrivateKey?: string };
  Keys?: { publicKey?: string; encryptedPrivateKey?: string; PublicKey?: string; EncryptedPrivateKey?: string };
}

function readStr(...values: (string | undefined)[]): string {
  for (const v of values) {
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return '';
}

// POST /api/organizations
export async function handleCreateOrganization(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: OrganizationCreateBody;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const name = readStr(body.name);
  const memberKey = readStr(body.key, body.Key);
  const keys = body.keys || body.Keys || {};
  const publicKey = readStr(keys.publicKey, keys.PublicKey);
  const encryptedPrivateKey = readStr(keys.encryptedPrivateKey, keys.EncryptedPrivateKey);

  if (!name) return errorResponse('Organization name is required', 400);
  if (!memberKey) return errorResponse('Organization key is required', 400);
  if (!publicKey || !encryptedPrivateKey) return errorResponse('Organization keys are required', 400);

  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  const now = new Date().toISOString();
  const orgId = generateUUID();
  const org: Organization = {
    id: orgId,
    name,
    billingEmail: readStr(body.billingEmail, body.BillingEmail) || user.email,
    publicKey,
    privateKey: encryptedPrivateKey,
    createdAt: now,
    updatedAt: now,
  };

  const membership: OrgMembership = {
    id: generateUUID(),
    organizationId: orgId,
    userId: user.id,
    role: 'owner',
    status: 2,
    key: memberKey,
    accessAll: true,
    createdAt: now,
    updatedAt: now,
  };

  await storage.createOrganization(org);
  await storage.createMembership(membership);

  // Create the default collection for the organization.
  const collectionName = readStr(body.collectionName, body.CollectionName) || 'Default Collection';
  const collection: Collection = {
    id: generateUUID(),
    organizationId: orgId,
    name: collectionName,
    externalId: null,
    createdAt: now,
    updatedAt: now,
  };
  await storage.createCollection(collection);
  await storage.setCollectionAccess({
    collectionId: collection.id,
    membershipId: membership.id,
    readOnly: false,
    hidePasswords: false,
    manage: true,
  });

  await writeOrgAudit(storage, request, userId, 'organization.create', orgId, { name });

  return jsonResponse(organizationResponse(org, membership));
}

// GET /api/organizations/:id
export async function handleGetOrganization(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const membership = await storage.getMembershipForUser(orgId, userId);
  // Only confirmed members may read organization details (name, keys, metadata).
  if (!membership || membership.status !== 2) return errorResponse('Not found', 404);
  const org = await storage.getOrganization(orgId);
  if (!org) return errorResponse('Not found', 404);
  return jsonResponse(organizationResponse(org, membership));
}

interface OrganizationUpdateBody {
  name?: string;
  billingEmail?: string;
  BillingEmail?: string;
}

// PUT /api/organizations/:id
export async function handleUpdateOrganization(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const membership = await storage.getMembershipForUser(orgId, userId);
  if (!canManageOrg(membership)) return errorResponse('Forbidden', 403);
  const org = await storage.getOrganization(orgId);
  if (!org) return errorResponse('Not found', 404);

  let body: OrganizationUpdateBody;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const name = readStr(body.name) || org.name;
  const billingEmail = readStr(body.billingEmail, body.BillingEmail) || org.billingEmail;
  const now = new Date().toISOString();
  await storage.updateOrganization(orgId, name, billingEmail, now);
  await writeOrgAudit(storage, request, userId, 'organization.update', orgId, { name });

  const updated = await storage.getOrganization(orgId);
  return jsonResponse(organizationResponse(updated!, membership!));
}

// DELETE /api/organizations/:id
export async function handleDeleteOrganization(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const membership = await storage.getMembershipForUser(orgId, userId);
  if (!isOwner(membership)) return errorResponse('Forbidden', 403);

  // Capture members before cascade removes them so their clients resync, and
  // purge attachment blobs of org-owned ciphers (R2 has no FK cascade).
  const members = await storage.listMembershipsForOrg(orgId);
  const orgCipherIds = await storage.getCiphersForOrganization(orgId);
  if (orgCipherIds.length) await deleteAllAttachmentsForCiphers(env, orgCipherIds);

  await storage.deleteOrganization(orgId);
  for (const member of members) {
    try { await storage.updateRevisionDate(member.userId); } catch { /* best-effort resync */ }
  }
  await writeOrgAudit(storage, request, userId, 'organization.delete', orgId, {});
  return new Response(null, { status: 200 });
}

// ===================== Member management (invite -> accept -> confirm) =====================

interface InviteBody {
  emails?: string[];
  Emails?: string[];
  type?: number;
  Type?: number;
  accessAll?: boolean;
  AccessAll?: boolean;
  collections?: { id?: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }[];
  Collections?: { id?: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }[];
}

// POST /api/organizations/:orgId/users/invite
// Creates one membership per email. Because this server has no email channel,
// existing users are placed directly into "accepted" state so an owner/admin
// can immediately confirm them (mirrors how mail-less deployments behave).
export async function handleInviteOrganizationUsers(
  request: Request,
  env: Env,
  userId: string,
  orgId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const actor = await storage.getMembershipForUser(orgId, userId);
  if (!canManageOrg(actor)) return errorResponse('Forbidden', 403);

  let body: InviteBody;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const emails = (body.emails || body.Emails || [])
    .map((e) => String(e || '').trim().toLowerCase())
    .filter(Boolean);
  if (!emails.length) return errorResponse('At least one email is required', 400);

  const role = typeToRole(Number(body.type ?? body.Type ?? 2));
  const accessAll = !!(body.accessAll ?? body.AccessAll);
  const collectionsInput = body.collections || body.Collections || [];
  const now = new Date().toISOString();

  for (const email of emails) {
    const invitee = await storage.getUser(email);
    // Without an email channel we can only onboard existing local users.
    if (!invitee) continue;
    const existing = await storage.getMembershipForUser(orgId, invitee.id);
    if (existing) continue;

    const membership: OrgMembership = {
      id: generateUUID(),
      organizationId: orgId,
      userId: invitee.id,
      role,
      // Existing user with a password -> accepted (awaiting confirmation key).
      status: 1,
      key: null,
      accessAll,
      createdAt: now,
      updatedAt: now,
    };
    await storage.createMembership(membership);

    if (!accessAll) {
      for (const c of collectionsInput) {
        const collectionId = String(c.id || '').trim();
        if (!collectionId) continue;
        await storage.setCollectionAccess({
          collectionId,
          membershipId: membership.id,
          readOnly: !!c.readOnly,
          hidePasswords: !!c.hidePasswords,
          manage: !!c.manage,
        });
      }
    }
  }

  await writeOrgAudit(storage, request, userId, 'organization.user.invite', orgId, { emails, role });
  return new Response(null, { status: 200 });
}

// GET /api/organizations/:orgId/users
export async function handleListOrganizationUsers(
  request: Request,
  env: Env,
  userId: string,
  orgId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const actor = await storage.getMembershipForUser(orgId, userId);
  // Only confirmed members may view the member roster (emails + public keys).
  if (!actor || actor.status !== 2) return errorResponse('Not found', 404);
  const members = await storage.listMembershipsForOrg(orgId);
  return jsonResponse({
    data: members.map(membershipResponse),
    object: 'list',
    continuationToken: null,
  });
}

// GET /api/organizations/:orgId/users/:membershipId
// Includes the member's public key so an admin client can wrap the org key
// locally before calling confirm.
export async function handleGetOrganizationUser(
  request: Request,
  env: Env,
  userId: string,
  orgId: string,
  membershipId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const actor = await storage.getMembershipForUser(orgId, userId);
  if (!canManageOrg(actor)) return errorResponse('Forbidden', 403);
  const members = await storage.listMembershipsForOrg(orgId);
  const member = members.find((m) => m.id === membershipId);
  if (!member || member.organizationId !== orgId) return errorResponse('Not found', 404);
  const access = await storage.listAccessForMembership(membershipId);
  return jsonResponse({
    ...membershipResponse(member),
    publicKey: member.publicKey,
    collections: access.map((a) => ({
      id: a.collectionId,
      readOnly: a.readOnly,
      hidePasswords: a.hidePasswords,
      manage: a.manage,
    })),
  });
}

// POST /api/organizations/:orgId/users/:membershipId/accept
// Called by the invited member. Moves status from invited(0) to accepted(1).
export async function handleAcceptOrganizationUser(
  request: Request,
  env: Env,
  userId: string,
  orgId: string,
  membershipId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const membership = await storage.getMembership(membershipId);
  if (!membership || membership.organizationId !== orgId || membership.userId !== userId) {
    return errorResponse('Not found', 404);
  }
  const now = new Date().toISOString();
  await storage.acceptMembership(membershipId, now);
  return new Response(null, { status: 200 });
}

interface ConfirmBody {
  key?: string;
  Key?: string;
}

// POST /api/organizations/:orgId/users/:membershipId/confirm
// Called by an owner/admin. Stores the org key wrapped with the member's public key.
export async function handleConfirmOrganizationUser(
  request: Request,
  env: Env,
  userId: string,
  orgId: string,
  membershipId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const actor = await storage.getMembershipForUser(orgId, userId);
  if (!canManageOrg(actor)) return errorResponse('Forbidden', 403);

  const membership = await storage.getMembership(membershipId);
  if (!membership || membership.organizationId !== orgId) return errorResponse('Not found', 404);

  let body: ConfirmBody;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  const key = readStr(body.key, body.Key);
  if (!key) return errorResponse('Confirmation key is required', 400);

  const now = new Date().toISOString();
  await storage.confirmMembership(membershipId, key, now);
  try { await storage.updateRevisionDate(membership.userId); } catch { /* bump member sync */ }
  await writeOrgAudit(storage, request, userId, 'organization.user.confirm', orgId, { membershipId });
  return new Response(null, { status: 200 });
}

interface UpdateUserBody {
  type?: number;
  Type?: number;
  accessAll?: boolean;
  AccessAll?: boolean;
  collections?: { id?: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }[];
  Collections?: { id?: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }[];
}

// PUT /api/organizations/:orgId/users/:membershipId
export async function handleUpdateOrganizationUser(
  request: Request,
  env: Env,
  userId: string,
  orgId: string,
  membershipId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const actor = await storage.getMembershipForUser(orgId, userId);
  if (!canManageOrg(actor)) return errorResponse('Forbidden', 403);

  const membership = await storage.getMembership(membershipId);
  if (!membership || membership.organizationId !== orgId) return errorResponse('Not found', 404);

  let body: UpdateUserBody;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const newRole = typeToRole(Number(body.type ?? body.Type ?? roleToType(membership.role)));
  // Only an owner may grant the owner role or modify an existing owner. This
  // prevents an admin from escalating itself (or anyone) to owner, or
  // demoting/altering owners.
  if ((newRole === 'owner' || membership.role === 'owner') && !isOwner(actor)) {
    return errorResponse('Only an owner can assign or modify the owner role', 403);
  }
  // Prevent demoting the last remaining owner.
  if (membership.role === 'owner' && newRole !== 'owner') {
    const owners = await storage.countOrganizationOwners(orgId);
    if (owners <= 1) return errorResponse('Cannot demote the last owner', 400);
  }

  const now = new Date().toISOString();
  await storage.updateMembershipRole(membershipId, newRole, now);
  try { await storage.updateRevisionDate(membership.userId); } catch { /* bump member sync */ }

  const accessAll = !!(body.accessAll ?? body.AccessAll);
  if (!accessAll) {
    const collectionsInput = body.collections || body.Collections || [];
    // Only collections that belong to this organization may be assigned.
    const orgCollections = await storage.listCollectionsForOrg(orgId);
    const validCollectionIds = new Set(orgCollections.map((c) => c.id));
    for (const c of collectionsInput) {
      const collectionId = String(c.id || '').trim();
      if (!collectionId) continue;
      if (!validCollectionIds.has(collectionId)) continue;
      await storage.setCollectionAccess({
        collectionId,
        membershipId,
        readOnly: !!c.readOnly,
        hidePasswords: !!c.hidePasswords,
        manage: !!c.manage,
      });
    }
  }

  await writeOrgAudit(storage, request, userId, 'organization.user.update', orgId, { membershipId, role: newRole });
  return new Response(null, { status: 200 });
}

// DELETE /api/organizations/:orgId/users/:membershipId
export async function handleRemoveOrganizationUser(
  request: Request,
  env: Env,
  userId: string,
  orgId: string,
  membershipId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const actor = await storage.getMembershipForUser(orgId, userId);
  if (!canManageOrg(actor)) return errorResponse('Forbidden', 403);

  const membership = await storage.getMembership(membershipId);
  if (!membership || membership.organizationId !== orgId) return errorResponse('Not found', 404);

  // Never remove the last owner.
  if (membership.role === 'owner') {
    // Only an owner may remove another owner.
    if (!isOwner(actor)) return errorResponse('Only an owner can remove an owner', 403);
    const owners = await storage.countOrganizationOwners(orgId);
    if (owners <= 1) return errorResponse('Cannot remove the last owner', 400);
  }

  await storage.deleteMembership(membershipId);
  try { await storage.updateRevisionDate(membership.userId); } catch { /* bump member sync */ }
  await writeOrgAudit(storage, request, userId, 'organization.user.remove', orgId, { membershipId });
  return new Response(null, { status: 200 });
}

// ===================== Collection management =====================

interface CollectionBody {
  name?: string;
  Name?: string;
  externalId?: string;
  ExternalId?: string;
  users?: { id?: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }[];
  Users?: { id?: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }[];
}

// POST /api/organizations/:orgId/collections
export async function handleCreateCollection(
  request: Request,
  env: Env,
  userId: string,
  orgId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const actor = await storage.getMembershipForUser(orgId, userId);
  if (!canManageOrg(actor)) return errorResponse('Forbidden', 403);

  let body: CollectionBody;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const name = readStr(body.name, body.Name);
  if (!name) return errorResponse('Collection name is required', 400);

  const now = new Date().toISOString();
  const collection: Collection = {
    id: generateUUID(),
    organizationId: orgId,
    name,
    externalId: readStr(body.externalId, body.ExternalId) || null,
    createdAt: now,
    updatedAt: now,
  };
  await storage.createCollection(collection);

  // Grant the creator manage access, plus any explicitly listed memberships.
  await storage.setCollectionAccess({
    collectionId: collection.id,
    membershipId: actor!.id,
    readOnly: false,
    hidePasswords: false,
    manage: true,
  });
  const usersInput = body.users || body.Users || [];
  // Only memberships that belong to this organization may be granted access.
  const createOrgMembers = await storage.listMembershipsForOrg(orgId);
  const createValidMembershipIds = new Set(createOrgMembers.map((m) => m.id));
  for (const u of usersInput) {
    const membershipId = String(u.id || '').trim();
    if (!membershipId || membershipId === actor!.id) continue;
    if (!createValidMembershipIds.has(membershipId)) continue;
    await storage.setCollectionAccess({
      collectionId: collection.id,
      membershipId,
      readOnly: !!u.readOnly,
      hidePasswords: !!u.hidePasswords,
      manage: !!u.manage,
    });
  }

  await writeOrgAudit(storage, request, userId, 'organization.collection.create', orgId, { collectionId: collection.id, name });
  return jsonResponse(collectionResponse(collection));
}

// PUT /api/organizations/:orgId/collections/:collectionId
export async function handleUpdateCollection(
  request: Request,
  env: Env,
  userId: string,
  orgId: string,
  collectionId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const actor = await storage.getMembershipForUser(orgId, userId);
  if (!canManageOrg(actor)) return errorResponse('Forbidden', 403);

  const collection = await storage.getCollection(collectionId);
  if (!collection || collection.organizationId !== orgId) return errorResponse('Not found', 404);

  let body: CollectionBody;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const name = readStr(body.name, body.Name) || collection.name;
  const externalId = readStr(body.externalId, body.ExternalId) || collection.externalId;
  const now = new Date().toISOString();
  await storage.updateCollection(collectionId, name, externalId, now);

  const usersInput = body.users || body.Users;
  if (Array.isArray(usersInput)) {
    // Only memberships that belong to this organization may be granted access,
    // to prevent linking foreign-org memberships into this collection.
    const orgMembers = await storage.listMembershipsForOrg(orgId);
    const validMembershipIds = new Set(orgMembers.map((m) => m.id));
    for (const u of usersInput) {
      const membershipId = String(u.id || '').trim();
      if (!membershipId) continue;
      if (!validMembershipIds.has(membershipId)) continue;
      await storage.setCollectionAccess({
        collectionId,
        membershipId,
        readOnly: !!u.readOnly,
        hidePasswords: !!u.hidePasswords,
        manage: !!u.manage,
      });
    }
  }

  await writeOrgAudit(storage, request, userId, 'organization.collection.update', orgId, { collectionId, name });
  const updated = await storage.getCollection(collectionId);
  return jsonResponse(collectionResponse(updated!));
}

// DELETE /api/organizations/:orgId/collections/:collectionId
export async function handleDeleteCollection(
  request: Request,
  env: Env,
  userId: string,
  orgId: string,
  collectionId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const actor = await storage.getMembershipForUser(orgId, userId);
  if (!canManageOrg(actor)) return errorResponse('Forbidden', 403);

  const collection = await storage.getCollection(collectionId);
  if (!collection || collection.organizationId !== orgId) return errorResponse('Not found', 404);

  await storage.deleteCollection(collectionId);
  await writeOrgAudit(storage, request, userId, 'organization.collection.delete', orgId, { collectionId });
  return new Response(null, { status: 200 });
}

// Builds the profileOrganization list for a user's /sync and /profile responses.
// Only confirmed memberships (status 2) carry a usable organization key.
export async function buildProfileOrganizations(
  storage: StorageService,
  userId: string
): Promise<Record<string, unknown>[]> {
  const memberships = await storage.listMembershipsForUser(userId);
  const result: Record<string, unknown>[] = [];
  for (const membership of memberships) {
    const org = await storage.getOrganization(membership.organizationId);
    if (!org) continue;
    result.push(organizationResponse(org, membership));
  }
  return result;
}

// Collections visible to a user across all their organizations, shaped for /sync.
export async function buildSyncCollections(
  storage: StorageService,
  userId: string
): Promise<Record<string, unknown>[]> {
  const memberships = await storage.listMembershipsForUser(userId);
  const result: Record<string, unknown>[] = [];
  for (const membership of memberships) {
    if (membership.status !== 2) continue;
    const collections = await storage.listCollectionsForOrg(membership.organizationId);
    const access = await storage.listAccessForMembership(membership.id);
    const accessById = new Map(access.map((a) => [a.collectionId, a]));
    for (const collection of collections) {
      const granted = membership.accessAll ? null : accessById.get(collection.id);
      // Without accessAll, only expose collections the member is assigned to.
      if (!membership.accessAll && !granted) continue;
      result.push({
        id: collection.id,
        organizationId: collection.organizationId,
        name: collection.name,
        externalId: collection.externalId,
        readOnly: granted ? granted.readOnly : false,
        hidePasswords: granted ? granted.hidePasswords : false,
        manage: granted ? granted.manage : membership.accessAll,
        object: 'collectionDetails',
      });
    }
  }
  return result;
}
