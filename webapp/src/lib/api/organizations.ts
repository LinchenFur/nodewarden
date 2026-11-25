import type { SessionState } from '../types';
import { base64ToBytes, bytesToBase64, encryptBw, requireWebCrypto, toBufferSource } from '../crypto';
import type { AuthedFetch } from './shared';
import { parseErrorMessage, parseJson } from './shared';
import { getProfile } from './auth';

// RSA-OAEP(SHA-1) encrypts raw bytes with a base64 SPKI public key and returns a
// Bitwarden type-4 EncString ("4.<b64>"). Official Bitwarden clients require the
// organization member key to be asymmetrically encrypted so it can be unwrapped
// with the user's private key; a symmetric (type-2) member key makes the desktop
// SDK throw `EncString(InvalidTypeAsymm)` and hang on an empty vault.
async function rsaEncryptToType4(spkiB64: string, data: Uint8Array): Promise<string> {
  const spki = base64ToBytes(spkiB64);
  const pubKey = await requireWebCrypto().subtle.importKey(
    'spki',
    toBufferSource(spki),
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['encrypt']
  );
  const encrypted = new Uint8Array(await requireWebCrypto().subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, toBufferSource(data)));
  return '4.' + bytesToBase64(encrypted);
}

export interface OrganizationSummary {
  id: string;
  name: string;
  billingEmail: string | null;
  organizationUserId?: string;
  type?: number;
  status?: number;
  object?: string;
}

// Generates a fresh 64-byte organization symmetric key (32 enc + 32 mac),
// matching the Bitwarden AesCbc256-HmacSha256 key layout.
function generateOrgSymmetricKey(): Uint8Array {
  const key = new Uint8Array(64);
  requireWebCrypto().getRandomValues(key);
  return key;
}

async function generateOrgRsaKeyPair(): Promise<{ publicKeyB64: string; privateKey: Uint8Array }> {
  const subtle = requireWebCrypto().subtle;
  const pair = await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
    true,
    ['encrypt', 'decrypt']
  );
  const spki = new Uint8Array(await subtle.exportKey('spki', pair.publicKey));
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
  return { publicKeyB64: bytesToBase64(spki), privateKey: pkcs8 };
}

// Creates an organization fully client-side so the server never sees plaintext keys:
//  - a new org symmetric key, wrapped with the current user key -> member `key`
//  - a new org RSA keypair; the private key is wrapped with the org symmetric key
export async function createOrganization(
  authedFetch: AuthedFetch,
  session: SessionState,
  input: { name: string; billingEmail?: string; collectionName?: string }
): Promise<OrganizationSummary> {
  const name = input.name.trim();
  if (!name) throw new Error('Organization name is required');
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');

  const userEnc = base64ToBytes(session.symEncKey);
  const userMac = base64ToBytes(session.symMacKey);

  const orgKey = generateOrgSymmetricKey();
  const orgEnc = orgKey.slice(0, 32);
  const orgMac = orgKey.slice(32, 64);

  // The member key (profileOrganization.key) must be RSA-encrypted with the
  // user's own public key (type 4), matching official Bitwarden. Clients unwrap
  // it with the user's private key; a symmetric wrap breaks the desktop SDK.
  const profile = await getProfile(authedFetch);
  // The profile only exposes the public key inside accountKeys (official
  // Bitwarden shape); fall back to it when no top-level publicKey is present.
  const accountKeys = profile.accountKeys as { publicKeyEncryptionKeyPair?: { publicKey?: string | null } } | null | undefined;
  const userPublicKey = String(profile.publicKey || accountKeys?.publicKeyEncryptionKeyPair?.publicKey || '').trim();
  if (!userPublicKey) throw new Error('User public key unavailable');
  const memberKey = await rsaEncryptToType4(userPublicKey, orgKey);

  const { publicKeyB64, privateKey } = await generateOrgRsaKeyPair();
  // Wrap the org private key with the org symmetric key.
  const encryptedPrivateKey = await encryptBw(privateKey, orgEnc, orgMac);

  // The collection name is an EncString encrypted with the organization key,
  // matching how official Bitwarden clients store collection names. Storing it
  // as plaintext makes clients fail to decrypt the collection on sync.
  const collectionPlaintext = input.collectionName?.trim() || 'Default Collection';
  const encryptedCollectionName = await encryptBw(
    new TextEncoder().encode(collectionPlaintext),
    orgEnc,
    orgMac
  );

  const resp = await authedFetch('/api/organizations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name,
      billingEmail: input.billingEmail?.trim() || undefined,
      collectionName: encryptedCollectionName,
      key: memberKey,
      keys: { publicKey: publicKeyB64, encryptedPrivateKey },
    }),
  });

  if (!resp.ok) {
    throw new Error(await parseErrorMessage(resp, 'Create organization failed'));
  }
  const body = await parseJson<OrganizationSummary>(resp);
  if (!body?.id) throw new Error('Create organization failed');
  return body;
}


// --- Organization management (members + collections) ---

export interface OrgMember {
  id: string;
  userId: string;
  name: string | null;
  email: string;
  type: number;
  status: number;
  publicKey?: string | null;
}

export async function listOrgMembers(authedFetch: AuthedFetch, orgId: string): Promise<OrgMember[]> {
  const resp = await authedFetch("/api/organizations/" + orgId + "/users");
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, "Load members failed"));
  const body = await parseJson<{ data?: OrgMember[] }>(resp);
  return Array.isArray(body?.data) ? body!.data! : [];
}

export async function inviteOrgMember(authedFetch: AuthedFetch, orgId: string, email: string, type: number): Promise<void> {
  const resp = await authedFetch("/api/organizations/" + orgId + "/users/invite", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ emails: [email], type, accessAll: true }),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, "Invite failed"));
}

export async function getOrgMember(authedFetch: AuthedFetch, orgId: string, membershipId: string): Promise<OrgMember> {
  const resp = await authedFetch("/api/organizations/" + orgId + "/users/" + membershipId);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, "Load member failed"));
  const body = await parseJson<OrgMember>(resp);
  if (!body) throw new Error("Load member failed");
  return body;
}

// Confirms a member: wraps the org key with the member public key (RSA-OAEP).
export async function confirmOrgMember(
  authedFetch: AuthedFetch,
  session: SessionState,
  orgId: string,
  membershipId: string,
  orgKeyRaw: Uint8Array,
  memberPublicKeyB64: string
): Promise<void> {
  const spki = base64ToBytes(memberPublicKeyB64);
  const pubKey = await crypto.subtle.importKey("spki", toBufferSource(spki), { name: "RSA-OAEP", hash: "SHA-1" }, false, ["encrypt"]);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pubKey, toBufferSource(orgKeyRaw)));
  const wrapped = "4." + bytesToBase64(encrypted);
  const resp = await authedFetch("/api/organizations/" + orgId + "/users/" + membershipId + "/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key: wrapped }),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, "Confirm failed"));
}

export async function removeOrgMember(authedFetch: AuthedFetch, orgId: string, membershipId: string): Promise<void> {
  const resp = await authedFetch("/api/organizations/" + orgId + "/users/" + membershipId, { method: "DELETE" });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, "Remove failed"));
}

export async function createOrgCollection(
  authedFetch: AuthedFetch,
  orgId: string,
  encryptedName: string
): Promise<{ id: string }> {
  const resp = await authedFetch("/api/organizations/" + orgId + "/collections", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: encryptedName }),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, "Create collection failed"));
  // The server echoes the created collection (collectionDetails) including its id.
  let id = "";
  try {
    const data = (await resp.json()) as { id?: unknown };
    id = String(data?.id || "");
  } catch { /* id stays empty; caller falls back to a parent refetch */ }
  return { id };
}

export async function deleteOrgCollection(authedFetch: AuthedFetch, orgId: string, collectionId: string): Promise<void> {
  const resp = await authedFetch("/api/organizations/" + orgId + "/collections/" + collectionId, { method: "DELETE" });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, "Delete collection failed"));
}
