import type {
  Collection,
  CollectionAccess,
  Organization,
  OrgMembership,
  OrgMembershipStatus,
  OrgMembershipWithUser,
  OrgRole,
} from '../types';

function mapOrgRow(row: any): Organization {
  return {
    id: row.id,
    name: row.name,
    billingEmail: row.billing_email ?? null,
    publicKey: row.public_key,
    privateKey: row.private_key,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapMembershipRow(row: any): OrgMembership {
  return {
    id: row.id,
    organizationId: row.organization_id,
    userId: row.user_id,
    role: row.role as OrgRole,
    status: Number(row.status) as OrgMembershipStatus,
    key: row.key ?? null,
    accessAll: !!row.access_all,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapMembershipWithUserRow(row: any): OrgMembershipWithUser {
  return {
    ...mapMembershipRow(row),
    email: row.email,
    name: row.name ?? null,
    publicKey: row.public_key ?? null,
  };
}

function mapCollectionRow(row: any): Collection {
  return {
    id: row.id,
    organizationId: row.organization_id,
    name: row.name,
    externalId: row.external_id ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapCollectionAccessRow(row: any): CollectionAccess {
  return {
    collectionId: row.collection_id,
    membershipId: row.membership_id,
    readOnly: !!row.read_only,
    hidePasswords: !!row.hide_passwords,
    manage: !!row.manage,
  };
}

// --- Organizations ---

export async function createOrganization(db: D1Database, org: Organization): Promise<void> {
  await db
    .prepare(
      'INSERT INTO organizations(id, name, billing_email, public_key, private_key, created_at, updated_at) ' +
      'VALUES(?, ?, ?, ?, ?, ?, ?)'
    )
    .bind(org.id, org.name, org.billingEmail, org.publicKey, org.privateKey, org.createdAt, org.updatedAt)
    .run();
}

export async function getOrganization(db: D1Database, id: string): Promise<Organization | null> {
  const row = await db
    .prepare('SELECT * FROM organizations WHERE id = ?')
    .bind(id)
    .first<any>();
  return row ? mapOrgRow(row) : null;
}

export async function updateOrganization(
  db: D1Database,
  id: string,
  name: string,
  billingEmail: string | null,
  updatedAt: string
): Promise<void> {
  await db
    .prepare('UPDATE organizations SET name = ?, billing_email = ?, updated_at = ? WHERE id = ?')
    .bind(name, billingEmail, updatedAt, id)
    .run();
}

export async function deleteOrganization(db: D1Database, id: string): Promise<void> {
  // The ciphers table stores organization_id as a plain column with no FK
  // cascade, so deleting the organization would otherwise leave org-owned
  // ciphers behind. Those ciphers are wrapped with the (now gone) organization
  // key and can never be decrypted again, so they are organization data that
  // must be destroyed alongside the organization. Callers delete attachment
  // blobs first via listCipherIdsForOrganization().
  await db.batch([
    db.prepare('DELETE FROM ciphers WHERE organization_id = ?').bind(id),
    // FK cascade clears memberships/collections/collection_users/cipher_collections.
    db.prepare('DELETE FROM organizations WHERE id = ?').bind(id),
  ]);
}

// --- Memberships ---

export async function createMembership(db: D1Database, m: OrgMembership): Promise<void> {
  await db
    .prepare(
      'INSERT INTO org_memberships(id, organization_id, user_id, role, status, key, access_all, created_at, updated_at) ' +
      'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)'
    )
    .bind(m.id, m.organizationId, m.userId, m.role, m.status, m.key, m.accessAll ? 1 : 0, m.createdAt, m.updatedAt)
    .run();
}

export async function getMembership(db: D1Database, id: string): Promise<OrgMembership | null> {
  const row = await db.prepare('SELECT * FROM org_memberships WHERE id = ?').bind(id).first<any>();
  return row ? mapMembershipRow(row) : null;
}

export async function getMembershipForUser(
  db: D1Database,
  organizationId: string,
  userId: string
): Promise<OrgMembership | null> {
  const row = await db
    .prepare('SELECT * FROM org_memberships WHERE organization_id = ? AND user_id = ?')
    .bind(organizationId, userId)
    .first<any>();
  return row ? mapMembershipRow(row) : null;
}

export async function listMembershipsForOrg(
  db: D1Database,
  organizationId: string
): Promise<OrgMembershipWithUser[]> {
  const res = await db
    .prepare(
      'SELECT m.*, u.email AS email, u.name AS name, u.public_key AS public_key ' +
      'FROM org_memberships m JOIN users u ON u.id = m.user_id ' +
      'WHERE m.organization_id = ? ORDER BY m.created_at ASC'
    )
    .bind(organizationId)
    .all<any>();
  return (res.results || []).map(mapMembershipWithUserRow);
}

export async function listMembershipsForUser(db: D1Database, userId: string): Promise<OrgMembership[]> {
  const res = await db
    .prepare('SELECT * FROM org_memberships WHERE user_id = ? ORDER BY created_at ASC')
    .bind(userId)
    .all<any>();
  return (res.results || []).map(mapMembershipRow);
}

export async function updateMembershipRole(
  db: D1Database,
  id: string,
  role: OrgRole,
  updatedAt: string
): Promise<void> {
  await db
    .prepare('UPDATE org_memberships SET role = ?, updated_at = ? WHERE id = ?')
    .bind(role, updatedAt, id)
    .run();
}

export async function confirmMembership(
  db: D1Database,
  id: string,
  key: string,
  updatedAt: string
): Promise<void> {
  await db
    .prepare('UPDATE org_memberships SET status = 2, key = ?, updated_at = ? WHERE id = ?')
    .bind(key, updatedAt, id)
    .run();
}

export async function acceptMembership(db: D1Database, id: string, updatedAt: string): Promise<void> {
  await db
    .prepare('UPDATE org_memberships SET status = 1, updated_at = ? WHERE id = ? AND status = 0')
    .bind(updatedAt, id)
    .run();
}

export async function deleteMembership(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM org_memberships WHERE id = ?').bind(id).run();
}

export async function countOwners(db: D1Database, organizationId: string): Promise<number> {
  const row = await db
    .prepare("SELECT COUNT(*) AS n FROM org_memberships WHERE organization_id = ? AND role = 'owner'")
    .bind(organizationId)
    .first<any>();
  return Number(row?.n || 0);
}

// --- Collections ---

export async function createCollection(db: D1Database, c: Collection): Promise<void> {
  await db
    .prepare(
      'INSERT INTO collections(id, organization_id, name, external_id, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)'
    )
    .bind(c.id, c.organizationId, c.name, c.externalId, c.createdAt, c.updatedAt)
    .run();
}

export async function getCollection(db: D1Database, id: string): Promise<Collection | null> {
  const row = await db.prepare('SELECT * FROM collections WHERE id = ?').bind(id).first<any>();
  return row ? mapCollectionRow(row) : null;
}

export async function listCollectionsForOrg(db: D1Database, organizationId: string): Promise<Collection[]> {
  const res = await db
    .prepare('SELECT * FROM collections WHERE organization_id = ? ORDER BY name ASC')
    .bind(organizationId)
    .all<any>();
  return (res.results || []).map(mapCollectionRow);
}

export async function updateCollection(
  db: D1Database,
  id: string,
  name: string,
  externalId: string | null,
  updatedAt: string
): Promise<void> {
  await db
    .prepare('UPDATE collections SET name = ?, external_id = ?, updated_at = ? WHERE id = ?')
    .bind(name, externalId, updatedAt, id)
    .run();
}

export async function deleteCollection(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM collections WHERE id = ?').bind(id).run();
}

// --- Collection access (per membership) ---

export async function setCollectionAccess(db: D1Database, access: CollectionAccess): Promise<void> {
  await db
    .prepare(
      'INSERT INTO collection_users(collection_id, membership_id, read_only, hide_passwords, manage) VALUES(?, ?, ?, ?, ?) ' +
      'ON CONFLICT(collection_id, membership_id) DO UPDATE SET read_only=excluded.read_only, hide_passwords=excluded.hide_passwords, manage=excluded.manage'
    )
    .bind(
      access.collectionId,
      access.membershipId,
      access.readOnly ? 1 : 0,
      access.hidePasswords ? 1 : 0,
      access.manage ? 1 : 0
    )
    .run();
}

export async function removeCollectionAccess(
  db: D1Database,
  collectionId: string,
  membershipId: string
): Promise<void> {
  await db
    .prepare('DELETE FROM collection_users WHERE collection_id = ? AND membership_id = ?')
    .bind(collectionId, membershipId)
    .run();
}

export async function listAccessForMembership(
  db: D1Database,
  membershipId: string
): Promise<CollectionAccess[]> {
  const res = await db
    .prepare('SELECT * FROM collection_users WHERE membership_id = ?')
    .bind(membershipId)
    .all<any>();
  return (res.results || []).map(mapCollectionAccessRow);
}

export async function listAccessForCollection(
  db: D1Database,
  collectionId: string
): Promise<CollectionAccess[]> {
  const res = await db
    .prepare('SELECT * FROM collection_users WHERE collection_id = ?')
    .bind(collectionId)
    .all<any>();
  return (res.results || []).map(mapCollectionAccessRow);
}

// --- Cipher <-> Collection links ---

export async function setCipherCollections(
  db: D1Database,
  cipherId: string,
  collectionIds: string[]
): Promise<void> {
  const statements: D1PreparedStatement[] = [
    db.prepare('DELETE FROM cipher_collections WHERE cipher_id = ?').bind(cipherId),
  ];
  const unique = Array.from(new Set(collectionIds.map((id) => String(id || '').trim()).filter(Boolean)));
  for (const collectionId of unique) {
    statements.push(
      db
        .prepare('INSERT OR IGNORE INTO cipher_collections(cipher_id, collection_id) VALUES(?, ?)')
        .bind(cipherId, collectionId)
    );
  }
  await db.batch(statements);
}

export async function getCipherCollectionIds(db: D1Database, cipherId: string): Promise<string[]> {
  const res = await db
    .prepare('SELECT collection_id FROM cipher_collections WHERE cipher_id = ?')
    .bind(cipherId)
    .all<any>();
  return (res.results || []).map((r) => r.collection_id as string);
}

// Returns the distinct cipher ids assigned to any of the given collections.
// Used to deliver organization ciphers to confirmed members during sync,
// scoped to the collections they can access.
export async function getCipherIdsForCollections(
  db: D1Database,
  collectionIds: string[]
): Promise<string[]> {
  const unique = Array.from(new Set(collectionIds.map((c) => String(c || '').trim()).filter(Boolean)));
  if (!unique.length) return [];
  const out = new Set<string>();
  // Chunk to stay within SQLite variable limits.
  const CHUNK = 100;
  for (let i = 0; i < unique.length; i += CHUNK) {
    const chunk = unique.slice(i, i + CHUNK);
    const placeholders = chunk.map(() => '?').join(',');
    const res = await db
      .prepare(`SELECT DISTINCT cipher_id FROM cipher_collections WHERE collection_id IN (${placeholders})`)
      .bind(...chunk)
      .all<any>();
    for (const r of res.results || []) out.add(r.cipher_id as string);
  }
  return Array.from(out);
}

// --- Cipher organization ownership ---

// Marks a cipher as organization-owned (or clears it when organizationId is null).
// Does not touch the encrypted blob; the client re-encrypts the key separately.
export async function setCipherOrganization(
  db: D1Database,
  cipherId: string,
  userId: string,
  organizationId: string | null,
  updatedAt: string
): Promise<boolean> {
  const result = await db
    .prepare('UPDATE ciphers SET organization_id = ?, updated_at = ? WHERE id = ? AND user_id = ?')
    .bind(organizationId, updatedAt, cipherId, userId)
    .run();
  return result.meta.changes === 1;
}

// Returns the organization_id for a cipher, or null for a personal item.
export async function getCipherOrganizationId(db: D1Database, cipherId: string): Promise<string | null> {
  const row = await db
    .prepare('SELECT organization_id FROM ciphers WHERE id = ?')
    .bind(cipherId)
    .first<any>();
  return row?.organization_id ?? null;
}

// Lists ciphers belonging to an organization (used for org-scoped sync/views).
export async function getCiphersForOrganization(db: D1Database, organizationId: string): Promise<string[]> {
  const res = await db
    .prepare('SELECT id FROM ciphers WHERE organization_id = ?')
    .bind(organizationId)
    .all<any>();
  return (res.results || []).map((r) => r.id as string);
}
