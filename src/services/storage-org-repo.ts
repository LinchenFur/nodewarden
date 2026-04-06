import type {
  CollectionCipher,
  CollectionMembership,
  OrgCollection,
  Organization,
  OrganizationMembership,
} from '../types';
import { OrganizationMembershipStatus } from '../types';

type SqlChunkSize = (fixedBindCount: number) => number;

function mapOrganizationRow(row: any): Organization {
  return {
    id: row.id,
    name: row.name,
    billingEmail: row.billing_email ?? null,
    privateKey: row.private_key ?? null,
    publicKey: row.public_key ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapOrganizationMembershipRow(row: any): OrganizationMembership {
  return {
    id: row.id,
    organizationId: row.organization_id,
    userId: row.user_id,
    userEmail: row.user_email,
    key: row.akey ?? null,
    status: Number(row.status) || 0,
    type: Number(row.atype) || 2,
    accessAll: !!row.access_all,
    externalId: row.external_id ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapCollectionRow(row: any): OrgCollection {
  return {
    id: row.id,
    organizationId: row.organization_id,
    name: row.name,
    externalId: row.external_id ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapCollectionMembershipRow(row: any): CollectionMembership {
  return {
    collectionId: row.collection_id,
    membershipId: row.membership_id,
    readOnly: !!row.read_only,
    hidePasswords: !!row.hide_passwords,
    manage: !!row.manage,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function sanitizeIds(ids: string[]): string[] {
  return Array.from(new Set(ids.map((value) => String(value || '').trim()).filter(Boolean)));
}

export async function getOrganization(db: D1Database, id: string): Promise<Organization | null> {
  const row = await db
    .prepare(
      'SELECT id, name, billing_email, private_key, public_key, created_at, updated_at FROM organizations WHERE id = ?'
    )
    .bind(id)
    .first<any>();
  return row ? mapOrganizationRow(row) : null;
}

export async function saveOrganization(db: D1Database, organization: Organization): Promise<void> {
  await db
    .prepare(
      'INSERT INTO organizations(id, name, billing_email, private_key, public_key, created_at, updated_at) ' +
      'VALUES(?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET name=excluded.name, billing_email=excluded.billing_email, private_key=excluded.private_key, public_key=excluded.public_key, updated_at=excluded.updated_at'
    )
    .bind(
      organization.id,
      organization.name,
      organization.billingEmail,
      organization.privateKey,
      organization.publicKey,
      organization.createdAt,
      organization.updatedAt
    )
    .run();
}

export async function getOrganizationsByUser(db: D1Database, userId: string): Promise<Organization[]> {
  const res = await db
    .prepare(
      `SELECT o.id, o.name, o.billing_email, o.private_key, o.public_key, o.created_at, o.updated_at
       FROM organizations o
       INNER JOIN organization_memberships om ON om.organization_id = o.id
       WHERE om.user_id = ? AND om.status = ?
       ORDER BY o.updated_at DESC`
    )
    .bind(userId, OrganizationMembershipStatus.Confirmed)
    .all<any>();
  return (res.results || []).map(mapOrganizationRow);
}

export async function getOrganizationMembershipById(
  db: D1Database,
  id: string
): Promise<OrganizationMembership | null> {
  const row = await db
    .prepare(
      'SELECT id, organization_id, user_id, user_email, akey, status, atype, access_all, external_id, created_at, updated_at FROM organization_memberships WHERE id = ?'
    )
    .bind(id)
    .first<any>();
  return row ? mapOrganizationMembershipRow(row) : null;
}

export async function getOrganizationMembershipByUserAndOrg(
  db: D1Database,
  userId: string,
  organizationId: string
): Promise<OrganizationMembership | null> {
  const row = await db
    .prepare(
      `SELECT id, organization_id, user_id, user_email, akey, status, atype, access_all, external_id, created_at, updated_at
       FROM organization_memberships
       WHERE user_id = ? AND organization_id = ?
       LIMIT 1`
    )
    .bind(userId, organizationId)
    .first<any>();
  return row ? mapOrganizationMembershipRow(row) : null;
}

export async function getOrganizationMembershipsByUser(
  db: D1Database,
  userId: string,
  confirmedOnly: boolean = false
): Promise<OrganizationMembership[]> {
  const whereStatus = confirmedOnly ? 'AND status = ?' : '';
  const stmt = db.prepare(
    `SELECT id, organization_id, user_id, user_email, akey, status, atype, access_all, external_id, created_at, updated_at
     FROM organization_memberships
     WHERE user_id = ? ${whereStatus}
     ORDER BY updated_at DESC`
  );
  const res = confirmedOnly
    ? await stmt.bind(userId, OrganizationMembershipStatus.Confirmed).all<any>()
    : await stmt.bind(userId).all<any>();
  return (res.results || []).map(mapOrganizationMembershipRow);
}

export async function getOrganizationMembershipsByOrg(
  db: D1Database,
  organizationId: string
): Promise<OrganizationMembership[]> {
  const res = await db
    .prepare(
      `SELECT id, organization_id, user_id, user_email, akey, status, atype, access_all, external_id, created_at, updated_at
       FROM organization_memberships
       WHERE organization_id = ?
       ORDER BY created_at ASC`
    )
    .bind(organizationId)
    .all<any>();
  return (res.results || []).map(mapOrganizationMembershipRow);
}

export async function getConfirmedOrganizationMemberUserIds(
  db: D1Database,
  organizationId: string
): Promise<string[]> {
  const res = await db
    .prepare('SELECT user_id FROM organization_memberships WHERE organization_id = ? AND status = ?')
    .bind(organizationId, OrganizationMembershipStatus.Confirmed)
    .all<{ user_id: string }>();
  return Array.from(new Set((res.results || []).map((row) => String(row.user_id || '').trim()).filter(Boolean)));
}

export async function saveOrganizationMembership(
  db: D1Database,
  membership: OrganizationMembership
): Promise<void> {
  await db
    .prepare(
      'INSERT INTO organization_memberships(id, organization_id, user_id, user_email, akey, status, atype, access_all, external_id, created_at, updated_at) ' +
      'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET user_email=excluded.user_email, akey=excluded.akey, status=excluded.status, atype=excluded.atype, access_all=excluded.access_all, external_id=excluded.external_id, updated_at=excluded.updated_at'
    )
    .bind(
      membership.id,
      membership.organizationId,
      membership.userId,
      membership.userEmail,
      membership.key,
      membership.status,
      membership.type,
      membership.accessAll ? 1 : 0,
      membership.externalId,
      membership.createdAt,
      membership.updatedAt
    )
    .run();
}

export async function deleteOrganizationMembership(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM organization_memberships WHERE id = ?').bind(id).run();
}

export async function getOrgCollection(db: D1Database, id: string): Promise<OrgCollection | null> {
  const row = await db
    .prepare(
      'SELECT id, organization_id, name, external_id, created_at, updated_at FROM org_collections WHERE id = ?'
    )
    .bind(id)
    .first<any>();
  return row ? mapCollectionRow(row) : null;
}

export async function saveOrgCollection(db: D1Database, collection: OrgCollection): Promise<void> {
  await db
    .prepare(
      'INSERT INTO org_collections(id, organization_id, name, external_id, created_at, updated_at) ' +
      'VALUES(?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET name=excluded.name, external_id=excluded.external_id, updated_at=excluded.updated_at'
    )
    .bind(
      collection.id,
      collection.organizationId,
      collection.name,
      collection.externalId,
      collection.createdAt,
      collection.updatedAt
    )
    .run();
}

export async function deleteOrgCollection(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM org_collections WHERE id = ?').bind(id).run();
}

export async function getCollectionsByOrganization(db: D1Database, organizationId: string): Promise<OrgCollection[]> {
  const res = await db
    .prepare(
      'SELECT id, organization_id, name, external_id, created_at, updated_at FROM org_collections WHERE organization_id = ? ORDER BY updated_at DESC'
    )
    .bind(organizationId)
    .all<any>();
  return (res.results || []).map(mapCollectionRow);
}

export async function getCollectionsByUser(db: D1Database, userId: string): Promise<OrgCollection[]> {
  const memberships = await getOrganizationMembershipsByUser(db, userId, true);
  if (!memberships.length) return [];

  const byOrg = new Map<string, OrganizationMembership>();
  for (const membership of memberships) {
    if (!byOrg.has(membership.organizationId)) {
      byOrg.set(membership.organizationId, membership);
    }
  }

  const collections: OrgCollection[] = [];
  for (const membership of byOrg.values()) {
    const orgCollections = await getCollectionsByOrganization(db, membership.organizationId);
    if (membership.accessAll || membership.type === 0 || membership.type === 1) {
      collections.push(...orgCollections);
      continue;
    }

    const access = await getCollectionMembershipsByMembershipIds(db, [membership.id], () => 99);
    const allowedIds = new Set((access.get(membership.id) || []).map((assignment) => assignment.collectionId));
    collections.push(...orgCollections.filter((collection) => allowedIds.has(collection.id)));
  }

  return collections;
}

export async function getCollectionMembershipsByMembershipIds(
  db: D1Database,
  membershipIds: string[],
  sqlChunkSize: SqlChunkSize
): Promise<Map<string, CollectionMembership[]>> {
  const uniqueIds = sanitizeIds(membershipIds);
  const out = new Map<string, CollectionMembership[]>();
  if (!uniqueIds.length) return out;

  const chunkSize = sqlChunkSize(0);
  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    const res = await db
      .prepare(
        `SELECT collection_id, membership_id, read_only, hide_passwords, manage, created_at, updated_at
         FROM collection_memberships
         WHERE membership_id IN (${placeholders})`
      )
      .bind(...chunk)
      .all<any>();
    for (const row of res.results || []) {
      const mapped = mapCollectionMembershipRow(row);
      const existing = out.get(mapped.membershipId) || [];
      existing.push(mapped);
      out.set(mapped.membershipId, existing);
    }
  }

  return out;
}

export async function getCollectionMembershipsByCollectionIds(
  db: D1Database,
  collectionIds: string[],
  sqlChunkSize: SqlChunkSize
): Promise<Map<string, CollectionMembership[]>> {
  const uniqueIds = sanitizeIds(collectionIds);
  const out = new Map<string, CollectionMembership[]>();
  if (!uniqueIds.length) return out;

  const chunkSize = sqlChunkSize(0);
  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    const res = await db
      .prepare(
        `SELECT collection_id, membership_id, read_only, hide_passwords, manage, created_at, updated_at
         FROM collection_memberships
         WHERE collection_id IN (${placeholders})`
      )
      .bind(...chunk)
      .all<any>();
    for (const row of res.results || []) {
      const mapped = mapCollectionMembershipRow(row);
      const existing = out.get(mapped.collectionId) || [];
      existing.push(mapped);
      out.set(mapped.collectionId, existing);
    }
  }

  return out;
}

export async function replaceCollectionMemberships(
  db: D1Database,
  collectionId: string,
  assignments: CollectionMembership[]
): Promise<void> {
  await db.prepare('DELETE FROM collection_memberships WHERE collection_id = ?').bind(collectionId).run();
  for (const assignment of assignments) {
    await db
      .prepare(
        'INSERT INTO collection_memberships(collection_id, membership_id, read_only, hide_passwords, manage, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?)'
      )
      .bind(
        collectionId,
        assignment.membershipId,
        assignment.readOnly ? 1 : 0,
        assignment.hidePasswords ? 1 : 0,
        assignment.manage ? 1 : 0,
        assignment.createdAt,
        assignment.updatedAt
      )
      .run();
  }
}

export async function replaceMembershipCollectionAccess(
  db: D1Database,
  membershipId: string,
  assignments: CollectionMembership[]
): Promise<void> {
  await db.prepare('DELETE FROM collection_memberships WHERE membership_id = ?').bind(membershipId).run();
  for (const assignment of assignments) {
    await db
      .prepare(
        'INSERT INTO collection_memberships(collection_id, membership_id, read_only, hide_passwords, manage, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?)'
      )
      .bind(
        assignment.collectionId,
        membershipId,
        assignment.readOnly ? 1 : 0,
        assignment.hidePasswords ? 1 : 0,
        assignment.manage ? 1 : 0,
        assignment.createdAt,
        assignment.updatedAt
      )
      .run();
  }
}

export async function getCollectionIdsByCipherIds(
  db: D1Database,
  cipherIds: string[],
  sqlChunkSize: SqlChunkSize
): Promise<Map<string, string[]>> {
  const uniqueIds = sanitizeIds(cipherIds);
  const out = new Map<string, string[]>();
  if (!uniqueIds.length) return out;

  const chunkSize = sqlChunkSize(0);
  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    const res = await db
      .prepare(`SELECT collection_id, cipher_id FROM collection_ciphers WHERE cipher_id IN (${placeholders})`)
      .bind(...chunk)
      .all<{ collection_id: string; cipher_id: string }>();
    for (const row of res.results || []) {
      const existing = out.get(row.cipher_id) || [];
      existing.push(row.collection_id);
      out.set(row.cipher_id, existing);
    }
  }

  return out;
}

export async function getCollectionCiphersByCollectionIds(
  db: D1Database,
  collectionIds: string[],
  sqlChunkSize: SqlChunkSize
): Promise<Map<string, CollectionCipher[]>> {
  const uniqueIds = sanitizeIds(collectionIds);
  const out = new Map<string, CollectionCipher[]>();
  if (!uniqueIds.length) return out;

  const chunkSize = sqlChunkSize(0);
  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    const res = await db
      .prepare(`SELECT collection_id, cipher_id FROM collection_ciphers WHERE collection_id IN (${placeholders})`)
      .bind(...chunk)
      .all<{ collection_id: string; cipher_id: string }>();
    for (const row of res.results || []) {
      const mapped: CollectionCipher = {
        collectionId: row.collection_id,
        cipherId: row.cipher_id,
      };
      const existing = out.get(mapped.collectionId) || [];
      existing.push(mapped);
      out.set(mapped.collectionId, existing);
    }
  }

  return out;
}

export async function replaceCipherCollections(
  db: D1Database,
  cipherId: string,
  collectionIds: string[]
): Promise<void> {
  await db.prepare('DELETE FROM collection_ciphers WHERE cipher_id = ?').bind(cipherId).run();
  for (const collectionId of sanitizeIds(collectionIds)) {
    await db
      .prepare('INSERT INTO collection_ciphers(collection_id, cipher_id) VALUES(?, ?)')
      .bind(collectionId, cipherId)
      .run();
  }
}
