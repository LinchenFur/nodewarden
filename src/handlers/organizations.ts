import {
  type CollectionMembership,
  type Env,
  type OrgCollection,
  type Organization,
  type OrganizationMembership,
} from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { notifyUserVaultSync } from '../durable/notifications-hub';
import { readActingDeviceIdentifier } from '../utils/device';
import {
  getAccessibleCiphersForUser,
  buildCollectionDetails,
  buildOrganizationMemberDetails,
  buildProfileOrganizations,
  loadOrganizationAccessSnapshot,
  resolveCipherAccess,
} from '../utils/organization-access';
import {
  hasFullOrganizationAccess,
  isMembershipAtLeast,
  isOrganizationManager,
  mergeCollectionAccess,
  membershipTypeToResponse,
  normalizeOrganizationMembershipType,
} from '../utils/organization-permissions';
import { cipherToResponse } from './ciphers';

function getBoolean(value: unknown): boolean {
  return !!value;
}

function normalizeOptionalString(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

async function notifyOrganizationUsersSync(
  request: Request,
  env: Env,
  storage: StorageService,
  organizationId: string
): Promise<void> {
  const contextId = readActingDeviceIdentifier(request);
  const revisions = await storage.updateRevisionDatesForOrganization(organizationId);
  for (const [userId, revisionDate] of revisions.entries()) {
    await notifyUserVaultSync(env, userId, revisionDate, contextId);
  }
}

async function requireConfirmedMembership(
  storage: StorageService,
  userId: string,
  organizationId: string
): Promise<OrganizationMembership | null> {
  const membership = await storage.getOrganizationMembershipByUserAndOrg(userId, organizationId);
  if (!membership || Number(membership.status) !== 2) {
    return null;
  }
  return membership;
}

function buildOrganizationResponse(organization: Organization): any {
  return {
    id: organization.id,
    identifier: null,
    name: organization.name,
    billingEmail: organization.billingEmail,
    seats: 20,
    maxCollections: null,
    usersGetPremium: true,
    useTotp: true,
    usePolicies: true,
    useGroups: false,
    useEvents: false,
    useDirectory: false,
    useApi: true,
    useResetPassword: false,
    useSecretsManager: false,
    usePasswordManager: true,
    useSso: false,
    useScim: false,
    use2fa: true,
    useKeyConnector: false,
    useCustomPermissions: true,
    selfHost: true,
    hasPublicAndPrivateKeys: !!organization.privateKey && !!organization.publicKey,
    productTierType: 3,
    keyConnectorEnabled: false,
    keyConnectorUrl: null,
    object: 'organization',
  };
}

async function buildOrganizationProfileResponse(
  storage: StorageService,
  userId: string,
  organization: Organization
): Promise<any> {
  const organizations = await buildProfileOrganizations(storage, userId);
  const match = organizations.find((entry) => entry.id === organization.id);
  if (match) {
    return {
      ...match,
      billingEmail: organization.billingEmail,
      name: organization.name,
      hasPublicAndPrivateKeys: !!organization.privateKey && !!organization.publicKey,
    };
  }

  return {
    ...buildOrganizationResponse(organization),
    userId,
    status: 2,
    type: 0,
    enabled: true,
    object: 'organization',
  };
}

function parseMemberCollectionAssignments(
  bodyCollections: any[] | null | undefined,
  membershipId: string,
  now: string
): CollectionMembership[] {
  if (!Array.isArray(bodyCollections)) return [];
  return bodyCollections
    .map((entry) => {
      const collectionId = normalizeOptionalString(entry?.id);
      if (!collectionId) return null;
      return {
        collectionId,
        membershipId,
        readOnly: getBoolean(entry?.readOnly),
        hidePasswords: getBoolean(entry?.hidePasswords),
        manage: getBoolean(entry?.manage),
        createdAt: now,
        updatedAt: now,
      } satisfies CollectionMembership;
    })
    .filter(Boolean) as CollectionMembership[];
}

async function buildCollectionAccessDetailsResponse(
  storage: StorageService,
  userId: string,
  organizationId: string,
  collection: OrgCollection
): Promise<any> {
  const snapshot = await loadOrganizationAccessSnapshot(storage, userId);
  const membershipsByOrg = await storage.getOrganizationMembershipsByOrg(organizationId);
  const assignmentsByCollectionId = await storage.getCollectionMembershipsByCollectionIds([collection.id]);
  const base = await buildCollectionDetails(storage, userId, collection, snapshot);
  const users = [];

  for (const member of membershipsByOrg) {
    if (Number(member.status) !== 2) continue;
    if (hasFullOrganizationAccess(member)) {
      users.push({
        id: member.id,
        readOnly: false,
        hidePasswords: false,
        manage: true,
      });
      continue;
    }

    const assignment = (assignmentsByCollectionId.get(collection.id) || []).find((entry) => entry.membershipId === member.id);
    if (!assignment) continue;

    users.push({
      id: member.id,
      readOnly: assignment.readOnly,
      hidePasswords: assignment.hidePasswords,
      manage: assignment.manage || membershipTypeToResponse(member.type, member.accessAll) === 4,
    });
  }

  return {
    ...base,
    assigned: true,
    users,
    groups: [],
    unmanaged: false,
    object: 'collectionAccessDetails',
  };
}

async function requireCollectionAccessContext(
  storage: StorageService,
  userId: string,
  organizationId: string,
  collectionId: string
): Promise<{
  membership: OrganizationMembership;
  collection: OrgCollection;
  matchedAssignments: CollectionMembership[];
  canManage: boolean;
} | null> {
  const membership = await requireConfirmedMembership(storage, userId, organizationId);
  if (!membership) return null;

  const collection = await storage.getOrgCollection(collectionId);
  if (!collection || collection.organizationId !== organizationId) {
    return null;
  }

  const snapshot = await loadOrganizationAccessSnapshot(storage, userId);
  const matchedAssignments = (snapshot.assignmentsByMembershipId.get(membership.id) || [])
    .filter((assignment) => assignment.collectionId === collectionId);

  if (!hasFullOrganizationAccess(membership) && !matchedAssignments.length) {
    return null;
  }

  const merged = mergeCollectionAccess(matchedAssignments, isOrganizationManager(membership));
  const canManage = hasFullOrganizationAccess(membership) || merged.manage;

  return {
    membership,
    collection,
    matchedAssignments,
    canManage,
  };
}

async function buildCollectionUsersResponse(
  storage: StorageService,
  organizationId: string,
  collectionId: string
): Promise<any[]> {
  const assignmentsByCollectionId = await storage.getCollectionMembershipsByCollectionIds([collectionId]);
  const assignmentsByMembershipId = new Map(
    (assignmentsByCollectionId.get(collectionId) || []).map((assignment) => [assignment.membershipId, assignment])
  );
  const members = await storage.getOrganizationMembershipsByOrg(organizationId);
  const data = [];

  for (const member of members) {
    if (Number(member.status) !== 2) continue;

    const membershipType = membershipTypeToResponse(member.type, member.accessAll);
    const assignment = assignmentsByMembershipId.get(member.id);
    if (!hasFullOrganizationAccess(member) && !assignment) continue;

    const user = await storage.getUserById(member.userId);
    data.push({
      id: member.id,
      organizationUserId: member.id,
      name: user?.name ?? null,
      email: member.userEmail,
      status: member.status,
      type: membershipType,
      accessAll: member.accessAll,
      readOnly: assignment ? assignment.readOnly : false,
      hidePasswords: assignment ? assignment.hidePasswords : false,
      manage: assignment ? assignment.manage || membershipType === 4 : true,
      object: 'collectionUserDetails',
    });
  }

  return data;
}

function parseFullCollectionPayload(body: any): {
  name: string | null;
  externalId: string | null;
  users: Array<{ id?: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }>;
} {
  return {
    name: normalizeOptionalString(body?.name),
    externalId: normalizeOptionalString(body?.externalId),
    users: Array.isArray(body?.users) ? body.users : [],
  };
}

export async function handleGetOrganizations(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const organizations = await buildProfileOrganizations(storage, userId);
  return jsonResponse({
    data: organizations,
    object: 'list',
    continuationToken: null,
  });
}

export async function handleCreateOrganization(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: {
    name?: string;
    billingEmail?: string;
    collectionName?: string;
    key?: string;
    keys?: {
      encryptedPrivateKey?: string;
      publicKey?: string;
    };
  };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const name = normalizeOptionalString(body.name);
  if (!name) {
    return errorResponse('Organization name is required', 400);
  }

  const now = new Date().toISOString();
  const organization: Organization = {
    id: generateUUID(),
    name,
    billingEmail: normalizeOptionalString(body.billingEmail) ?? user.email,
    privateKey: normalizeOptionalString(body.keys?.encryptedPrivateKey),
    publicKey: normalizeOptionalString(body.keys?.publicKey),
    createdAt: now,
    updatedAt: now,
  };
  const membership: OrganizationMembership = {
    id: generateUUID(),
    organizationId: organization.id,
    userId,
    userEmail: user.email,
    key: normalizeOptionalString(body.key),
    status: 2,
    type: 0,
    accessAll: true,
    externalId: null,
    createdAt: now,
    updatedAt: now,
  };
  const collection: OrgCollection = {
    id: generateUUID(),
    organizationId: organization.id,
    name: normalizeOptionalString(body.collectionName) ?? 'Default',
    externalId: null,
    createdAt: now,
    updatedAt: now,
  };

  await storage.saveOrganization(organization);
  await storage.saveOrganizationMembership(membership);
  await storage.saveOrgCollection(collection);
  await notifyOrganizationUsersSync(request, env, storage, organization.id);

  return jsonResponse(await buildOrganizationProfileResponse(storage, userId, organization), 200);
}

export async function handleGetOrganization(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string
): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const membership = await requireConfirmedMembership(storage, userId, organizationId);
  if (!membership) return errorResponse('Organization not found', 404);
  const organization = await storage.getOrganization(organizationId);
  if (!organization) return errorResponse('Organization not found', 404);
  return jsonResponse(await buildOrganizationProfileResponse(storage, userId, organization));
}

export async function handleUpdateOrganization(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const membership = await requireConfirmedMembership(storage, userId, organizationId);
  if (!membership || normalizeOrganizationMembershipType(membership.type) !== 0) {
    return errorResponse('Organization not found', 404);
  }

  const organization = await storage.getOrganization(organizationId);
  if (!organization) return errorResponse('Organization not found', 404);

  let body: { name?: string; billingEmail?: string | null };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const name = normalizeOptionalString(body.name);
  if (!name) return errorResponse('Organization name is required', 400);

  organization.name = name;
  organization.billingEmail = normalizeOptionalString(body.billingEmail);
  organization.updatedAt = new Date().toISOString();
  await storage.saveOrganization(organization);
  await notifyOrganizationUsersSync(request, env, storage, organizationId);
  return jsonResponse(await buildOrganizationProfileResponse(storage, userId, organization));
}

export async function handleGetOrganizationPublicKey(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string
): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const membership = await requireConfirmedMembership(storage, userId, organizationId);
  if (!membership) return errorResponse('Organization not found', 404);
  const organization = await storage.getOrganization(organizationId);
  if (!organization) return errorResponse('Organization not found', 404);
  return jsonResponse({
    object: 'organizationPublicKey',
    publicKey: organization.publicKey,
  });
}

export async function handleGetCollections(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const collections = await storage.getCollectionsByUser(userId);
  return jsonResponse({
    data: collections.map((collection) => ({
      id: collection.id,
      organizationId: collection.organizationId,
      externalId: collection.externalId,
      name: collection.name,
      object: 'collection',
    })),
    object: 'list',
    continuationToken: null,
  });
}

export async function handleGetOrganizationCollections(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string
): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const membership = await requireConfirmedMembership(storage, userId, organizationId);
  if (!membership) return errorResponse('Organization not found', 404);
  if (!hasFullOrganizationAccess(membership)) {
    return errorResponse('Resource not found.', 404);
  }

  const collections = await storage.getCollectionsByOrganization(organizationId);
  return jsonResponse({
    data: collections.map((collection) => ({
      id: collection.id,
      organizationId: collection.organizationId,
      externalId: collection.externalId,
      name: collection.name,
      object: 'collection',
    })),
    object: 'list',
    continuationToken: null,
  });
}

export async function handleGetOrganizationCollectionsDetails(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string
): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const membership = await requireConfirmedMembership(storage, userId, organizationId);
  if (!membership) return errorResponse('Organization not found', 404);

  const snapshot = await loadOrganizationAccessSnapshot(storage, userId);
  const collections = await storage.getCollectionsByOrganization(organizationId);
  const assignmentsByCollectionId = await storage.getCollectionMembershipsByCollectionIds(collections.map((collection) => collection.id));
  const membershipsByOrg = await storage.getOrganizationMembershipsByOrg(organizationId);

  const details = [];
  for (const collection of collections) {
    const assigned = hasFullOrganizationAccess(membership)
      || (snapshot.assignmentsByMembershipId.get(membership.id) || []).some((assignment) => assignment.collectionId === collection.id);
    if (!assigned) continue;
    void membershipsByOrg;
    void assignmentsByCollectionId;
    details.push(await buildCollectionAccessDetailsResponse(storage, userId, organizationId, collection));
  }

  return jsonResponse({
    data: details,
    object: 'list',
    continuationToken: null,
  });
}

export async function handleGetOrganizationCollectionDetails(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  collectionId: string
): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const context = await requireCollectionAccessContext(storage, userId, organizationId, collectionId);
  if (!context) return errorResponse('Collection not found', 404);
  return jsonResponse(await buildCollectionAccessDetailsResponse(storage, userId, organizationId, context.collection));
}

export async function handleGetOrganizationCollectionUsers(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  collectionId: string
): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const context = await requireCollectionAccessContext(storage, userId, organizationId, collectionId);
  if (!context) return errorResponse('Collection not found', 404);

  return jsonResponse(await buildCollectionUsersResponse(storage, organizationId, collectionId));
}

export async function handleUpdateOrganizationCollectionUsers(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  collectionId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const context = await requireCollectionAccessContext(storage, userId, organizationId, collectionId);
  if (!context) return errorResponse('Collection not found', 404);
  if (!context.canManage) return errorResponse('Insufficient permissions', 403);

  let body: {
    users?: Array<{ id?: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }>;
  } | Array<{ id?: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }>;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const userAssignments = Array.isArray(body) ? body : body.users || [];
  const organizationMembers = await storage.getOrganizationMembershipsByOrg(organizationId);
  const membershipIds = new Set(organizationMembers.map((entry) => entry.id));
  const now = new Date().toISOString();
  const assignments: CollectionMembership[] = [];

  for (const userAssignment of userAssignments) {
    const memberId = normalizeOptionalString(userAssignment?.id);
    if (!memberId || !membershipIds.has(memberId)) continue;
    assignments.push({
      collectionId,
      membershipId: memberId,
      readOnly: getBoolean(userAssignment.readOnly),
      hidePasswords: getBoolean(userAssignment.hidePasswords),
      manage: getBoolean(userAssignment.manage),
      createdAt: now,
      updatedAt: now,
    });
  }

  await storage.replaceCollectionMemberships(collectionId, assignments);
  await notifyOrganizationUsersSync(request, env, storage, organizationId);

  return jsonResponse({
    data: await buildCollectionUsersResponse(storage, organizationId, collectionId),
    object: 'list',
    continuationToken: null,
  });
}

export async function handleCreateOrganizationCollection(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const membership = await requireConfirmedMembership(storage, userId, organizationId);
  if (!membership) return errorResponse('Organization not found', 404);
  if (!hasFullOrganizationAccess(membership) && !(normalizeOrganizationMembershipType(membership.type) === 3 && membership.accessAll)) {
    return errorResponse("You don't have permission to create collections", 403);
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const payload = parseFullCollectionPayload(body);
  if (!payload.name) return errorResponse('Collection name is required', 400);

  const now = new Date().toISOString();
  const collection: OrgCollection = {
    id: generateUUID(),
    organizationId,
    name: payload.name,
    externalId: payload.externalId,
    createdAt: now,
    updatedAt: now,
  };

  await storage.saveOrgCollection(collection);
  const memberIds = new Set((await storage.getOrganizationMembershipsByOrg(organizationId)).map((entry) => entry.id));
  const assignments: CollectionMembership[] = [];
  for (const userAssignment of payload.users) {
    const memberId = normalizeOptionalString(userAssignment?.id);
    if (!memberId || !memberIds.has(memberId)) continue;
    const member = await storage.getOrganizationMembershipById(memberId);
    if (!member || member.accessAll || hasFullOrganizationAccess(member)) continue;
    assignments.push({
      collectionId: collection.id,
      membershipId: memberId,
      readOnly: getBoolean(userAssignment.readOnly),
      hidePasswords: getBoolean(userAssignment.hidePasswords),
      manage: getBoolean(userAssignment.manage),
      createdAt: now,
      updatedAt: now,
    });
  }
  await storage.replaceCollectionMemberships(collection.id, assignments);
  await notifyOrganizationUsersSync(request, env, storage, organizationId);

  const snapshot = await loadOrganizationAccessSnapshot(storage, userId);
  return jsonResponse(await buildCollectionDetails(storage, userId, collection, snapshot), 200);
}

export async function handleUpdateOrganizationCollection(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  collectionId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const context = await requireCollectionAccessContext(storage, userId, organizationId, collectionId);
  if (!context || !context.canManage) return errorResponse('Collection not found', 404);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const payload = parseFullCollectionPayload(body);
  if (!payload.name) return errorResponse('Collection name is required', 400);

  const collection = context.collection;
  const now = new Date().toISOString();
  collection.name = payload.name;
  collection.externalId = payload.externalId;
  collection.updatedAt = now;
  await storage.saveOrgCollection(collection);

  const organizationMembers = await storage.getOrganizationMembershipsByOrg(organizationId);
  const membershipIds = new Set(organizationMembers.map((entry) => entry.id));
  const assignments: CollectionMembership[] = [];
  for (const userAssignment of payload.users) {
    const memberId = normalizeOptionalString(userAssignment?.id);
    if (!memberId || !membershipIds.has(memberId)) continue;
    const member = organizationMembers.find((entry) => entry.id === memberId) || null;
    if (!member || member.accessAll || hasFullOrganizationAccess(member)) continue;
    assignments.push({
      collectionId,
      membershipId: memberId,
      readOnly: getBoolean(userAssignment.readOnly),
      hidePasswords: getBoolean(userAssignment.hidePasswords),
      manage: getBoolean(userAssignment.manage),
      createdAt: now,
      updatedAt: now,
    });
  }

  await storage.replaceCollectionMemberships(collectionId, assignments);
  await notifyOrganizationUsersSync(request, env, storage, organizationId);

  const snapshot = await loadOrganizationAccessSnapshot(storage, userId);
  return jsonResponse(await buildCollectionDetails(storage, userId, collection, snapshot));
}

export async function handleDeleteOrganizationCollection(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  collectionId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const context = await requireCollectionAccessContext(storage, userId, organizationId, collectionId);
  if (!context || !context.canManage) return errorResponse('Collection not found', 404);

  await storage.deleteOrgCollection(collectionId);
  await notifyOrganizationUsersSync(request, env, storage, organizationId);
  return new Response(null, { status: 200 });
}

export async function handleGetOrganizationMembers(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string
): Promise<Response> {
  void env;
  const storage = new StorageService(env.DB);
  const membership = await requireConfirmedMembership(storage, userId, organizationId);
  if (!membership) return errorResponse('Organization not found', 404);

  const url = new URL(request.url);
  const includeCollections = url.searchParams.get('includeCollections') === 'true';
  const members = await storage.getOrganizationMembershipsByOrg(organizationId);
  const data = [];
  for (const member of members) {
    data.push(await buildOrganizationMemberDetails(storage, member, includeCollections));
  }

  return jsonResponse({
    data,
    object: 'list',
    continuationToken: null,
  });
}

export async function handleGetOrganizationMemberMiniDetails(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string
): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const membership = await requireConfirmedMembership(storage, userId, organizationId);
  if (!membership) return errorResponse('Organization not found', 404);

  const members = await storage.getOrganizationMembershipsByOrg(organizationId);
  const data = [];
  for (const member of members) {
    data.push(await buildOrganizationMemberDetails(storage, member, false));
  }

  return jsonResponse({
    data,
    object: 'list',
    continuationToken: null,
  });
}

export async function handleGetOrganizationMember(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  memberId: string
): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const membership = await requireConfirmedMembership(storage, userId, organizationId);
  if (!membership) return errorResponse('Organization not found', 404);

  const target = await storage.getOrganizationMembershipById(memberId);
  if (!target || target.organizationId !== organizationId) {
    return errorResponse("The specified user isn't member of the organization", 404);
  }

  return jsonResponse(await buildOrganizationMemberDetails(storage, target, true));
}

export async function handleUpdateOrganizationMember(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  memberId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const actor = await requireConfirmedMembership(storage, userId, organizationId);
  if (!actor) return errorResponse('Organization not found', 404);
  if (!hasFullOrganizationAccess(actor) || !isMembershipAtLeast(actor.type, 3)) {
    return errorResponse('Insufficient permissions', 403);
  }

  const target = await storage.getOrganizationMembershipById(memberId);
  if (!target || target.organizationId !== organizationId) {
    return errorResponse("The specified user isn't member of the organization", 404);
  }

  let body: {
    type?: number | string;
    accessAll?: boolean;
    permissions?: Record<string, boolean>;
    collections?: Array<{ id?: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }>;
  };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const requestedType = normalizeOrganizationMembershipType(body.type);
  const explicitAccessAll = typeof body.accessAll === 'boolean' ? body.accessAll : null;
  const customAccessAll =
    String(body.type) === '4' &&
    body.permissions?.createNewCollections === true &&
    body.permissions?.editAnyCollection === true &&
    body.permissions?.deleteAnyCollection === true;
  const nextAccessAll = explicitAccessAll ?? (requestedType <= 1 || customAccessAll);

  if ((isMembershipAtLeast(target.type, 1) || requestedType <= 1) && normalizeOrganizationMembershipType(actor.type) !== 0) {
    return errorResponse('Only Owners can grant and remove Admin or Owner privileges', 403);
  }

  if (normalizeOrganizationMembershipType(target.type) === 0 && normalizeOrganizationMembershipType(actor.type) !== 0) {
    return errorResponse('Only Owners can edit Owner users', 403);
  }

  if (normalizeOrganizationMembershipType(target.type) === 0 && requestedType !== 0) {
    const owners = (await storage.getOrganizationMembershipsByOrg(organizationId)).filter((entry) => Number(entry.status) === 2 && normalizeOrganizationMembershipType(entry.type) === 0);
    if (owners.length <= 1) {
      return errorResponse("Can't delete the last owner", 400);
    }
  }

  target.type = requestedType;
  target.accessAll = nextAccessAll;
  target.updatedAt = new Date().toISOString();
  await storage.saveOrganizationMembership(target);

  const collectionAssignments = nextAccessAll
    ? []
    : parseMemberCollectionAssignments(body.collections, target.id, target.updatedAt);
  await storage.replaceMembershipCollectionAccess(target.id, collectionAssignments);
  await notifyOrganizationUsersSync(request, env, storage, organizationId);

  return new Response(null, { status: 200 });
}

export async function handleGetOrganizationCipherDetails(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string
): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const membership = await requireConfirmedMembership(storage, userId, organizationId);
  if (!membership) return errorResponse('Organization not found', 404);
  if (!hasFullOrganizationAccess(membership)) {
    return errorResponse('Resource not found.', 404);
  }

  const { ciphers, collectionIdsByCipherId, snapshot } = await getAccessibleCiphersForUser(storage, userId);
  const orgCiphers = ciphers.filter((cipher) => String((cipher as { organizationId?: unknown }).organizationId || '') === organizationId);
  const attachments = await storage.getAttachmentsByCipherIds(orgCiphers.map((cipher) => cipher.id));

  const data = [];
  for (const cipher of orgCiphers) {
    const access = await resolveCipherAccess(storage, userId, cipher, snapshot, collectionIdsByCipherId);
    data.push(
      cipherToResponse(cipher, attachments.get(cipher.id) || [], {
        organizationId: access.organizationId,
        collectionIds: access.collectionIds,
        edit: access.canEdit,
        viewPassword: access.canViewPassword,
        permissions: {
          delete: access.canDelete,
          restore: access.canRestore,
        },
      })
    );
  }

  return jsonResponse({
    data,
    object: 'list',
    continuationToken: null,
  });
}
