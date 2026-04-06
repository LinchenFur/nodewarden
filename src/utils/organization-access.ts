import type {
  Cipher,
  CollectionMembership,
  OrgCollection,
  Organization,
  OrganizationMembership,
} from '../types';
import { StorageService } from '../services/storage';
import {
  hasFullOrganizationAccess,
  isOrganizationManager,
  membershipTypeToResponse,
  mergeCollectionAccess,
  resolveOrganizationPermissions,
} from './organization-permissions';

export interface OrganizationAccessSnapshot {
  membershipsByOrganizationId: Map<string, OrganizationMembership>;
  assignmentsByMembershipId: Map<string, CollectionMembership[]>;
}

export interface ResolvedCipherAccess {
  organizationId: string | null;
  collectionIds: string[];
  canAccess: boolean;
  canEdit: boolean;
  canDelete: boolean;
  canRestore: boolean;
  canViewPassword: boolean;
}

function toBoolean(value: unknown): boolean {
  return !!value;
}

function withAliases<T extends Record<string, any>>(
  value: T,
  aliases: Record<string, string>
): T & Record<string, any> {
  const response: Record<string, any> = { ...value };
  for (const [sourceKey, aliasKey] of Object.entries(aliases)) {
    response[aliasKey] = value[sourceKey];
  }
  return response as T & Record<string, any>;
}

export async function loadOrganizationAccessSnapshot(
  storage: StorageService,
  userId: string
): Promise<OrganizationAccessSnapshot> {
  const memberships = await storage.getOrganizationMembershipsByUser(userId, true);
  const membershipsByOrganizationId = new Map<string, OrganizationMembership>();
  for (const membership of memberships) {
    membershipsByOrganizationId.set(membership.organizationId, membership);
  }

  const assignmentsByMembershipId = await storage.getCollectionMembershipsByMembershipIds(
    memberships.map((membership) => membership.id)
  );

  return {
    membershipsByOrganizationId,
    assignmentsByMembershipId,
  };
}

export async function buildProfileOrganizations(
  storage: StorageService,
  userId: string
): Promise<any[]> {
  const memberships = await storage.getOrganizationMembershipsByUser(userId, true);
  const organizations = await storage.getOrganizationsByUser(userId);
  const organizationsById = new Map<string, Organization>(organizations.map((organization) => [organization.id, organization]));

  return memberships
    .map((membership) => {
      const organization = organizationsById.get(membership.organizationId);
      if (!organization) return null;

      const membershipType = membershipTypeToResponse(membership.type, membership.accessAll);
      const permissions = resolveOrganizationPermissions(membership.type, membership.accessAll);

      return {
        id: organization.id,
        identifier: null,
        name: organization.name,
        seats: 20,
        maxCollections: null,
        usersGetPremium: true,
        use2fa: true,
        useDirectory: false,
        useEvents: false,
        useGroups: false,
        useTotp: true,
        useScim: false,
        usePolicies: true,
        useApi: true,
        selfHost: true,
        hasPublicAndPrivateKeys: !!organization.privateKey && !!organization.publicKey,
        resetPasswordEnrolled: false,
        useResetPassword: false,
        ssoBound: false,
        useSso: false,
        useKeyConnector: false,
        useSecretsManager: false,
        usePasswordManager: true,
        useCustomPermissions: true,
        useActivateAutofillPolicy: false,
        useAdminSponsoredFamilies: false,
        useRiskInsights: false,
        organizationUserId: membership.id,
        providerId: null,
        providerName: null,
        providerType: null,
        familySponsorshipFriendlyName: null,
        familySponsorshipAvailable: false,
        productTierType: 3,
        keyConnectorEnabled: false,
        keyConnectorUrl: null,
        familySponsorshipLastSyncDate: null,
        familySponsorshipValidUntil: null,
        familySponsorshipToDelete: null,
        accessSecretsManager: false,
        limitCollectionCreation: Number(membership.type) < 3 || !membership.accessAll,
        limitCollectionDeletion: true,
        limitItemDeletion: false,
        allowAdminAccessToAllCollectionItems: true,
        userIsManagedByOrganization: false,
        userIsClaimedByOrganization: false,
        permissions,
        canCreateNewCollections: permissions.createNewCollections,
        canEditAnyCollection: permissions.editAnyCollection,
        canDeleteAnyCollection: permissions.deleteAnyCollection,
        canAccessEventLogs: permissions.accessEventLogs,
        canAccessImportExport: permissions.accessImportExport,
        canAccessReports: permissions.accessReports,
        canManageGroups: permissions.manageGroups,
        canManagePolicies: permissions.managePolicies,
        canManageUsers: permissions.manageUsers || membershipType <= 1,
        canManageUsersPassword: permissions.manageResetPassword,
        maxStorageGb: 32767,
        userId,
        key: membership.key,
        status: membership.status,
        type: membershipType,
        enabled: true,
        object: 'profileOrganization',
      };
    })
    .filter(Boolean);
}

export async function resolveCipherAccess(
  storage: StorageService,
  userId: string,
  cipher: Cipher,
  snapshot?: OrganizationAccessSnapshot,
  collectionIdsByCipherId?: Map<string, string[]>
): Promise<ResolvedCipherAccess> {
  const organizationId = String((cipher as { organizationId?: unknown }).organizationId || '').trim() || null;
  if (!organizationId) {
    const ownCipher = cipher.userId === userId;
    return {
      organizationId: null,
      collectionIds: [],
      canAccess: ownCipher,
      canEdit: ownCipher,
      canDelete: ownCipher,
      canRestore: ownCipher,
      canViewPassword: ownCipher,
    };
  }

  const accessSnapshot = snapshot ?? (await loadOrganizationAccessSnapshot(storage, userId));
  const membership = accessSnapshot.membershipsByOrganizationId.get(organizationId);
  const collectionIds = collectionIdsByCipherId?.get(cipher.id) || [];
  if (!membership) {
    return {
      organizationId,
      collectionIds,
      canAccess: false,
      canEdit: false,
      canDelete: false,
      canRestore: false,
      canViewPassword: false,
    };
  }

  if (hasFullOrganizationAccess(membership)) {
    return {
      organizationId,
      collectionIds,
      canAccess: true,
      canEdit: true,
      canDelete: true,
      canRestore: true,
      canViewPassword: true,
    };
  }

  if (!collectionIds.length) {
    return {
      organizationId,
      collectionIds,
      canAccess: false,
      canEdit: false,
      canDelete: false,
      canRestore: false,
      canViewPassword: false,
    };
  }

  const membershipAssignments = accessSnapshot.assignmentsByMembershipId.get(membership.id) || [];
  const matchedAssignments = membershipAssignments.filter((assignment) => collectionIds.includes(assignment.collectionId));
  if (!matchedAssignments.length) {
    return {
      organizationId,
      collectionIds,
      canAccess: false,
      canEdit: false,
      canDelete: false,
      canRestore: false,
      canViewPassword: false,
    };
  }

  const merged = mergeCollectionAccess(matchedAssignments, isOrganizationManager(membership));
  return {
    organizationId,
    collectionIds,
    canAccess: true,
    canEdit: !merged.readOnly,
    canDelete: !merged.readOnly,
    canRestore: !merged.readOnly,
    canViewPassword: !merged.hidePasswords,
  };
}

export async function getAccessibleCiphersForUser(
  storage: StorageService,
  userId: string
): Promise<{ ciphers: Cipher[]; collectionIdsByCipherId: Map<string, string[]>; snapshot: OrganizationAccessSnapshot }> {
  const snapshot = await loadOrganizationAccessSnapshot(storage, userId);
  const personalCiphers = await storage.getAllCiphers(userId);
  const organizationIds = Array.from(snapshot.membershipsByOrganizationId.keys());
  const organizationCiphers = organizationIds.length ? await storage.getCiphersByOrganizationIds(organizationIds) : [];
  const allCiphers = [...personalCiphers, ...organizationCiphers];
  const collectionIdsByCipherId = await storage.getCollectionIdsByCipherIds(allCiphers.map((cipher) => cipher.id));
  const accessible: Cipher[] = [];

  for (const cipher of allCiphers) {
    const access = await resolveCipherAccess(storage, userId, cipher, snapshot, collectionIdsByCipherId);
    if (access.canAccess) {
      accessible.push(cipher);
    }
  }

  accessible.sort((left, right) => {
    return new Date(right.updatedAt).getTime() - new Date(left.updatedAt).getTime();
  });

  return {
    ciphers: accessible,
    collectionIdsByCipherId,
    snapshot,
  };
}

export async function buildCollectionDetails(
  storage: StorageService,
  userId: string,
  collection: OrgCollection,
  snapshot?: OrganizationAccessSnapshot
): Promise<any> {
  const accessSnapshot = snapshot ?? (await loadOrganizationAccessSnapshot(storage, userId));
  const membership = accessSnapshot.membershipsByOrganizationId.get(collection.organizationId);
  const assignments = membership ? accessSnapshot.assignmentsByMembershipId.get(membership.id) || [] : [];
  const matchedAssignments = assignments.filter((assignment) => assignment.collectionId === collection.id);

  let readOnly = true;
  let hidePasswords = true;
  let manage = false;
  if (membership) {
    if (hasFullOrganizationAccess(membership)) {
      readOnly = false;
      hidePasswords = false;
      manage = isOrganizationManager(membership) || Number(membership.type) <= 1;
    } else if (matchedAssignments.length) {
      const merged = mergeCollectionAccess(matchedAssignments, isOrganizationManager(membership));
      readOnly = merged.readOnly;
      hidePasswords = merged.hidePasswords;
      manage = merged.manage;
    }
  }

  return withAliases({
    id: collection.id,
    organizationId: collection.organizationId,
    externalId: collection.externalId,
    name: collection.name,
    readOnly,
    hidePasswords,
    manage,
    object: 'collectionDetails',
  }, {
    id: 'Id',
    organizationId: 'OrganizationId',
    externalId: 'ExternalId',
    name: 'Name',
    readOnly: 'ReadOnly',
    hidePasswords: 'HidePasswords',
    manage: 'Manage',
    object: 'Object',
  });
}

export async function buildOrganizationMemberDetails(
  storage: StorageService,
  membership: OrganizationMembership,
  includeCollections: boolean
): Promise<any> {
  const user = await storage.getUserById(membership.userId);
  const membershipType = membershipTypeToResponse(membership.type, membership.accessAll);
  let collections: any[] = [];

  if (includeCollections && !hasFullOrganizationAccess(membership)) {
    const assignmentsByMembershipId = await storage.getCollectionMembershipsByMembershipIds([membership.id]);
    const assignments = assignmentsByMembershipId.get(membership.id) || [];
    collections = assignments.map((assignment) => withAliases({
      id: assignment.collectionId,
      readOnly: toBoolean(assignment.readOnly),
      hidePasswords: toBoolean(assignment.hidePasswords),
      manage: toBoolean(assignment.manage) || (membershipType === 4 && !assignment.readOnly && !assignment.hidePasswords),
    }, {
      id: 'Id',
      readOnly: 'ReadOnly',
      hidePasswords: 'HidePasswords',
      manage: 'Manage',
    }));
  }

  return withAliases({
    id: membership.id,
    userId: membership.userId,
    name: user?.name ?? null,
    email: membership.userEmail,
    externalId: membership.externalId,
    avatarColor: null,
    groups: [],
    collections,
    status: membership.status,
    type: membershipType,
    accessAll: membership.accessAll,
    twoFactorEnabled: !!user?.totpSecret,
    resetPasswordEnrolled: false,
    hasMasterPassword: true,
    permissions: resolveOrganizationPermissions(membership.type, membership.accessAll),
    ssoExternalId: null,
    ssoBound: false,
    managedByOrganization: false,
    claimedByOrganization: false,
    usesKeyConnector: false,
    accessSecretsManager: false,
    object: 'organizationUserUserDetails',
  }, {
    id: 'Id',
    userId: 'UserId',
    name: 'Name',
    email: 'Email',
    externalId: 'ExternalId',
    avatarColor: 'AvatarColor',
    groups: 'Groups',
    collections: 'Collections',
    status: 'Status',
    type: 'Type',
    accessAll: 'AccessAll',
    twoFactorEnabled: 'TwoFactorEnabled',
    resetPasswordEnrolled: 'ResetPasswordEnrolled',
    hasMasterPassword: 'HasMasterPassword',
    permissions: 'Permissions',
    ssoExternalId: 'SsoExternalId',
    ssoBound: 'SsoBound',
    managedByOrganization: 'ManagedByOrganization',
    claimedByOrganization: 'ClaimedByOrganization',
    usesKeyConnector: 'UsesKeyConnector',
    accessSecretsManager: 'AccessSecretsManager',
    object: 'Object',
  });
}
