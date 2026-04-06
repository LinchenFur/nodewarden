import type {
  CollectionMembership,
  OrganizationMembership,
  OrganizationMembershipType,
} from '../types';
import { OrganizationMembershipStatus } from '../types';

export interface ResolvedCollectionAccess {
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

export interface OrganizationPermissionsResponse {
  accessEventLogs: boolean;
  accessImportExport: boolean;
  accessReports: boolean;
  createNewCollections: boolean;
  editAnyCollection: boolean;
  deleteAnyCollection: boolean;
  manageGroups: boolean;
  managePolicies: boolean;
  manageSso: boolean;
  manageUsers: boolean;
  manageResetPassword: boolean;
  manageScim: boolean;
}

export function withPascalCaseAliases<T extends Record<string, any>>(value: T): T & Record<string, any> {
  const response: Record<string, any> = { ...value };
  for (const [key, currentValue] of Object.entries(value)) {
    if (!key.length) continue;
    const alias = key.charAt(0).toUpperCase() + key.slice(1);
    response[alias] = currentValue;
  }
  return response as T & Record<string, any>;
}

const NO_ORGANIZATION_PERMISSIONS: OrganizationPermissionsResponse = {
  accessEventLogs: false,
  accessImportExport: false,
  accessReports: false,
  createNewCollections: false,
  editAnyCollection: false,
  deleteAnyCollection: false,
  manageGroups: false,
  managePolicies: false,
  manageSso: false,
  manageUsers: false,
  manageResetPassword: false,
  manageScim: false,
};

const FULL_ORGANIZATION_PERMISSIONS: OrganizationPermissionsResponse = {
  accessEventLogs: true,
  accessImportExport: true,
  accessReports: true,
  createNewCollections: true,
  editAnyCollection: true,
  deleteAnyCollection: true,
  manageGroups: true,
  managePolicies: true,
  manageSso: false,
  manageUsers: true,
  manageResetPassword: true,
  manageScim: false,
};

const MANAGER_ORGANIZATION_PERMISSIONS: OrganizationPermissionsResponse = {
  accessEventLogs: false,
  accessImportExport: false,
  accessReports: false,
  createNewCollections: true,
  editAnyCollection: true,
  deleteAnyCollection: true,
  manageGroups: false,
  managePolicies: false,
  manageSso: false,
  manageUsers: false,
  manageResetPassword: false,
  manageScim: false,
};

function organizationTypeAccessRank(type: number): number {
  switch (Number(type)) {
    case 0:
      return 3;
    case 1:
      return 2;
    case 3:
    case 4:
      return 1;
    default:
      return 0;
  }
}

export function normalizeOrganizationMembershipType(value: unknown): number {
  const normalized = Number(value);
  if (normalized === 4) return 3;
  if (normalized >= 0 && normalized <= 3) return normalized;
  return 2;
}

export function membershipTypeToResponse(
  type: number,
  accessAll: boolean
): OrganizationMembershipType {
  const normalized = normalizeOrganizationMembershipType(type);
  if (normalized === 3 && accessAll) return 4 as OrganizationMembershipType;
  return normalized as OrganizationMembershipType;
}

export function resolveOrganizationPermissions(
  type: number,
  accessAll: boolean
): OrganizationPermissionsResponse {
  const normalized = normalizeOrganizationMembershipType(type);
  if (normalized === 0 || normalized === 1) {
    return { ...FULL_ORGANIZATION_PERMISSIONS };
  }
  if (normalized === 3 || (normalized === 4 && accessAll)) {
    return { ...MANAGER_ORGANIZATION_PERMISSIONS };
  }
  return { ...NO_ORGANIZATION_PERMISSIONS };
}

export function buildOrganizationPermissionsPayload(
  type: number,
  accessAll: boolean
): OrganizationPermissionsResponse & Record<string, any> {
  return withPascalCaseAliases(resolveOrganizationPermissions(type, accessAll));
}

export function isConfirmedMembership(membership: Pick<OrganizationMembership, 'status'> | null | undefined): boolean {
  return Number(membership?.status) === OrganizationMembershipStatus.Confirmed;
}

export function isMembershipAtLeast(type: number, minimumType: number): boolean {
  return organizationTypeAccessRank(type) >= organizationTypeAccessRank(minimumType);
}

export function hasFullOrganizationAccess(
  membership: Pick<OrganizationMembership, 'status' | 'type' | 'accessAll'> | null | undefined
): boolean {
  if (!membership || !isConfirmedMembership(membership as Pick<OrganizationMembership, 'status'>)) return false;
  return !!membership.accessAll || isMembershipAtLeast(membership.type, 1);
}

export function isOrganizationManager(
  membership: Pick<OrganizationMembership, 'type'> | null | undefined
): boolean {
  return membership ? normalizeOrganizationMembershipType(membership.type) === 3 : false;
}

export function mergeCollectionAccess(
  assignments: CollectionMembership[],
  isManager: boolean
): ResolvedCollectionAccess {
  if (!assignments.length) {
    return {
      readOnly: true,
      hidePasswords: true,
      manage: false,
    };
  }

  let readOnly = true;
  let hidePasswords = true;
  let manage = false;

  for (const assignment of assignments) {
    readOnly = readOnly && !!assignment.readOnly;
    hidePasswords = hidePasswords && !!assignment.hidePasswords;
    manage = manage || !!assignment.manage;
  }

  return {
    readOnly,
    hidePasswords,
    manage: isManager && (manage || (!readOnly && !hidePasswords)),
  };
}
