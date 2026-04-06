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
