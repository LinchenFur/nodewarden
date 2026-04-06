import type {
  ListResponse,
  OrganizationCollection,
  OrganizationCollectionAccessDetail,
  OrganizationMember,
  OrganizationSummary,
} from '../types';
import { parseErrorMessage, parseJson, type AuthedFetch } from './shared';

export async function listOrganizations(authedFetch: AuthedFetch): Promise<OrganizationSummary[]> {
  const resp = await authedFetch('/api/organizations');
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Failed to load organizations'));
  const body = await parseJson<ListResponse<OrganizationSummary>>(resp);
  return body?.data || [];
}

export async function createOrganization(
  authedFetch: AuthedFetch,
  payload: {
    name: string;
    billingEmail?: string | null;
    collectionName?: string | null;
  }
): Promise<OrganizationSummary> {
  const resp = await authedFetch('/api/organizations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Failed to create organization'));
  const body = await parseJson<OrganizationSummary>(resp);
  if (!body?.id) throw new Error('Failed to create organization');
  return body;
}

export async function listOrganizationCollections(
  authedFetch: AuthedFetch,
  organizationId: string
): Promise<OrganizationCollection[]> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(organizationId)}/collections`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Failed to load collections'));
  const body = await parseJson<ListResponse<OrganizationCollection>>(resp);
  return body?.data || [];
}

export async function listOrganizationCollectionAccessDetails(
  authedFetch: AuthedFetch,
  organizationId: string
): Promise<OrganizationCollectionAccessDetail[]> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(organizationId)}/collections/details`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Failed to load collection details'));
  const body = await parseJson<ListResponse<OrganizationCollectionAccessDetail>>(resp);
  return body?.data || [];
}

export async function createOrganizationCollection(
  authedFetch: AuthedFetch,
  organizationId: string,
  payload: {
    name: string;
  }
): Promise<OrganizationCollection> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(organizationId)}/collections`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Failed to create collection'));
  const body = await parseJson<OrganizationCollection>(resp);
  if (!body?.id) throw new Error('Failed to create collection');
  return body;
}

export async function listOrganizationMembers(
  authedFetch: AuthedFetch,
  organizationId: string
): Promise<OrganizationMember[]> {
  const resp = await authedFetch(
    `/api/organizations/${encodeURIComponent(organizationId)}/users?includeCollections=true`
  );
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Failed to load organization members'));
  const body = await parseJson<ListResponse<OrganizationMember>>(resp);
  return body?.data || [];
}

export async function updateOrganizationMember(
  authedFetch: AuthedFetch,
  organizationId: string,
  memberId: string,
  payload: {
    type: number;
    accessAll: boolean;
    collections: Array<{
      id: string;
      readOnly: boolean;
      hidePasswords: boolean;
      manage: boolean;
    }>;
  }
): Promise<void> {
  const resp = await authedFetch(
    `/api/organizations/${encodeURIComponent(organizationId)}/users/${encodeURIComponent(memberId)}`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }
  );
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Failed to update organization member'));
}
