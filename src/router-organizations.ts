import type { Env, User } from './types';
import { errorResponse, jsonResponse } from './utils/response';
import { StorageService } from './services/storage';
import {
  handleCreateOrganization,
  handleGetOrganization,
  handleUpdateOrganization,
  handleDeleteOrganization,
  handleInviteOrganizationUsers,
  handleListOrganizationUsers,
  handleGetOrganizationUser,
  handleAcceptOrganizationUser,
  handleConfirmOrganizationUser,
  handleUpdateOrganizationUser,
  handleRemoveOrganizationUser,
  handleCreateCollection,
  handleUpdateCollection,
  handleDeleteCollection,
  organizationResponse,
} from './handlers/organizations';

// Routes for /api/organizations and /api/collections.
// Returns null when no organization route matches so the caller can continue.
export async function handleOrganizationRoute(
  request: Request,
  env: Env,
  userId: string,
  currentUser: User,
  path: string,
  method: string
): Promise<Response | null> {
  void currentUser;

  // Collections list is still a global read used by clients on sync fallback.
  // Org-scoped collection management arrives in a later step.
  if (path === '/api/collections' && method === 'GET') {
    return jsonResponse({ data: [], object: 'list', continuationToken: null });
  }

  if (path === '/api/organizations') {
    if (method === 'POST') return handleCreateOrganization(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  const orgMatch = path.match(/^\/api\/organizations\/([a-f0-9-]+)$/i);
  if (orgMatch) {
    const orgId = orgMatch[1];
    if (method === 'GET') return handleGetOrganization(request, env, userId, orgId);
    if (method === 'PUT' || method === 'POST') return handleUpdateOrganization(request, env, userId, orgId);
    if (method === 'DELETE') return handleDeleteOrganization(request, env, userId, orgId);
    return errorResponse('Method not allowed', 405);
  }

  // --- Member management: invite -> accept -> confirm ---
  if (path.match(/^\/api\/organizations\/([a-f0-9-]+)\/users\/invite$/i) && method === 'POST') {
    const orgId = path.split('/')[3];
    return handleInviteOrganizationUsers(request, env, userId, orgId);
  }

  const orgUsersListMatch = path.match(/^\/api\/organizations\/([a-f0-9-]+)\/users$/i);
  if (orgUsersListMatch && method === 'GET') {
    return handleListOrganizationUsers(request, env, userId, orgUsersListMatch[1]);
  }

  const orgUserActionMatch = path.match(/^\/api\/organizations\/([a-f0-9-]+)\/users\/([a-f0-9-]+)(\/(accept|confirm))?$/i);
  if (orgUserActionMatch) {
    const orgId = orgUserActionMatch[1];
    const membershipId = orgUserActionMatch[2];
    const action = orgUserActionMatch[4];
    if (action === 'accept' && method === 'POST') {
      return handleAcceptOrganizationUser(request, env, userId, orgId, membershipId);
    }
    if (action === 'confirm' && method === 'POST') {
      return handleConfirmOrganizationUser(request, env, userId, orgId, membershipId);
    }
    if (!action) {
      if (method === 'GET') return handleGetOrganizationUser(request, env, userId, orgId, membershipId);
      if (method === 'PUT' || method === 'POST') return handleUpdateOrganizationUser(request, env, userId, orgId, membershipId);
      if (method === 'DELETE') return handleRemoveOrganizationUser(request, env, userId, orgId, membershipId);
    }
  }

  // --- Collection management ---
  if (path.match(/^\/api\/organizations\/([a-f0-9-]+)\/collections$/i) && method === 'POST') {
    const orgId = path.split('/')[3];
    return handleCreateCollection(request, env, userId, orgId);
  }

  const collectionItemMatch = path.match(/^\/api\/organizations\/([a-f0-9-]+)\/collections\/([a-f0-9-]+)$/i);
  if (collectionItemMatch) {
    const orgId = collectionItemMatch[1];
    const collectionId = collectionItemMatch[2];
    if (method === 'PUT' || method === 'POST') return handleUpdateCollection(request, env, userId, orgId, collectionId);
    if (method === 'DELETE') return handleDeleteCollection(request, env, userId, orgId, collectionId);
  }

  // GET /api/organizations/:id/collections — collections visible to this member.
  const orgCollectionsMatch = path.match(/^\/api\/organizations\/([a-f0-9-]+)\/collections$/i);
  if (orgCollectionsMatch && method === 'GET') {
    const orgId = orgCollectionsMatch[1];
    const storage = new StorageService(env.DB);
    const membership = await storage.getMembershipForUser(orgId, userId);
    // Only confirmed members may list the organization's collections.
    if (!membership || membership.status !== 2) return errorResponse('Not found', 404);
    const collections = await storage.listCollectionsForOrg(orgId);
    return jsonResponse({
      data: collections.map((c) => ({
        id: c.id,
        organizationId: c.organizationId,
        name: c.name,
        externalId: c.externalId,
        readOnly: false,
        hidePasswords: false,
        manage: true,
        object: 'collectionDetails',
      })),
      object: 'list',
      continuationToken: null,
    });
  }

  return null;
}

// Re-export so the response serializer stays discoverable from the router module.
export { organizationResponse };
