import { Env, Attachment, DEFAULT_DEV_SECRET } from '../types';
import { notifyUserVaultSync } from '../durable/notifications-hub';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { buildDirectUploadUrl, getSafeJwtSecret, parseDirectUploadPayload } from '../utils/direct-upload';
import { generateUUID } from '../utils/uuid';
import {
  createAttachmentUploadToken,
  createFileDownloadToken,
  verifyAttachmentUploadToken,
  verifyFileDownloadToken,
} from '../utils/jwt';
import { cipherToResponse } from './ciphers';
import { LIMITS } from '../config/limits';
import { readActingDeviceIdentifier } from '../utils/device';
import { loadOrganizationAccessSnapshot, resolveCipherAccess } from '../utils/organization-access';
import {
  deleteBlobObject,
  getAttachmentObjectKey,
  getBlobObject,
  getBlobStorageMaxBytes,
  putBlobObject,
} from '../services/blob-store';

async function notifyVaultSyncForRequest(
  request: Request,
  env: Env,
  userId: string,
  revisionDate: string
): Promise<void> {
  await notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
}

async function notifyCipherUsersSync(
  request: Request,
  env: Env,
  storage: StorageService,
  cipher: { userId: string; organizationId?: string | null }
): Promise<void> {
  const organizationId = String(cipher.organizationId || '').trim() || null;
  if (organizationId) {
    const revisions = await storage.updateRevisionDatesForOrganization(organizationId);
    for (const [memberUserId, revisionDate] of revisions.entries()) {
      await notifyVaultSyncForRequest(request, env, memberUserId, revisionDate);
    }
    return;
  }

  const revisionDate = await storage.updateRevisionDate(cipher.userId);
  await notifyVaultSyncForRequest(request, env, cipher.userId, revisionDate);
}

async function getCipherAttachmentAccess(
  storage: StorageService,
  userId: string,
  cipherId: string
): Promise<{
  cipher: any;
  access: Awaited<ReturnType<typeof resolveCipherAccess>>;
} | null> {
  const cipher = await storage.getCipher(cipherId);
  if (!cipher) return null;
  const snapshot = await loadOrganizationAccessSnapshot(storage, userId);
  const collectionIdsByCipherId = await storage.getCollectionIdsByCipherIds([cipher.id]);
  const access = await resolveCipherAccess(storage, userId, cipher, snapshot, collectionIdsByCipherId);
  if (!access.canAccess) return null;
  return { cipher, access };
}

// Format file size to human readable
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} Bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

async function processAttachmentUpload(
  request: Request,
  env: Env,
  attachment: Attachment,
  cipherId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const maxFileSize = getBlobStorageMaxBytes(env, LIMITS.attachment.maxFileSizeBytes);
  const upload = await parseDirectUploadPayload(request, {
    expectedSize: Number(attachment.size) || 0,
    maxFileSize,
    tooLargeMessage: `File too large. Maximum size is ${Math.floor(maxFileSize / (1024 * 1024))}MB`,
  });
  if (upload instanceof Response) {
    return upload;
  }

  const path = getAttachmentObjectKey(cipherId, attachment.id);
  try {
    await putBlobObject(env, path, upload.body, {
      size: upload.size,
      contentType: upload.contentType,
      customMetadata: {
        cipherId,
        attachmentId: attachment.id,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('KV object too large')) {
      return errorResponse(`File too large. Maximum size is ${Math.floor(maxFileSize / (1024 * 1024))}MB`, 413);
    }
    return errorResponse('Attachment storage is not configured', 500);
  }

  if (upload.size !== attachment.size) {
    attachment.size = upload.size;
    attachment.sizeName = formatSize(upload.size);
    await storage.saveAttachment(attachment);
  }

  const cipher = await storage.getCipher(cipherId);
  if (cipher) {
    await notifyCipherUsersSync(request, env, storage, cipher as { userId: string; organizationId?: string | null });
  }

  return new Response(null, { status: 201 });
}

// POST /api/ciphers/{cipherId}/attachment/v2
// Creates attachment metadata and returns upload URL
export async function handleCreateAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  // Verify cipher exists and belongs to user
  const accessState = await getCipherAttachmentAccess(storage, userId, cipherId);
  if (!accessState) {
    return errorResponse('Cipher not found', 404);
  }
  if (!accessState.access.canEdit) return errorResponse('Insufficient permissions', 403);

  let body: {
    fileName?: string;
    key?: string;
    fileSize?: number;
  };

  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.fileName || !body.key) {
    return errorResponse('fileName and key are required', 400);
  }

  const fileSize = body.fileSize || 0;
  const attachmentId = generateUUID();

  // Create attachment metadata
  const attachment: Attachment = {
    id: attachmentId,
    cipherId: cipherId,
    fileName: body.fileName,
    size: fileSize,
    sizeName: formatSize(fileSize),
    key: body.key,
  };

  // Save attachment metadata
  await storage.saveAttachment(attachment);

  // Add attachment to cipher
  await storage.addAttachmentToCipher(cipherId, attachmentId);

  // Update cipher revision date
  await notifyCipherUsersSync(request, env, storage, accessState.cipher as { userId: string; organizationId?: string | null });

  // Get updated cipher for response
  const updatedCipher = await storage.getCipher(cipherId);
  const attachments = await storage.getAttachmentsByCipher(cipherId);
  const jwtSecret = getSafeJwtSecret(env);
  if (!jwtSecret) {
    return errorResponse('Server configuration error', 500);
  }
  const uploadToken = await createAttachmentUploadToken(userId, cipherId, attachmentId, jwtSecret);

  return jsonResponse({
    object: 'attachment-fileUpload',
    attachmentId: attachmentId,
    url: buildDirectUploadUrl(request, `/api/ciphers/${cipherId}/attachment/${attachmentId}`, uploadToken),
    fileUploadType: 1,
    cipherResponse: cipherToResponse(updatedCipher!, attachments, {
      organizationId: accessState.access.organizationId,
      collectionIds: accessState.access.collectionIds,
      edit: accessState.access.canEdit,
      viewPassword: accessState.access.canViewPassword,
      permissions: {
        delete: accessState.access.canDelete,
        restore: accessState.access.canRestore,
      },
    }),
  });
}

// POST /api/ciphers/{cipherId}/attachment/{attachmentId}
// Upload attachment file content
export async function handleUploadAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  // Verify cipher exists and belongs to user
  const accessState = await getCipherAttachmentAccess(storage, userId, cipherId);
  if (!accessState) {
    return errorResponse('Cipher not found', 404);
  }
  if (!accessState.access.canEdit) return errorResponse('Insufficient permissions', 403);

  // Verify attachment exists
  const attachment = await storage.getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  return processAttachmentUpload(request, env, attachment, cipherId);
}

export async function handlePublicUploadAttachment(
  request: Request,
  env: Env,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const jwtSecret = getSafeJwtSecret(env);
  if (!jwtSecret) {
    return errorResponse('Server configuration error', 500);
  }

  const token = new URL(request.url).searchParams.get('token');
  if (!token) {
    return errorResponse('Token required', 401);
  }

  const claims = await verifyAttachmentUploadToken(token, jwtSecret);
  if (!claims) {
    return errorResponse('Invalid or expired token', 401);
  }
  if (claims.cipherId !== cipherId || claims.attachmentId !== attachmentId) {
    return errorResponse('Token mismatch', 401);
  }

  const storage = new StorageService(env.DB);
  const accessState = await getCipherAttachmentAccess(storage, claims.userId, cipherId);
  if (!accessState) {
    return errorResponse('Cipher not found', 404);
  }
  if (!accessState.access.canEdit) return errorResponse('Insufficient permissions', 403);

  const attachment = await storage.getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  return processAttachmentUpload(request, env, attachment, cipherId);
}

// GET /api/ciphers/{cipherId}/attachment/{attachmentId}
// Get attachment download info
export async function handleGetAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  // Verify cipher exists and belongs to user
  const accessState = await getCipherAttachmentAccess(storage, userId, cipherId);
  if (!accessState) {
    return errorResponse('Cipher not found', 404);
  }

  // Verify attachment exists
  const attachment = await storage.getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  // Generate short-lived download token
  const token = await createFileDownloadToken(cipherId, attachmentId, env.JWT_SECRET);
  
  // Generate download URL with token
  const url = new URL(request.url);
  const downloadUrl = `${url.origin}/api/attachments/${cipherId}/${attachmentId}?token=${token}`;

  return jsonResponse({
    object: 'attachment',
    id: attachment.id,
    url: downloadUrl,
    fileName: attachment.fileName,
    key: attachment.key,
    size: String(Number(attachment.size) || 0),
    sizeName: attachment.sizeName,
  });
}

// GET /api/attachments/{cipherId}/{attachmentId}?token=xxx
// Public download endpoint (uses token for auth instead of header)
export async function handlePublicDownloadAttachment(
  request: Request,
  env: Env,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret || secret.length < LIMITS.auth.jwtSecretMinLength || secret === DEFAULT_DEV_SECRET) {
    return errorResponse('Server configuration error', 500);
  }

  const url = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) {
    return errorResponse('Token required', 401);
  }

  // Verify token
  const claims = await verifyFileDownloadToken(token, env.JWT_SECRET);
  if (!claims) {
    return errorResponse('Invalid or expired token', 401);
  }

  // Verify token matches request
  if (claims.cipherId !== cipherId || claims.attachmentId !== attachmentId) {
    return errorResponse('Token mismatch', 401);
  }

  const storage = new StorageService(env.DB);

  // Verify attachment exists
  const attachment = await storage.getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  const path = getAttachmentObjectKey(cipherId, attachmentId);
  const object = await getBlobObject(env, path);

  if (!object) {
    return errorResponse('Attachment file not found', 404);
  }

  const firstUse = await storage.consumeAttachmentDownloadToken(claims.jti, claims.exp);
  if (!firstUse) {
    return errorResponse('Invalid or expired token', 401);
  }

  return new Response(object.body, {
    headers: {
      'Content-Type': object.contentType || 'application/octet-stream',
      'Content-Length': String(object.size),
      'Cache-Control': 'private, no-cache',
    },
  });
}

// DELETE /api/ciphers/{cipherId}/attachment/{attachmentId}
// Delete attachment
export async function handleDeleteAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  // Verify cipher exists and belongs to user
  const accessState = await getCipherAttachmentAccess(storage, userId, cipherId);
  if (!accessState) {
    return errorResponse('Cipher not found', 404);
  }
  if (!accessState.access.canDelete) return errorResponse('Insufficient permissions', 403);

  // Verify attachment exists
  const attachment = await storage.getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  const path = getAttachmentObjectKey(cipherId, attachmentId);
  await deleteBlobObject(env, path);

  // Delete attachment metadata
  await storage.deleteAttachment(attachmentId);

  // Remove attachment from cipher
  await storage.removeAttachmentFromCipher(cipherId, attachmentId);

  // Update cipher revision date
  await notifyCipherUsersSync(request, env, storage, accessState.cipher as { userId: string; organizationId?: string | null });

  // Get updated cipher for response
  const updatedCipher = await storage.getCipher(cipherId);
  const attachments = await storage.getAttachmentsByCipher(cipherId);

  return jsonResponse({
    cipher: cipherToResponse(updatedCipher!, attachments, {
      organizationId: accessState.access.organizationId,
      collectionIds: accessState.access.collectionIds,
      edit: accessState.access.canEdit,
      viewPassword: accessState.access.canViewPassword,
      permissions: {
        delete: accessState.access.canDelete,
        restore: accessState.access.canRestore,
      },
    }),
  });
}

// Delete all attachments for a cipher (used when deleting cipher)
export async function deleteAllAttachmentsForCipher(
  env: Env,
  cipherId: string
): Promise<void> {
  const storage = new StorageService(env.DB);
  const attachments = await storage.getAttachmentsByCipher(cipherId);

  for (const attachment of attachments) {
    const path = getAttachmentObjectKey(cipherId, attachment.id);
    await deleteBlobObject(env, path);
    await storage.deleteAttachment(attachment.id);
  }
}
