import { base64ToBytes, decryptBw, decryptStr, rsaDecryptOaepSha1 } from './crypto';
import { deriveSendKeyParts, looksLikeCipherString } from './app-support';
import type { Cipher, Folder, Send, OrgProfile, OrgCollection } from './types';
import { decryptSingleCipher } from './decrypt-cipher';

export interface DecryptVaultCoreArgs {
  folders: Folder[];
  ciphers: Cipher[];
  symEncKeyB64: string;
  symMacKeyB64: string;
  // Organizations the user belongs to. Needed to unwrap per-cipher keys of
  // org-owned ciphers, whose `key` is wrapped with the organization key rather
  // than the user key.
  organizations?: OrgProfile[];
  // The user's decrypted RSA private key (PKCS#8, base64). Required to unwrap
  // type-4 organization member keys. Optional for personal-only vaults.
  userPrivateKeyB64?: string;
}

export interface DecryptVaultCoreResult {
  folders: Folder[];
  ciphers: Cipher[];
}

export interface DecryptSendsArgs {
  sends: Send[];
  symEncKeyB64: string;
  symMacKeyB64: string;
  origin: string;
}

async function decryptField(
  value: string | null | undefined,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<string> {
  if (!value || typeof value !== 'string') return '';
  try {
    return await decryptStr(value, enc, mac);
  } catch {
    return looksLikeCipherString(value) ? '' : value;
  }
}

// Unwraps an organization member key into its 64-byte symmetric org key.
// Official Bitwarden wraps it with the user's RSA public key (type 4); older
// NodeWarden builds used the user symmetric key (type 2). Both are supported.
export async function unwrapOrgKey(
  memberKey: string,
  userEnc: Uint8Array,
  userMac: Uint8Array,
  userPrivateKey: Uint8Array | null
): Promise<{ enc: Uint8Array; mac: Uint8Array } | null> {
  const raw = memberKey.startsWith('4.')
    ? (userPrivateKey ? await rsaDecryptOaepSha1(userPrivateKey, memberKey) : null)
    : await decryptBw(memberKey, userEnc, userMac);
  if (!raw || raw.byteLength < 64) return null;
  return { enc: raw.slice(0, 32), mac: raw.slice(32, 64) };
}

async function buildOrgKeyMap(
  organizations: OrgProfile[] | undefined,
  userEnc: Uint8Array,
  userMac: Uint8Array,
  userPrivateKeyB64: string | undefined
): Promise<Map<string, { enc: Uint8Array; mac: Uint8Array }>> {
  const userPrivateKey = userPrivateKeyB64 ? base64ToBytes(userPrivateKeyB64) : null;
  const orgKeys = new Map<string, { enc: Uint8Array; mac: Uint8Array }>();
  for (const org of organizations || []) {
    if (!org?.id || !org.key) continue;
    try {
      const key = await unwrapOrgKey(org.key, userEnc, userMac, userPrivateKey);
      if (key) orgKeys.set(org.id, key);
    } catch {
      // Org key not decryptable (e.g. membership not yet confirmed).
    }
  }
  return orgKeys;
}

export async function decryptVaultCore(args: DecryptVaultCoreArgs): Promise<DecryptVaultCoreResult> {
  const userEnc = base64ToBytes(args.symEncKeyB64);
  const userMac = base64ToBytes(args.symMacKeyB64);
  const orgKeys = await buildOrgKeyMap(args.organizations, userEnc, userMac, args.userPrivateKeyB64);

  const folders = await Promise.all(
    args.folders.map(async (folder) => ({
      ...folder,
      decName: await decryptField(folder.name, userEnc, userMac),
    }))
  );

  const ciphers = await Promise.all(args.ciphers.map((cipher) => {
    const orgId = typeof cipher.organizationId === 'string' ? cipher.organizationId : '';
    return decryptSingleCipher(cipher, userEnc, userMac, orgId ? orgKeys.get(orgId) : undefined);
  }));

  return { folders, ciphers };
}

export async function decryptSends(args: DecryptSendsArgs): Promise<Send[]> {
  const userEnc = base64ToBytes(args.symEncKeyB64);
  const userMac = base64ToBytes(args.symMacKeyB64);
  return Promise.all(
    args.sends.map(async (send) => {
      const nextSend: Send = { ...send };
      try {
        if (send.key) {
          const sendKeyRaw = await decryptBw(send.key, userEnc, userMac);
          const derived = await deriveSendKeyParts(sendKeyRaw);
          nextSend.decName = await decryptField(send.name || '', derived.enc, derived.mac);
          nextSend.decNotes = await decryptField(send.notes || '', derived.enc, derived.mac);
          nextSend.decText = await decryptField(send.text?.text || '', derived.enc, derived.mac);
          if (send.file?.fileName) {
            const decFileName = await decryptField(send.file.fileName, derived.enc, derived.mac);
            nextSend.file = {
              ...(send.file || {}),
              fileName: decFileName || send.file.fileName,
            };
          }
          nextSend.decShareKey = btoa(String.fromCharCode(...sendKeyRaw))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');
          nextSend.shareUrl = `${args.origin}/#/send/${send.accessId}/${nextSend.decShareKey}`;
        } else {
          nextSend.decName = '';
          nextSend.decNotes = '';
          nextSend.decText = '';
        }
      } catch {
        nextSend.decName = 'Decrypt failed';
      }
      return nextSend;
    })
  );
}

export async function decryptOrganizations(args: {
  organizations: OrgProfile[];
  collections: OrgCollection[];
  symEncKeyB64: string;
  symMacKeyB64: string;
  userPrivateKeyB64?: string;
}): Promise<{ organizations: OrgProfile[]; collections: OrgCollection[] }> {
  const userEnc = base64ToBytes(args.symEncKeyB64);
  const userMac = base64ToBytes(args.symMacKeyB64);
  const orgKeys = await buildOrgKeyMap(args.organizations, userEnc, userMac, args.userPrivateKeyB64);
  const collections: OrgCollection[] = [];
  for (const col of args.collections || []) {
    const key = orgKeys.get(col.organizationId);
    let decName = col.name;
    if (key) {
      try {
        decName = await decryptStr(col.name, key.enc, key.mac);
      } catch {
        decName = col.name;
      }
    }
    collections.push({ ...col, decName });
  }
  return { organizations: args.organizations || [], collections };
}
