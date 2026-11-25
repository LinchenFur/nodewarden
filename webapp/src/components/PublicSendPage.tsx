import { useEffect, useRef, useState } from 'preact/hooks';
import { Clipboard, Download, Eye, Lock } from 'lucide-preact';
import { accessPublicSend, accessPublicSendFile, decryptPublicSend, decryptPublicSendFileBytes } from '@/lib/api/send';
import { copyTextToClipboard } from '@/lib/clipboard';
import { toBufferSource, calcTotpNow } from '@/lib/crypto';
import { downloadBytesAsFile, readResponseBytesWithProgress } from '@/lib/download';
import NotFoundPage from '@/components/NotFoundPage';
import StandalonePageFrame from '@/components/StandalonePageFrame';
import { getDemoPublicSend, IS_DEMO_MODE } from '@/lib/demo';
import { t } from '@/lib/i18n';

interface PublicSendPageProps {
  accessId: string;
  keyPart: string | null;
}

interface PublicSendFileData {
  id: string;
  fileName?: string | null;
  sizeName?: string | null;
}

interface PublicSendData {
  id: string;
  type: 0 | 1;
  decName?: string | null;
  decText?: string | null;
  decFileName?: string | null;
  expirationDate?: string | null;
  file?: PublicSendFileData | null;
}

// Structured payload nodewarden writes when sharing a vault login as a Send, so
// the recipient can see the password and a live-refreshing 2FA code. Plain text
// Sends have no such marker and keep rendering as before.
interface SharedLogin {
  username: string;
  password: string;
  totp: string;
  note: string;
  uri: string;
}

function parseSharedLogin(decText: string | null | undefined): SharedLogin | null {
  const raw = String(decText || '').trim();
  if (!raw.startsWith('{') || !raw.includes('"nwShare"')) return null;
  try {
    const obj = JSON.parse(raw) as Record<string, unknown>;
    if (Number(obj.nwShare) !== 1) return null;
    return {
      username: typeof obj.username === 'string' ? obj.username : '',
      password: typeof obj.password === 'string' ? obj.password : '',
      totp: typeof obj.totp === 'string' ? obj.totp : '',
      note: typeof obj.note === 'string' ? obj.note : '',
      uri: typeof obj.uri === 'string' ? obj.uri : '',
    };
  } catch {
    return null;
  }
}

function decodeBase64Url(value: string): Uint8Array | null {
  try {
    const raw = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = raw + '='.repeat((4 - (raw.length % 4)) % 4);
    const decoded = atob(padded);
    const out = new Uint8Array(decoded.length);
    for (let i = 0; i < decoded.length; i += 1) out[i] = decoded.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function hasUsableSendKey(keyPart: string | null): boolean {
  if (!keyPart) return false;
  const bytes = decodeBase64Url(keyPart);
  return !!bytes && bytes.length >= 16;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' ? value as Record<string, unknown> : null;
}

function formatSendDate(value: string | null | undefined): string {
  if (!value) return '';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return '';
  return parsed.toLocaleString();
}

function optionalString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

// Renders a 2FA code that recomputes locally every second from the shared TOTP
// secret, so the recipient always sees the current code without an account.
function LiveTotp(props: { secret: string }) {
  const [state, setState] = useState<{ code: string; remain: number; period: number } | null>(null);
  // Tracks the previous remaining seconds so we can suppress the ring's
  // animation on the frame where the countdown resets to a new period,
  // otherwise it would visibly spring backwards from empty to full.
  const prevRemainRef = useRef<number | null>(null);
  // Always holds the latest code so the copy button copies the current value
  // regardless of render timing.
  const codeRef = useRef<string>('');
  useEffect(() => {
    let active = true;
    let timer: number | undefined;
    const tick = async () => {
      const r = await calcTotpNow(props.secret);
      if (!active) return;
      codeRef.current = r ? r.code : '';
      setState(r);
      timer = window.setTimeout(() => void tick(), 1000);
    };
    void tick();
    return () => { active = false; if (timer) window.clearTimeout(timer); };
  }, [props.secret]);
  if (!state) return <strong className="public-send-totp-code">------</strong>;
  const grouped = state.code.length === 6 ? `${state.code.slice(0, 3)} ${state.code.slice(3)}` : state.code;

  // Countdown ring: a full circle that empties as `remain` shrinks. The ring
  // and the centered number turn red in the last 10 seconds.
  const period = state.period || 30;
  const R = 13;
  const CIRCUMFERENCE = 2 * Math.PI * R;
  const fraction = Math.max(0, Math.min(1, state.remain / period));
  const dashOffset = CIRCUMFERENCE * (1 - fraction);
  const low = state.remain <= 10;
  const resetting = prevRemainRef.current != null && state.remain > prevRemainRef.current;
  prevRemainRef.current = state.remain;

  return (
    <span className="public-send-totp">
      <strong className={`public-send-totp-code${low ? ' is-low' : ''}`}>{grouped}</strong>
      <button
        type="button"
        className="btn btn-secondary small public-send-totp-copy"
        aria-label={t('txt_copy') || 'Copy'}
        onClick={() => void copyTextToClipboard(codeRef.current || state.code)}
      >
        <Clipboard size={14} className="btn-icon" />{t('txt_copy') || 'Copy'}
      </button>
      <span className={`public-send-totp-ring${low ? ' is-low' : ''}`}>
        <svg width="32" height="32" viewBox="0 0 32 32" aria-hidden="true">
          <circle className="public-send-totp-ring-track" cx="16" cy="16" r={R} fill="none" strokeWidth="3" />
          <circle
            className={`public-send-totp-ring-progress${resetting ? ' no-transition' : ''}`}
            cx="16"
            cy="16"
            r={R}
            fill="none"
            strokeWidth="3"
            strokeLinecap="round"
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={dashOffset}
            transform="rotate(-90 16 16)"
          />
        </svg>
        <span className="public-send-totp-ring-num">{state.remain}</span>
      </span>
    </span>
  );
}

function parsePublicSendData(value: unknown): PublicSendData | null {
  const source = asRecord(value);
  if (!source) return null;
  const id = optionalString(source.id);
  const rawType = Number(source.type);
  if (!id || (rawType !== 0 && rawType !== 1)) return null;

  const fileSource = asRecord(source.file);
  const fileId = optionalString(fileSource?.id);
  const file = fileSource && fileId
    ? {
        id: fileId,
        fileName: optionalString(fileSource.fileName),
        sizeName: optionalString(fileSource.sizeName),
      }
    : null;
  if (rawType === 1 && !file) return null;

  return {
    id,
    type: rawType,
    decName: optionalString(source.decName),
    decText: optionalString(source.decText),
    decFileName: optionalString(source.decFileName),
    expirationDate: optionalString(source.expirationDate),
    file,
  };
}

export default function PublicSendPage(props: PublicSendPageProps) {
  const initialDemoSend = IS_DEMO_MODE ? getDemoPublicSend(props.accessId) : null;
  const [loading, setLoading] = useState(!IS_DEMO_MODE);
  const [password, setPassword] = useState('');
  const [needPassword, setNeedPassword] = useState(false);
  const [error, setError] = useState('');
  const [notFound, setNotFound] = useState(IS_DEMO_MODE && !initialDemoSend);
  const [sendData, setSendData] = useState<PublicSendData | null>(initialDemoSend);
  const [busy, setBusy] = useState(false);
  const [downloadPercent, setDownloadPercent] = useState<number | null>(null);
  const loadRequestRef = useRef(0);
  const loadAbortRef = useRef<AbortController | null>(null);

  async function loadSend(pass?: string): Promise<void> {
    loadAbortRef.current?.abort();
    const controller = new AbortController();
    const requestId = loadRequestRef.current + 1;
    loadRequestRef.current = requestId;
    loadAbortRef.current = controller;
    setBusy(true);
    setError('');
    setNotFound(false);
    setLoading(true);
    try {
      if (IS_DEMO_MODE) {
        const demoSend = getDemoPublicSend(props.accessId);
        if (!demoSend) {
          setNotFound(true);
          setSendData(null);
          return;
        }
        setSendData(demoSend);
        setNeedPassword(false);
        return;
      }
      if (!hasUsableSendKey(props.keyPart)) {
        setNotFound(true);
        setSendData(null);
        return;
      }
      const data = await accessPublicSend(props.accessId, props.keyPart, pass, { signal: controller.signal });
      if (controller.signal.aborted || requestId !== loadRequestRef.current) return;
      if (!props.keyPart) {
        setError(t('txt_this_link_is_missing_decryption_key'));
        setSendData(null);
        return;
      }
      const decrypted = await decryptPublicSend(data, props.keyPart);
      if (controller.signal.aborted || requestId !== loadRequestRef.current) return;
      const parsed = parsePublicSendData(decrypted);
      if (!parsed) throw new Error(t('txt_send_unavailable'));
      setSendData(parsed);
      setNeedPassword(false);
    } catch (e) {
      if (controller.signal.aborted || requestId !== loadRequestRef.current) return;
      const err = e as Error & { status?: number };
      if (err.status === 401) {
        setNeedPassword(true);
        setError(t('txt_this_send_is_password_protected'));
      } else if (err.status === 404) {
        setNeedPassword(false);
        setNotFound(true);
        setError('');
      } else {
        setError(err.message || t('txt_failed_to_open_send'));
      }
      setSendData(null);
    } finally {
      if (controller.signal.aborted || requestId !== loadRequestRef.current) return;
      setBusy(false);
      setLoading(false);
    }
  }

  async function downloadFile(): Promise<void> {
    if (!sendData?.id || !sendData?.file?.id) return;
    setBusy(true);
    setDownloadPercent(null);
    setError('');
    try {
      if (IS_DEMO_MODE) {
        const bytes = new TextEncoder().encode('NodeWarden demo file Send.\nThis download is generated locally in demo mode.\n');
        downloadBytesAsFile(bytes, sendData.decFileName || sendData.file?.fileName || 'nodewarden-demo-send.txt', 'application/octet-stream');
        return;
      }
      const url = await accessPublicSendFile(sendData.id, sendData.file.id, props.keyPart, password || undefined);
      const resp = await fetch(url);
      if (!resp.ok) throw new Error(t('txt_download_failed'));
      const encryptedBytes = await readResponseBytesWithProgress(resp, (progress) => setDownloadPercent(progress.percent));
      let blob: Blob;
      if (props.keyPart) {
        try {
          const decryptedBytes = await decryptPublicSendFileBytes(encryptedBytes, props.keyPart);
          blob = new Blob([toBufferSource(decryptedBytes)], { type: 'application/octet-stream' });
        } catch {
          // Legacy compatibility: early web-created file sends uploaded plaintext bytes.
          blob = new Blob([toBufferSource(encryptedBytes)], { type: 'application/octet-stream' });
        }
      } else {
        blob = new Blob([toBufferSource(encryptedBytes)], { type: 'application/octet-stream' });
      }
      downloadBytesAsFile(
        new Uint8Array(await blob.arrayBuffer()),
        sendData.decFileName || sendData.file?.fileName || t('txt_send_file'),
        'application/octet-stream'
      );
    } catch (e) {
      const err = e as Error;
      setError(err.message || t('txt_download_failed'));
    } finally {
      setBusy(false);
      setDownloadPercent(null);
    }
  }

  useEffect(() => {
    if (IS_DEMO_MODE) {
      const demoSend = getDemoPublicSend(props.accessId);
      setSendData(demoSend);
      setNotFound(!demoSend);
      setNeedPassword(false);
      setError('');
      setLoading(false);
      return;
    }
    void loadSend();
    return () => {
      loadAbortRef.current?.abort();
    };
  }, [props.accessId, props.keyPart]);

  if (!loading && notFound) {
    return <NotFoundPage title={t('txt_page_not_found')} message={t('txt_send_unavailable')} />;
  }

  return (
    <div className="auth-page public-send-page">
      <StandalonePageFrame
        title={sendData ? (sendData.decName || t('txt_no_name')) : t('txt_nodewarden_send')}
        eyebrow={sendData ? t('txt_nodewarden_send') : undefined}
      >
        {loading && <p className="muted">{t('txt_loading')}</p>}

        {!loading && needPassword && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void loadSend(password);
            }}
          >
            <label className="field">
              <span>{t('txt_password')}</span>
              <div className="password-wrap">
                <input
                  className="input"
                  type="password"
                  value={password}
                  autoComplete="current-password"
                  onInput={(e) => setPassword((e.currentTarget as HTMLInputElement).value)}
                />
              </div>
            </label>
            <button type="submit" className="btn btn-primary full" disabled={busy}>
              <Lock size={14} className="btn-icon" /> {t('txt_unlock_send')}
            </button>
          </form>
        )}

        {!loading && sendData && (
          <>
            {sendData.type === 0 && parseSharedLogin(sendData.decText) ? (
              (() => {
                const login = parseSharedLogin(sendData.decText)!;
                return (
                  <div className="card public-send-card">
                    <div className="public-send-card-head">
                      <span>{t('txt_shared_login') || 'Shared login'}</span>
                    </div>
                    {login.uri ? (
                      <div className="kv-line public-send-login-row">
                        <span>{t('txt_website') || 'Website'}</span>
                        <strong className="public-send-login-value">{login.uri}</strong>
                      </div>
                    ) : null}
                    {login.username ? (
                      <div className="kv-line public-send-login-row">
                        <span>{t('txt_username') || 'Username'}</span>
                        <strong className="public-send-login-value">{login.username}</strong>
                        <button type="button" className="btn btn-secondary small" onClick={() => void copyTextToClipboard(login.username)}>
                          <Clipboard size={14} className="btn-icon" />{t('txt_copy')}
                        </button>
                      </div>
                    ) : null}
                    {login.password ? (
                      <div className="kv-line public-send-login-row">
                        <span>{t('txt_password') || 'Password'}</span>
                        <strong className="public-send-login-value public-send-password">{login.password}</strong>
                        <button type="button" className="btn btn-secondary small" onClick={() => void copyTextToClipboard(login.password)}>
                          <Clipboard size={14} className="btn-icon" />{t('txt_copy')}
                        </button>
                      </div>
                    ) : null}
                    {login.totp ? (
                      <div className="kv-line public-send-login-row">
                        <span>{t('txt_verification_code') || 'Verification code'}</span>
                        <LiveTotp secret={login.totp} />
                      </div>
                    ) : null}
                    {login.note ? <div className="notes" style={{ marginTop: '10px' }}>{login.note}</div> : null}
                  </div>
                );
              })()
            ) : sendData.type === 0 ? (
              <div className="card public-send-card">
                <div className="public-send-card-head">
                  <span>{t('txt_text_send')}</span>
                  <button
                    type="button"
                    className="btn btn-secondary small public-send-copy-btn"
                    disabled={!sendData.decText}
                    onClick={() => void copyTextToClipboard(sendData.decText || '')}
                  >
                    <Clipboard size={14} className="btn-icon" />
                    {t('txt_copy')}
                  </button>
                </div>
                <div className="notes">{sendData.decText || ''}</div>
              </div>
            ) : (
              <div className="card public-send-card">
                <div className="kv-line">
                  <span>{t('txt_file')}</span>
                  <strong>{sendData.decFileName || sendData.file?.fileName || sendData.file?.sizeName || t('txt_encrypted_file')}</strong>
                </div>
                <button type="button" className="btn btn-primary full" disabled={busy} onClick={() => void downloadFile()}>
                  <Download size={14} className="btn-icon" /> {downloadPercent == null ? (busy ? t('txt_downloading') : t('txt_download')) : t('txt_downloading_percent', { percent: downloadPercent })}
                </button>
              </div>
            )}
            {!!sendData.expirationDate && <p className="muted">{t('txt_expires_at_value', { value: formatSendDate(sendData.expirationDate) })}</p>}
          </>
        )}

        {!loading && !sendData && !needPassword && !error && (
          <p className="muted">
            <Eye size={14} className="inline-status-icon" /> {t('txt_send_unavailable')}
          </p>
        )}
        {!!error && <p className="local-error">{error}</p>}
      </StandalonePageFrame>
    </div>
  );
}
