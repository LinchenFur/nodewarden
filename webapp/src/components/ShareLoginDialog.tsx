import { useEffect, useState } from "preact/hooks";
import { Clipboard } from "lucide-preact";
import ConfirmDialog from "@/components/ConfirmDialog";
import { createSend, buildSendShareKey } from "@/lib/api/send";
import { buildPublicSendUrl } from "@/lib/app-support";
import { copyTextToClipboard } from "@/lib/clipboard";
import type { AuthedFetch } from "@/lib/api/shared";
import type { Cipher, SendDraft, SessionState } from "@/lib/types";
import { t } from "@/lib/i18n";

interface ShareLoginDialogProps {
  open: boolean;
  cipher: Cipher | null;
  session: SessionState | null;
  authedFetch: AuthedFetch;
  onClose: () => void;
}

// Shares a vault login as a Send link: packs the username/password/TOTP into a
// structured text Send so the recipient can open a web link and see the
// password plus a live-refreshing 2FA code, with an optional expiry.
export default function ShareLoginDialog(props: ShareLoginDialogProps) {
  const [expirationDays, setExpirationDays] = useState("7");
  const [maxAccessCount, setMaxAccessCount] = useState("");
  const [password, setPassword] = useState("");
  const [includeTotp, setIncludeTotp] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [link, setLink] = useState<string | null>(null);

  const login = props.cipher?.login || null;
  const hasTotp = !!(login?.decTotp && login.decTotp.trim());

  useEffect(() => {
    if (props.open) {
      setExpirationDays("7");
      setMaxAccessCount("");
      setPassword("");
      setIncludeTotp(true);
      setError(null);
      setLink(null);
      setBusy(false);
    }
  }, [props.open, props.cipher?.id]);

  const close = () => { if (busy) return; props.onClose(); };

  const generate = async () => {
    if (busy || !props.cipher || !props.session) return;
    if (!props.session.symEncKey || !props.session.symMacKey) { setError(t("txt_vault_locked") || "Vault is locked"); return; }
    setBusy(true); setError(null);
    try {
      const cipherName = props.cipher.decName || props.cipher.name || "";
      const firstUri = Array.isArray(login?.uris) && login!.uris!.length ? (login!.uris![0].decUri || "") : "";
      const payload = {
        nwShare: 1,
        username: login?.decUsername || "",
        password: login?.decPassword || "",
        totp: includeTotp && hasTotp ? (login?.decTotp || "") : "",
        uri: firstUri,
        note: props.cipher.decNotes || "",
      };
      // Deletion must be a positive number of days (the server rejects 0/empty
      // for deletion). Bind it to the chosen expiration when that is a positive
      // number, otherwise fall back to a safe default so "expire = 0" (treated
      // as no expiration) does not produce an instantly-dead link.
      const expDaysNum = Number(expirationDays.trim());
      const deletionDays = Number.isFinite(expDaysNum) && expDaysNum > 0 ? String(Math.floor(expDaysNum)) : "30";
      const draft: SendDraft = {
        type: "text",
        name: cipherName,
        notes: "",
        text: JSON.stringify(payload),
        file: null,
        deletionDays,
        expirationDays: expirationDays.trim(),
        maxAccessCount: maxAccessCount.trim(),
        password: password,
        disabled: false,
        // Do not expose the sharer's account email to link recipients.
        hideEmail: true,
      };
      const created = await createSend(props.authedFetch, props.session, draft);
      const keyPart = await buildSendShareKey(created.key || "", props.session.symEncKey, props.session.symMacKey);
      const url = buildPublicSendUrl(window.location.origin, created.accessId, keyPart);
      setLink(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : (t("txt_create_send_failed") || "Create send failed"));
    }
    setBusy(false);
  };

  return (
    <ConfirmDialog
      open={props.open}
      title={t("txt_share_as_link") || "Share as link"}
      confirmText={link ? (t("txt_done") || "Done") : busy ? (t("txt_saving") || "Saving...") : (t("txt_generate_link") || "Generate link")}
      cancelText={t("txt_close") || "Close"}
      hideCancel={!!link}
      confirmDisabled={busy}
      cancelDisabled={busy}
      closeButton
      onConfirm={() => { if (link) { props.onClose(); } else { void generate(); } }}
      onCancel={close}
    >
      {!link ? (
        <div className="stack">
          <p className="muted">{t("txt_share_login_hint") || "Creates a link. Anyone with the link can view the password and, if included, a live 2FA code."}</p>
          <div className="field">
            <label>
              <span>{t("txt_expiration_days") || "Expires after (days)"}</span>
              <input type="number" min="0" value={expirationDays} disabled={busy} placeholder="7"
                onInput={(e) => setExpirationDays((e.target as HTMLInputElement).value)} />
            </label>
          </div>
          <div className="field">
            <label>
              <span>{t("txt_max_access_count") || "Max views (optional)"}</span>
              <input type="number" min="1" value={maxAccessCount} disabled={busy} placeholder="∞"
                onInput={(e) => setMaxAccessCount((e.target as HTMLInputElement).value)} />
            </label>
          </div>
          <div className="field">
            <label>
              <span>{t("txt_access_password_optional") || "Access password (optional)"}</span>
              <input type="text" value={password} disabled={busy} autoComplete="off"
                onInput={(e) => setPassword((e.target as HTMLInputElement).value)} />
            </label>
          </div>
          {hasTotp ? (
            <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <input type="checkbox" checked={includeTotp} disabled={busy} onChange={() => setIncludeTotp((v) => !v)} />
              <span>{t("txt_include_live_2fa") || "Include live 2FA code"}</span>
            </label>
          ) : null}
          {error ? <p className="form-error" role="alert">{error}</p> : null}
        </div>
      ) : (
        <div className="stack">
          <p className="muted">{t("txt_share_link_ready") || "Link ready. Anyone with this link can view it until it expires."}</p>
          <div className="field" style={{ display: "flex", gap: "8px", alignItems: "flex-end" }}>
            <input type="text" readonly value={link} style={{ flex: "1 1 auto" }} onFocus={(e) => (e.target as HTMLInputElement).select()} />
            <button type="button" className="btn btn-primary" onClick={() => void copyTextToClipboard(link)}>
              <Clipboard size={14} className="btn-icon" />{t("txt_copy") || "Copy"}
            </button>
          </div>
          {hasTotp && includeTotp ? <p className="muted">{t("txt_share_link_totp_note") || "The link shows a 2FA code that refreshes automatically."}</p> : null}
        </div>
      )}
    </ConfirmDialog>
  );
}
