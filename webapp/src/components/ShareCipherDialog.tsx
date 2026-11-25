import { useState } from "preact/hooks";
import ConfirmDialog from "@/components/ConfirmDialog";
import { shareCipherToOrganization } from "@/lib/api/vault";
import { base64ToBytes, bytesToBase64 } from "@/lib/crypto";
import { unwrapOrgKey } from "@/lib/vault-decrypt";
import type { AuthedFetch } from "@/lib/api/shared";
import type { Cipher, OrgProfile, OrgCollection, SessionState } from "@/lib/types";
import { t } from "@/lib/i18n";

interface ShareCipherDialogProps {
  open: boolean;
  cipher: Cipher | null;
  organizations: OrgProfile[];
  collections: OrgCollection[];
  session: SessionState | null;
  userPrivateKeyB64?: string;
  authedFetch: AuthedFetch;
  onClose: () => void;
  onShared: () => void;
}

export default function ShareCipherDialog(props: ShareCipherDialogProps) {
  const [orgId, setOrgId] = useState("");
  const [selectedCollections, setSelectedCollections] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const confirmedOrgs = props.organizations.filter((o) => o.status === 2 && o.key);
  const orgCollections = props.collections.filter((c) => c.organizationId === orgId);

  const reset = () => { setOrgId(""); setSelectedCollections([]); setError(null); setBusy(false); };
  const cancel = () => { if (busy) return; reset(); props.onClose(); };

  const toggle = (id: string) => {
    setSelectedCollections((cur) => cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]);
  };

  const confirm = async () => {
    if (busy) return;
    if (!props.cipher) return;
    if (!orgId) { setError(t("txt_select_organization") || "Select an organization"); return; }
    if (!selectedCollections.length) { setError(t("txt_select_collection") || "Select a collection"); return; }
    if (!props.session?.symEncKey || !props.session?.symMacKey) { setError("Vault locked"); return; }
    const org = confirmedOrgs.find((o) => o.id === orgId);
    if (!org || !org.key) { setError("Organization key unavailable"); return; }
    setBusy(true); setError(null);
    try {
      const userEnc = base64ToBytes(props.session.symEncKey);
      const userMac = base64ToBytes(props.session.symMacKey);
      const userPrivateKey = props.userPrivateKeyB64 ? base64ToBytes(props.userPrivateKeyB64) : null;
      const orgKey = await unwrapOrgKey(org.key, userEnc, userMac, userPrivateKey);
      if (!orgKey) throw new Error("Organization key unavailable");
      const orgKeyB64 = { enc: bytesToBase64(orgKey.enc), mac: bytesToBase64(orgKey.mac) };
      await shareCipherToOrganization(props.authedFetch, props.session, props.cipher, orgId, orgKeyB64, selectedCollections);
      reset();
      props.onShared();
      props.onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Share failed");
      setBusy(false);
    }
  };

  return (
    <ConfirmDialog
      open={props.open}
      title={t("txt_share_to_organization") || "Share to organization"}
      confirmText={busy ? (t("txt_saving") || "Saving...") : (t("txt_share") || "Share")}
      cancelText={t("txt_cancel") || "Cancel"}
      confirmDisabled={busy}
      cancelDisabled={busy}
      closeButton
      onConfirm={() => void confirm()}
      onCancel={cancel}
    >
      <div className="field">
        <label>
          <span>{t("txt_organizations") || "Organization"}</span>
          <select value={orgId} disabled={busy} onChange={(e) => { setOrgId((e.target as HTMLSelectElement).value); setSelectedCollections([]); }}>
            <option value="">--</option>
            {confirmedOrgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
          </select>
        </label>
      </div>
      {orgId ? (
        <div className="field">
          <span>{t("txt_collections") || "Collections"}</span>
          {orgCollections.length === 0 ? <p>{t("txt_no_collections") || "No collections"}</p> : orgCollections.map((c) => (
            <label key={c.id} style={{ display: "block" }}>
              <input type="checkbox" checked={selectedCollections.includes(c.id)} disabled={busy} onChange={() => toggle(c.id)} /> {c.decName || c.name}
            </label>
          ))}
        </div>
      ) : null}
      {error ? <p className="form-error" role="alert">{error}</p> : null}
    </ConfirmDialog>
  );
}
