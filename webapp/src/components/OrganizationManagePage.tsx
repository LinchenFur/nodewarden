import { useEffect, useState } from "preact/hooks";
import ConfirmDialog from "@/components/ConfirmDialog";
import { listOrgMembers, inviteOrgMember, getOrgMember, confirmOrgMember, removeOrgMember, createOrgCollection, deleteOrgCollection, type OrgMember } from "@/lib/api/organizations";
import { base64ToBytes, encryptBw } from "@/lib/crypto";
import { unwrapOrgKey } from "@/lib/vault-decrypt";
import type { AuthedFetch } from "@/lib/api/shared";
import type { OrgProfile, OrgCollection, SessionState } from "@/lib/types";
import { t } from "@/lib/i18n";
import "@/styles/organization-manage.css";

interface OrganizationManagePageProps {
  organizationId: string | null;
  organizations: OrgProfile[];
  collections: OrgCollection[];
  session: SessionState | null;
  userPrivateKeyB64?: string;
  authedFetch: AuthedFetch;
  onClose: () => void;
  onChanged: () => void;
}

export default function OrganizationManagePage(props: OrganizationManagePageProps) {
  const [members, setMembers] = useState<OrgMember[]>([]);
  const [inviteEmail, setInviteEmail] = useState("");
  const [newCollection, setNewCollection] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loadingMembers, setLoadingMembers] = useState(false);
  // Collections mirror props but can be nudged optimistically so a freshly
  // added or removed collection shows immediately, before the parent's async
  // sync refetch completes.
  const [localCollections, setLocalCollections] = useState<OrgCollection[]>([]);

  const org = props.organizations.find((o) => o.id === props.organizationId) || null;
  const propCollections = props.collections.filter((c) => c.organizationId === props.organizationId);
  // Prefer whichever list is longer so an optimistic add is not clobbered by a
  // stale prop snapshot, and a delete is not resurrected by one.
  const orgCollections = localCollections.length >= propCollections.length ? localCollections : propCollections;

  useEffect(() => { setLocalCollections(propCollections); }, [props.collections, props.organizationId]);

  const refreshMembers = async () => {
    if (!props.organizationId) return;
    setLoadingMembers(true);
    try { setMembers(await listOrgMembers(props.authedFetch, props.organizationId)); }
    catch (e) { setError(e instanceof Error ? e.message : (t("txt_load_failed") || "Load failed")); }
    finally { setLoadingMembers(false); }
  };

  useEffect(() => { if (props.organizationId) { setError(null); void refreshMembers(); } }, [props.organizationId]);

  const deriveOrgKey = async (): Promise<Uint8Array> => {
    if (!org || !org.key || !props.session?.symEncKey || !props.session?.symMacKey) throw new Error("Vault locked");
    const userPrivateKey = props.userPrivateKeyB64 ? base64ToBytes(props.userPrivateKeyB64) : null;
    const orgKey = await unwrapOrgKey(org.key, base64ToBytes(props.session.symEncKey), base64ToBytes(props.session.symMacKey), userPrivateKey);
    if (!orgKey) throw new Error("Bad org key");
    const raw = new Uint8Array(64);
    raw.set(orgKey.enc, 0);
    raw.set(orgKey.mac, 32);
    return raw;
  };

  const handleInvite = async () => {
    if (busy || !props.organizationId || !inviteEmail.trim()) return;
    setBusy(true); setError(null);
    try { await inviteOrgMember(props.authedFetch, props.organizationId, inviteEmail.trim().toLowerCase(), 2); setInviteEmail(""); await refreshMembers(); } catch (e) { setError(e instanceof Error ? e.message : "Invite failed"); }
    setBusy(false);
  };

  const handleConfirm = async (m: OrgMember) => {
    if (busy || !props.organizationId || !props.session) return;
    setBusy(true); setError(null);
    try {
      const detail = await getOrgMember(props.authedFetch, props.organizationId, m.id);
      if (!detail.publicKey) throw new Error("Member has no public key");
      const orgKeyRaw = await deriveOrgKey();
      await confirmOrgMember(props.authedFetch, props.session, props.organizationId, m.id, orgKeyRaw, detail.publicKey);
      await refreshMembers();
    } catch (e) { setError(e instanceof Error ? e.message : "Confirm failed"); }
    setBusy(false);
  };

  const handleRemove = async (m: OrgMember) => {
    if (busy || !props.organizationId) return;
    setBusy(true); setError(null);
    try { await removeOrgMember(props.authedFetch, props.organizationId, m.id); await refreshMembers(); } catch (e) { setError(e instanceof Error ? e.message : "Remove failed"); }
    setBusy(false);
  };

  const handleCreateCollection = async () => {
    if (busy || !props.organizationId || !newCollection.trim()) return;
    setBusy(true); setError(null);
    const name = newCollection.trim();
    try {
      const raw = await deriveOrgKey();
      const encName = await encryptBw(new TextEncoder().encode(name), raw.slice(0, 32), raw.slice(32, 64));
      const created = await createOrgCollection(props.authedFetch, props.organizationId, encName);
      setNewCollection("");
      // Optimistically show the new collection with its plaintext name so the
      // list updates immediately, before the parent's async sync refetch lands.
      if (created.id && !orgCollections.some((c) => c.id === created.id)) {
        setLocalCollections((cur) => [...cur, { id: created.id, organizationId: props.organizationId!, name: encName, decName: name } as OrgCollection]);
      }
      props.onChanged();
    } catch (e) { setError(e instanceof Error ? e.message : "Create collection failed"); }
    setBusy(false);
  };

  const handleDeleteCollection = async (collectionId: string) => {
    if (busy || !props.organizationId) return;
    setBusy(true); setError(null);
    try {
      await deleteOrgCollection(props.authedFetch, props.organizationId, collectionId);
      setLocalCollections((cur) => cur.filter((c) => c.id !== collectionId));
      props.onChanged();
    } catch (e) { setError(e instanceof Error ? e.message : "Delete failed"); }
    setBusy(false);
  };

  const roleLabel = (type: number) => (type === 0 ? "Owner" : type === 1 ? "Admin" : "User");
  const statusLabel = (status: number) => (status === 2 ? (t("txt_confirmed") || "Confirmed") : status === 1 ? (t("txt_accepted") || "Accepted") : (t("txt_invited") || "Invited"));
  const roleClass = (type: number) => (type === 0 ? "om-badge om-badge-owner" : type === 1 ? "om-badge om-badge-admin" : "om-badge om-badge-user");
  const statusClass = (status: number) => (status === 2 ? "om-badge om-badge-ok" : status === 1 ? "om-badge om-badge-pending" : "om-badge om-badge-muted");

  const emailValid = /.+@.+\..+/.test(inviteEmail.trim());
  const confirmedCount = members.filter((m) => m.status === 2).length;

  return (
    <ConfirmDialog
      open={!!props.organizationId}
      title={(org?.name || "") + " · " + (t("txt_manage_organization") || "Manage organization")}
      confirmText={t("txt_close") || "Close"}
      hideCancel
      closeButton
      onConfirm={() => props.onClose()}
      onCancel={() => props.onClose()}
    >
      <div className="om-stack">
        <section className="om-section">
          <header className="om-section-head">
            <h4 className="om-section-title">{t("txt_members") || "Members"}</h4>
            <span className="om-count">{confirmedCount}/{members.length}</span>
          </header>
          <p className="om-hint">{t("txt_invite_member_hint") || "Invite a member by email, then confirm them once they accept."}</p>
          <div className="om-inline-form">
            <input
              type="email"
              className="om-input"
              value={inviteEmail}
              disabled={busy}
              placeholder={t("txt_member_email_placeholder") || "member@example.com"}
              onInput={(e) => setInviteEmail((e.target as HTMLInputElement).value)}
              onKeyDown={(e) => { if (e.key === "Enter" && emailValid && !busy) { e.preventDefault(); void handleInvite(); } }}
            />
            <button type="button" className="btn btn-primary" disabled={busy || !emailValid} onClick={() => void handleInvite()}>{t("txt_invite") || "Invite"}</button>
          </div>
          {loadingMembers && members.length === 0 ? (
            <p className="om-empty">{t("txt_loading") || "Loading…"}</p>
          ) : members.length === 0 ? (
            <p className="om-empty">{t("txt_no_members") || "No members yet."}</p>
          ) : (
            <ul className="om-list">
              {members.map((m) => (
                <li key={m.id} className="om-row">
                  <div className="om-row-main">
                    <span className="om-row-title">{m.email}</span>
                    <span className="om-row-tags">
                      <span className={roleClass(m.type)}>{roleLabel(m.type)}</span>
                      <span className={statusClass(m.status)}>{statusLabel(m.status)}</span>
                    </span>
                  </div>
                  <div className="om-row-actions">
                    {m.status === 1 ? <button type="button" className="btn btn-primary btn-sm" disabled={busy} onClick={() => void handleConfirm(m)}>{t("txt_confirm") || "Confirm"}</button> : null}
                    {m.type === 0 ? null : <button type="button" className="btn btn-danger btn-sm" disabled={busy} onClick={() => void handleRemove(m)}>{t("txt_remove") || "Remove"}</button>}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="om-section">
          <header className="om-section-head">
            <h4 className="om-section-title">{t("txt_collections") || "Collections"}</h4>
            <span className="om-count">{orgCollections.length}</span>
          </header>
          <p className="om-hint">{t("txt_collection_hint") || "Collections group shared items. Members see items in their collections."}</p>
          <div className="om-inline-form">
            <input
              type="text"
              className="om-input"
              value={newCollection}
              disabled={busy}
              placeholder={t("txt_collection_name_short") || "Collection name"}
              onInput={(e) => setNewCollection((e.target as HTMLInputElement).value)}
              onKeyDown={(e) => { if (e.key === "Enter" && newCollection.trim() && !busy) { e.preventDefault(); void handleCreateCollection(); } }}
            />
            <button type="button" className="btn btn-primary" disabled={busy || !newCollection.trim()} onClick={() => void handleCreateCollection()}>{t("txt_add") || "Add"}</button>
          </div>
          {orgCollections.length === 0 ? (
            <p className="om-empty">{t("txt_no_collections") || "No collections yet."}</p>
          ) : (
            <ul className="om-list">
              {orgCollections.map((c) => (
                <li key={c.id} className="om-row">
                  <span className="om-row-title">{c.decName || c.name}</span>
                  <div className="om-row-actions">
                    <button type="button" className="btn btn-danger btn-sm" disabled={busy} onClick={() => void handleDeleteCollection(c.id)}>{t("txt_delete") || "Delete"}</button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>

        {error ? <p className="form-error" role="alert">{error}</p> : null}
      </div>
    </ConfirmDialog>
  );
}
