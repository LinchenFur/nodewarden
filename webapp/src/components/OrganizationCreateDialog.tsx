import { useState } from 'preact/hooks';
import { Building2 } from 'lucide-preact';
import ConfirmDialog from '@/components/ConfirmDialog';
import { createOrganization } from '@/lib/api/organizations';
import type { AuthedFetch } from '@/lib/api/shared';
import type { SessionState } from '@/lib/types';
import { t } from '@/lib/i18n';

interface OrganizationCreateDialogProps {
  open: boolean;
  session: SessionState | null;
  authedFetch: AuthedFetch;
  onClose: () => void;
  onCreated: (summary: { id: string; name: string }) => void;
}

// Minimal client-side organization creation. All key material is generated and
// wrapped in the browser (see lib/api/organizations.ts) so the server only ever
// receives already-encrypted keys.
export default function OrganizationCreateDialog(props: OrganizationCreateDialogProps) {
  const [name, setName] = useState('');
  const [collectionName, setCollectionName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reset = () => {
    setName('');
    setCollectionName('');
    setError(null);
    setBusy(false);
  };

  const handleCancel = () => {
    if (busy) return;
    reset();
    props.onClose();
  };

  const handleConfirm = async () => {
    if (busy) return;
    const trimmed = name.trim();
    if (!trimmed) {
      setError(t('txt_organization_name_required') || 'Organization name is required');
      return;
    }
    if (!props.session?.symEncKey || !props.session?.symMacKey) {
      setError(t('txt_vault_locked') || 'Vault is locked');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const summary = await createOrganization(props.authedFetch, props.session, {
        name: trimmed,
        collectionName: collectionName.trim() || undefined,
      });
      reset();
      props.onCreated({ id: summary.id, name: summary.name });
      props.onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Create organization failed');
      setBusy(false);
    }
  };

  return (
    <ConfirmDialog
      open={props.open}
      title={(
        <span className="dialog-title-stack">
          <span className="dialog-hero-icon" aria-hidden="true">
            <Building2 size={22} />
          </span>
          <span>{t('txt_new_organization') || 'New organization'}</span>
          <span className="dialog-subtitle">
            {t('txt_new_organization_subtitle') || 'Create a shared space to organize and share logins.'}
          </span>
        </span>
      )}
      confirmText={busy ? (t('txt_saving') || 'Saving...') : (t('txt_create') || 'Create')}
      cancelText={t('txt_cancel') || 'Cancel'}
      confirmDisabled={busy}
      cancelDisabled={busy}
      closeButton
      onConfirm={() => void handleConfirm()}
      onCancel={handleCancel}
    >
      <label className="field">
        <span>{t('txt_organization_name') || 'Organization name'}</span>
        <input
          className="input"
          type="text"
          value={name}
          disabled={busy}
          onInput={(e) => setName((e.currentTarget as HTMLInputElement).value)}
          placeholder={t('txt_organization_name_placeholder') || 'e.g. My Team'}
        />
      </label>
      <label className="field">
        <span>{t('txt_collection_name') || 'First collection name'}</span>
        <input
          className="input"
          type="text"
          value={collectionName}
          disabled={busy}
          onInput={(e) => setCollectionName((e.currentTarget as HTMLInputElement).value)}
          placeholder={t('txt_collection_name_placeholder') || 'Default collection'}
        />
        <small className="field-help">
          {t('txt_collection_name_help') || 'Shared items live inside collections. We will create one to start.'}
        </small>
      </label>
      {error ? <p className="form-error" role="alert">{error}</p> : null}
    </ConfirmDialog>
  );
}
