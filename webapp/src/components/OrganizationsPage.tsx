import { useEffect, useMemo, useState } from 'preact/hooks';
import { useQuery } from '@tanstack/react-query';
import { Building2, FolderKanban, Plus, RefreshCw, Save, Users } from 'lucide-preact';
import {
  createOrganization,
  createOrganizationCollection,
  listOrganizationCollectionAccessDetails,
  listOrganizationMembers,
  listOrganizations,
  updateOrganizationMember,
} from '@/lib/api/organizations';
import type { AuthedFetch } from '@/lib/api/shared';
import { t } from '@/lib/i18n';
import type {
  OrganizationCollectionAccessDetail,
  OrganizationMember,
  OrganizationSummary,
  Profile,
} from '@/lib/types';

interface OrganizationsPageProps {
  profile: Profile;
  authedFetch: AuthedFetch;
  onNotify?: (type: 'success' | 'error' | 'warning', text: string) => void;
}

interface MemberCollectionDraft {
  assigned: boolean;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

interface MemberDraft {
  type: number;
  accessAll: boolean;
  collections: Record<string, MemberCollectionDraft>;
}

function normalizeMemberRole(type: number): number {
  return Number(type) === 4 ? 3 : Number(type);
}

function buildMemberDraft(
  member: OrganizationMember,
  collections: OrganizationCollectionAccessDetail[]
): MemberDraft {
  const draftCollections: Record<string, MemberCollectionDraft> = {};
  for (const collection of collections) {
    draftCollections[collection.id] = {
      assigned: false,
      readOnly: false,
      hidePasswords: false,
      manage: false,
    };
  }

  for (const assignment of member.collections || []) {
    draftCollections[assignment.id] = {
      assigned: true,
      readOnly: !!assignment.readOnly,
      hidePasswords: !!assignment.hidePasswords,
      manage: !!assignment.manage,
    };
  }

  return {
    type: normalizeMemberRole(member.type),
    accessAll: !!member.accessAll || normalizeMemberRole(member.type) <= 1,
    collections: draftCollections,
  };
}

function countAssignedCollections(draft: MemberDraft | null | undefined): number {
  if (!draft) return 0;
  return Object.values(draft.collections).filter((collection) => collection.assigned).length;
}

export default function OrganizationsPage(props: OrganizationsPageProps) {
  const [selectedOrganizationId, setSelectedOrganizationId] = useState('');
  const [creatingOrganization, setCreatingOrganization] = useState(false);
  const [creatingCollection, setCreatingCollection] = useState(false);
  const [savingMemberId, setSavingMemberId] = useState('');
  const [organizationForm, setOrganizationForm] = useState({
    name: '',
    billingEmail: props.profile.email || '',
    collectionName: '',
  });
  const [collectionName, setCollectionName] = useState('');
  const [memberDrafts, setMemberDrafts] = useState<Record<string, MemberDraft>>({});

  const organizationsQuery = useQuery({
    queryKey: ['organizations', props.profile.id],
    queryFn: () => listOrganizations(props.authedFetch),
    enabled: !!props.profile.id,
  });

  const collectionDetailsQuery = useQuery({
    queryKey: ['organization-collection-details', selectedOrganizationId],
    queryFn: () => listOrganizationCollectionAccessDetails(props.authedFetch, selectedOrganizationId),
    enabled: !!selectedOrganizationId,
  });

  const membersQuery = useQuery({
    queryKey: ['organization-members', selectedOrganizationId],
    queryFn: () => listOrganizationMembers(props.authedFetch, selectedOrganizationId),
    enabled: !!selectedOrganizationId,
  });

  useEffect(() => {
    const organizations = organizationsQuery.data || [];
    if (!organizations.length) {
      if (selectedOrganizationId) setSelectedOrganizationId('');
      return;
    }

    if (!selectedOrganizationId || !organizations.some((entry) => entry.id === selectedOrganizationId)) {
      setSelectedOrganizationId(organizations[0].id);
    }
  }, [organizationsQuery.data, selectedOrganizationId]);

  useEffect(() => {
    if (!selectedOrganizationId) {
      setMemberDrafts({});
      return;
    }

    const collections = collectionDetailsQuery.data || [];
    const members = membersQuery.data || [];
    const nextDrafts: Record<string, MemberDraft> = {};
    for (const member of members) {
      nextDrafts[member.id] = buildMemberDraft(member, collections);
    }
    setMemberDrafts(nextDrafts);
  }, [selectedOrganizationId, collectionDetailsQuery.data, membersQuery.data]);

  const organizations = organizationsQuery.data || [];
  const collections = collectionDetailsQuery.data || [];
  const members = membersQuery.data || [];
  const organizationsError = organizationsQuery.error instanceof Error ? organizationsQuery.error.message : '';
  const collectionsError = collectionDetailsQuery.error instanceof Error ? collectionDetailsQuery.error.message : '';
  const membersError = membersQuery.error instanceof Error ? membersQuery.error.message : '';
  const selectedOrganization = useMemo<OrganizationSummary | null>(
    () => organizations.find((entry) => entry.id === selectedOrganizationId) || null,
    [organizations, selectedOrganizationId]
  );
  const currentMember = useMemo(
    () => members.find((entry) => entry.userId === props.profile.id) || null,
    [members, props.profile.id]
  );

  const currentMemberRole = normalizeMemberRole(Number(currentMember?.type ?? 2));
  const actorIsOwner = currentMemberRole === 0;
  const actorCanManageMembers = !!currentMember && (
    currentMemberRole <= 1 || (currentMemberRole === 3 && !!currentMember.accessAll)
  );
  const ownerCount = members.filter(
    (entry) => Number(entry.status) === 2 && normalizeMemberRole(Number(entry.type)) === 0
  ).length;

  const roleOptions = [
    { value: 0, label: t('txt_role_owner') },
    { value: 1, label: t('txt_role_admin') },
    { value: 2, label: t('txt_role_user') },
    { value: 3, label: t('txt_role_manager') },
  ];

  const statusLabel = (status: number) => {
    switch (Number(status)) {
      case -1:
        return t('txt_status_revoked');
      case 0:
        return t('txt_status_invited');
      case 1:
        return t('txt_status_accepted');
      case 2:
        return t('txt_status_confirmed');
      default:
        return t('txt_dash');
    }
  };

  const roleLabel = (type: number) => {
    switch (normalizeMemberRole(Number(type))) {
      case 0:
        return t('txt_role_owner');
      case 1:
        return t('txt_role_admin');
      case 3:
        return t('txt_role_manager');
      default:
        return t('txt_role_user');
    }
  };

  const collectionAccessSummary = (collection: OrganizationCollectionAccessDetail) => {
    const tags: string[] = [];
    if (collection.manage) tags.push(t('txt_can_manage'));
    if (collection.readOnly) tags.push(t('txt_read_only'));
    if (collection.hidePasswords) tags.push(t('txt_hide_passwords'));
    if (!tags.length) tags.push(t('txt_full_access'));
    return tags;
  };

  const memberCanBeEdited = (member: OrganizationMember, draft: MemberDraft | undefined) => {
    if (!draft || !actorCanManageMembers) return false;
    const currentType = normalizeMemberRole(Number(member.type));
    if (!actorIsOwner && (currentType <= 1 || draft.type <= 1)) return false;
    if (currentType === 0 && ownerCount <= 1 && draft.type !== 0) return false;
    return true;
  };

  const memberSaveHint = (member: OrganizationMember, draft: MemberDraft | undefined) => {
    if (!draft) return '';
    const currentType = normalizeMemberRole(Number(member.type));
    if (!actorCanManageMembers) return t('txt_organization_members_read_only');
    if (!actorIsOwner && (currentType <= 1 || draft.type <= 1)) {
      return t('txt_organization_owner_required_for_admin_roles');
    }
    if (currentType === 0 && ownerCount <= 1 && draft.type !== 0) {
      return t('txt_organization_last_owner_warning');
    }
    return t('txt_organization_member_permission_hint');
  };

  async function refreshCurrentOrganization(): Promise<void> {
    await Promise.all([
      organizationsQuery.refetch(),
      selectedOrganizationId ? collectionDetailsQuery.refetch() : Promise.resolve(),
      selectedOrganizationId ? membersQuery.refetch() : Promise.resolve(),
    ]);
  }

  async function handleCreateOrganization(): Promise<void> {
    const name = organizationForm.name.trim();
    if (!name) {
      props.onNotify?.('error', t('txt_organization_name_required'));
      return;
    }

    setCreatingOrganization(true);
    try {
      const organization = await createOrganization(props.authedFetch, {
        name,
        billingEmail: organizationForm.billingEmail.trim() || null,
        collectionName: organizationForm.collectionName.trim() || null,
      });
      setOrganizationForm({
        name: '',
        billingEmail: props.profile.email || '',
        collectionName: '',
      });
      setSelectedOrganizationId(organization.id);
      await organizationsQuery.refetch();
      props.onNotify?.('success', t('txt_organization_created'));
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_create_organization_failed'));
    } finally {
      setCreatingOrganization(false);
    }
  }

  async function handleCreateCollection(): Promise<void> {
    const name = collectionName.trim();
    if (!selectedOrganizationId) return;
    if (!name) {
      props.onNotify?.('error', t('txt_collection_name_required'));
      return;
    }

    setCreatingCollection(true);
    try {
      await createOrganizationCollection(props.authedFetch, selectedOrganizationId, { name });
      setCollectionName('');
      await Promise.all([collectionDetailsQuery.refetch(), membersQuery.refetch()]);
      props.onNotify?.('success', t('txt_organization_collection_created'));
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_create_collection_failed'));
    } finally {
      setCreatingCollection(false);
    }
  }

  function updateDraft(memberId: string, updater: (draft: MemberDraft) => MemberDraft): void {
    setMemberDrafts((current) => {
      const existing = current[memberId];
      if (!existing) return current;
      return {
        ...current,
        [memberId]: updater(existing),
      };
    });
  }

  function handleMemberRoleChange(memberId: string, nextRole: number): void {
    updateDraft(memberId, (draft) => ({
      ...draft,
      type: nextRole,
      accessAll: nextRole <= 1 ? true : draft.accessAll,
    }));
  }

  function handleMemberAccessAllChange(memberId: string, accessAll: boolean): void {
    updateDraft(memberId, (draft) => ({
      ...draft,
      accessAll: draft.type <= 1 ? true : accessAll,
    }));
  }

  function handleCollectionAssignmentChange(
    memberId: string,
    collectionId: string,
    patch: Partial<MemberCollectionDraft>
  ): void {
    updateDraft(memberId, (draft) => {
      const existing = draft.collections[collectionId] || {
        assigned: false,
        readOnly: false,
        hidePasswords: false,
        manage: false,
      };
      const next = { ...existing, ...patch };
      if (patch.assigned === false) {
        next.readOnly = false;
        next.hidePasswords = false;
        next.manage = false;
      }
      return {
        ...draft,
        collections: {
          ...draft.collections,
          [collectionId]: next,
        },
      };
    });
  }

  async function handleSaveMember(member: OrganizationMember): Promise<void> {
    if (!selectedOrganizationId) return;
    const draft = memberDrafts[member.id];
    if (!draft) return;

    setSavingMemberId(member.id);
    try {
      await updateOrganizationMember(props.authedFetch, selectedOrganizationId, member.id, {
        type: draft.type,
        accessAll: draft.type <= 1 ? true : draft.accessAll,
        collections: draft.type <= 1 || draft.accessAll
          ? []
          : Object.entries(draft.collections)
            .filter(([, value]) => value.assigned)
            .map(([id, value]) => ({
              id,
              readOnly: value.readOnly,
              hidePasswords: value.hidePasswords,
              manage: value.manage,
            })),
      });
      await Promise.all([membersQuery.refetch(), collectionDetailsQuery.refetch()]);
      props.onNotify?.('success', t('txt_organization_member_saved'));
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_save_member_failed'));
    } finally {
      setSavingMemberId('');
    }
  }

  return (
    <div className="stack">
      <section className="card">
        <div className="section-head">
          <div>
            <h3>{t('nav_organizations')}</h3>
            <p className="organization-note">{t('txt_organization_page_intro')}</p>
          </div>
          <button type="button" className="btn btn-secondary" onClick={() => void refreshCurrentOrganization()}>
            <RefreshCw size={14} className="btn-icon" />
            {t('txt_sync')}
          </button>
        </div>
      </section>

      <div className="organizations-layout">
        <aside className="organizations-sidebar">
          <section className="card">
            <div className="section-head">
              <h3>{t('txt_create_organization')}</h3>
              <Building2 size={18} />
            </div>
            <label className="field">
              <span>{t('txt_organization_name')}</span>
              <input
                className="input"
                value={organizationForm.name}
                placeholder={t('txt_organization_name_placeholder')}
                onInput={(event) => setOrganizationForm((current) => ({
                  ...current,
                  name: (event.currentTarget as HTMLInputElement).value,
                }))}
              />
            </label>
            <label className="field">
              <span>{t('txt_billing_email_optional')}</span>
              <input
                className="input"
                type="email"
                value={organizationForm.billingEmail}
                placeholder={props.profile.email}
                onInput={(event) => setOrganizationForm((current) => ({
                  ...current,
                  billingEmail: (event.currentTarget as HTMLInputElement).value,
                }))}
              />
            </label>
            <label className="field">
              <span>{t('txt_default_collection')}</span>
              <input
                className="input"
                value={organizationForm.collectionName}
                placeholder={t('txt_default_collection_placeholder')}
                onInput={(event) => setOrganizationForm((current) => ({
                  ...current,
                  collectionName: (event.currentTarget as HTMLInputElement).value,
                }))}
              />
              <div className="field-help">{t('txt_default_collection_help')}</div>
            </label>
            <button
              type="button"
              className="btn btn-primary"
              disabled={creatingOrganization}
              onClick={() => void handleCreateOrganization()}
            >
              <Plus size={14} className="btn-icon" />
              {creatingOrganization ? t('txt_creating') : t('txt_create_organization')}
            </button>
          </section>

          <section className="card">
            <div className="section-head">
              <h3>{t('txt_your_organizations')}</h3>
              <span className="org-badge accent">{organizations.length}</span>
            </div>
            {organizationsQuery.isLoading ? (
              <div className="organization-empty">{t('txt_loading_nodewarden')}</div>
            ) : organizationsError ? (
              <div className="organization-empty">{organizationsError}</div>
            ) : organizations.length ? (
              <div className="organization-list">
                {organizations.map((organization) => (
                  <button
                    key={organization.id}
                    type="button"
                    className={`organization-list-item ${selectedOrganizationId === organization.id ? 'active' : ''}`}
                    onClick={() => setSelectedOrganizationId(organization.id)}
                  >
                    <strong>{organization.name}</strong>
                    <span>{organization.billingEmail || t('txt_dash')}</span>
                  </button>
                ))}
              </div>
            ) : (
              <div className="organization-empty">{t('txt_no_organizations_yet')}</div>
            )}
          </section>
        </aside>

        <div className="stack">
          <section className="card">
            <div className="section-head">
              <div>
                <h3>{selectedOrganization?.name || t('txt_select_an_organization')}</h3>
                <p className="organization-note">
                  {selectedOrganization
                    ? selectedOrganization.billingEmail || t('txt_organization_overview_help')
                    : t('txt_select_an_organization_help')}
                </p>
              </div>
              {selectedOrganization && <span className="org-badge">{selectedOrganization.id.slice(0, 8)}</span>}
            </div>
            {selectedOrganization ? (
              <div className="organization-stats-grid">
                <div className="organization-stat-card">
                  <span>{t('txt_collections')}</span>
                  <strong>{collections.length}</strong>
                </div>
                <div className="organization-stat-card">
                  <span>{t('txt_members')}</span>
                  <strong>{members.length}</strong>
                </div>
                <div className="organization-stat-card">
                  <span>{t('txt_confirmed')}</span>
                  <strong>{members.filter((entry) => Number(entry.status) === 2).length}</strong>
                </div>
              </div>
            ) : (
              <div className="organization-empty">{t('txt_select_an_organization_help')}</div>
            )}
          </section>

          <section className="card">
            <div className="section-head">
              <div>
                <h3>{t('txt_collections')}</h3>
                <p className="organization-note">{t('txt_organization_collections_help')}</p>
              </div>
              <FolderKanban size={18} />
            </div>
            <div className="organizations-inline-form">
              <input
                className="input"
                value={collectionName}
                placeholder={t('txt_collection_name_placeholder')}
                disabled={!selectedOrganization || !actorCanManageMembers || creatingCollection}
                onInput={(event) => setCollectionName((event.currentTarget as HTMLInputElement).value)}
              />
              <button
                type="button"
                className="btn btn-primary"
                disabled={!selectedOrganization || !actorCanManageMembers || creatingCollection}
                onClick={() => void handleCreateCollection()}
              >
                <Plus size={14} className="btn-icon" />
                {creatingCollection ? t('txt_creating') : t('txt_create_collection')}
              </button>
            </div>
            {!actorCanManageMembers && selectedOrganization && (
              <p className="organization-note">{t('txt_organization_collections_read_only')}</p>
            )}
            {selectedOrganization && collectionDetailsQuery.isLoading ? (
              <div className="organization-empty">{t('txt_loading_nodewarden')}</div>
            ) : collectionsError ? (
              <div className="organization-empty">{collectionsError}</div>
            ) : collections.length ? (
              <div className="organization-collection-grid">
                {collections.map((collection) => (
                  <article key={collection.id} className="organization-collection-card">
                    <div className="organization-collection-head">
                      <strong>{collection.name}</strong>
                      <span className="org-badge">{(collection.users || []).length} {t('txt_members')}</span>
                    </div>
                    <div className="organization-badge-row">
                      {collectionAccessSummary(collection).map((tag) => (
                        <span key={`${collection.id}-${tag}`} className="org-badge subtle">{tag}</span>
                      ))}
                    </div>
                  </article>
                ))}
              </div>
            ) : (
              <div className="organization-empty">
                {selectedOrganization ? t('txt_no_collections_yet') : t('txt_select_an_organization_help')}
              </div>
            )}
          </section>

          <section className="card">
            <div className="section-head">
              <div>
                <h3>{t('txt_members')}</h3>
                <p className="organization-note">{t('txt_organization_members_help')}</p>
              </div>
              <Users size={18} />
            </div>
            <p className="organization-note">{t('txt_organization_member_invite_note')}</p>
            {selectedOrganization && membersQuery.isLoading ? (
              <div className="organization-empty">{t('txt_loading_nodewarden')}</div>
            ) : membersError ? (
              <div className="organization-empty">{membersError}</div>
            ) : members.length ? (
              <div className="organization-member-grid">
                {members.map((member) => {
                  const draft = memberDrafts[member.id];
                  const canEdit = memberCanBeEdited(member, draft);
                  const saveHint = memberSaveHint(member, draft);
                  const showCollectionPermissions = !!draft && draft.type > 1 && !draft.accessAll && !!collections.length;
                  return (
                    <article key={member.id} className="organization-member-card">
                      <div className="organization-member-head">
                        <div>
                          <strong>{member.name || member.email}</strong>
                          <div className="organization-note">{member.email}</div>
                        </div>
                        <div className="organization-badge-row">
                          <span className="org-badge">{roleLabel(member.type)}</span>
                          <span className={`org-badge ${Number(member.status) === 2 ? 'success' : 'warning'}`}>
                            {statusLabel(member.status)}
                          </span>
                          {member.userId === props.profile.id && <span className="org-badge accent">{t('txt_you')}</span>}
                        </div>
                      </div>

                      <div className="field-grid organization-member-form">
                        <label className="field">
                          <span>{t('txt_role')}</span>
                          <select
                            className="input"
                            value={String(draft?.type ?? normalizeMemberRole(member.type))}
                            disabled={!actorCanManageMembers || savingMemberId === member.id}
                            onInput={(event) => handleMemberRoleChange(member.id, Number((event.currentTarget as HTMLSelectElement).value))}
                          >
                            {roleOptions.map((option) => (
                              <option
                                key={`${member.id}-role-${option.value}`}
                                value={option.value}
                                disabled={!actorIsOwner && option.value <= 1}
                              >
                                {option.label}
                              </option>
                            ))}
                          </select>
                        </label>

                        <label className="field">
                          <span>{t('txt_access_scope')}</span>
                          <div className="organization-check">
                            <input
                              type="checkbox"
                              checked={!!draft?.accessAll}
                              disabled={!actorCanManageMembers || (draft?.type ?? 2) <= 1 || savingMemberId === member.id}
                              onInput={(event) => handleMemberAccessAllChange(member.id, (event.currentTarget as HTMLInputElement).checked)}
                            />
                            <span>{t('txt_access_all_collections')}</span>
                          </div>
                          <div className="field-help">
                            {draft?.accessAll || (draft?.type ?? 2) <= 1
                              ? t('txt_full_collection_access')
                              : t('txt_selected_collections_count', { count: countAssignedCollections(draft) })}
                          </div>
                        </label>
                      </div>

                      {showCollectionPermissions && (
                        <div className="organization-permission-grid">
                          {collections.map((collection) => {
                            const access = draft?.collections[collection.id] || {
                              assigned: false,
                              readOnly: false,
                              hidePasswords: false,
                              manage: false,
                            };
                            return (
                              <div key={`${member.id}-${collection.id}`} className={`organization-permission-card ${access.assigned ? 'active' : ''}`}>
                                <label className="organization-check organization-check-primary">
                                  <input
                                    type="checkbox"
                                    checked={access.assigned}
                                    disabled={!actorCanManageMembers || savingMemberId === member.id}
                                    onInput={(event) => handleCollectionAssignmentChange(member.id, collection.id, {
                                      assigned: (event.currentTarget as HTMLInputElement).checked,
                                    })}
                                  />
                                  <span>{collection.name}</span>
                                </label>
                                <div className="organization-permission-flags">
                                  <label className="organization-check">
                                    <input
                                      type="checkbox"
                                      checked={access.readOnly}
                                      disabled={!actorCanManageMembers || !access.assigned || savingMemberId === member.id}
                                      onInput={(event) => handleCollectionAssignmentChange(member.id, collection.id, {
                                        readOnly: (event.currentTarget as HTMLInputElement).checked,
                                      })}
                                    />
                                    <span>{t('txt_read_only')}</span>
                                  </label>
                                  <label className="organization-check">
                                    <input
                                      type="checkbox"
                                      checked={access.hidePasswords}
                                      disabled={!actorCanManageMembers || !access.assigned || savingMemberId === member.id}
                                      onInput={(event) => handleCollectionAssignmentChange(member.id, collection.id, {
                                        hidePasswords: (event.currentTarget as HTMLInputElement).checked,
                                      })}
                                    />
                                    <span>{t('txt_hide_passwords')}</span>
                                  </label>
                                  <label className="organization-check">
                                    <input
                                      type="checkbox"
                                      checked={access.manage}
                                      disabled={!actorCanManageMembers || !access.assigned || savingMemberId === member.id}
                                      onInput={(event) => handleCollectionAssignmentChange(member.id, collection.id, {
                                        manage: (event.currentTarget as HTMLInputElement).checked,
                                      })}
                                    />
                                    <span>{t('txt_can_manage')}</span>
                                  </label>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}

                      <div className="organization-member-actions">
                        <p className="organization-note">{saveHint}</p>
                        <button
                          type="button"
                          className="btn btn-secondary"
                          disabled={!canEdit || savingMemberId === member.id}
                          onClick={() => void handleSaveMember(member)}
                        >
                          <Save size={14} className="btn-icon" />
                          {savingMemberId === member.id ? t('txt_saving') : t('txt_save_permissions')}
                        </button>
                      </div>
                    </article>
                  );
                })}
              </div>
            ) : (
              <div className="organization-empty">
                {selectedOrganization ? t('txt_no_members_yet') : t('txt_select_an_organization_help')}
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
