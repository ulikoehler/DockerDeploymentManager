import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  apiUsers, apiCreateUser, apiDeleteUser, apiSetPassword, apiSetAccess,
  apiUpdateUser, apiUserEffective, apiLogoutAll, apiMe, UserView,
} from '../api';
import { sharedStyles } from '../styles';
import { ddmConfirm, ddmPrompt } from '../dialog';

const FEATURE_LABELS: Record<string, string> = {
  create_services: 'create services',
  edit_compose: 'edit compose files',
  edit_units: 'edit systemd units',
  run_commands: 'run commands',
  manage_backup: 'manage backups',
  manage_monitoring: 'manage monitoring',
  edit_files: 'edit files & git',
  exec_containers: 'exec in containers',
  mount_files: 'mount files (WebDAV)',
  push_images: 'push docker images (registry)',
};

@customElement('ddm-users')
export class DdmUsers extends LitElement {
  static styles = [
    sharedStyles,
    css`td input, td select { width: 100%; }`,
  ];

  @state() private users: UserView[] = [];
  @state() private selected = '';
  @state() private effective: any = null;
  @state() private msg = '';

  connectedCallback() {
    super.connectedCallback();
    this.refresh();
  }

  private async refresh() {
    this.users = await apiUsers().catch(() => []);
    this.loadEffective();
  }

  private async loadEffective() {
    this.effective = null;
    if (!this.selected) return;
    this.effective = await apiUserEffective(this.selected).catch(() => null);
  }

  private sel() {
    return this.users.find((u) => u.name === this.selected);
  }

  private async logoutAll() {
    if (!(await ddmConfirm('invalidate ALL sessions and minted tokens? everyone must log in again', { danger: true, title: 'Logout everywhere' }))) return;
    try {
      await apiLogoutAll();
      this.msg = 'all sessions invalidated';
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async addUser(e: Event) {
    e.preventDefault();
    const f = e.target as HTMLFormElement;
    const name = (f.elements.namedItem('name') as HTMLInputElement).value;
    const password = (f.elements.namedItem('password') as HTMLInputElement).value;
    const role = (f.elements.namedItem('role') as HTMLSelectElement).value;
    try {
      await apiCreateUser({ name, password, roles: role ? [role] : [] });
      this.msg = `user ${name} created`;
      f.reset();
      this.refresh();
    } catch (err: any) {
      this.msg = err.message;
    }
  }

  private async removeUser(name: string) {
    if (!(await ddmConfirm(`delete user ${name}?`, { danger: true }))) return;
    await apiDeleteUser(name).catch((e) => (this.msg = e.message));
    if (this.selected === name) this.selected = '';
    this.refresh();
  }

  private async changePw(name: string) {
    // non-admin self-service changes require the current password —
    // ask for it up front instead of failing after the fact.
    const me = await apiMe().catch(() => null);
    const isSelf = me?.name === name;
    const needsCurrent = isSelf && !(me?.roles ?? []).includes('admin');
    const current = needsCurrent
      ? await ddmPrompt(`current password for ${name}`, '', { title: 'Confirm identity' })
      : null;
    if (needsCurrent && (current === null || !current)) return;
    const password = await ddmPrompt(`new password for ${name} (min 8 chars)`, '', { title: 'Set password' });
    if (password === null || !password) return;
    try {
      await apiSetPassword(name, password, current ?? undefined);
      this.msg = 'password updated';
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async saveRoles(u: UserView, roles: string) {
    await apiUpdateUser(u.name, { roles: roles.split(',').map((s) => s.trim()).filter(Boolean) })
      .then(() => (this.msg = 'roles updated'))
      .catch((e) => (this.msg = e.message));
    this.refresh();
  }

  private async saveAccess(u: UserView, text: string) {
    const rules = text
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const m = l.match(/^(allow|deny)\s+(\w+):(.+)$/);
        return m ? { type: m[2], pattern: m[3], effect: m[1] } : null;
      });
    if (rules.some((r) => !r)) {
      this.msg = 'syntax: "allow glob:web-*" per line';
      return;
    }
    try {
      await apiSetAccess(u.name, rules);
      this.msg = 'access rules updated';
    } catch (e: any) {
      this.msg = e.message;
    }
    this.refresh();
  }

  private async savePolicy(u: UserView, policy: string) {
    await apiUpdateUser(u.name, { compose_policy: policy === 'default' ? null : policy })
      .then(() => (this.msg = 'policy updated'))
      .catch((e) => (this.msg = e.message));
    this.refresh();
  }

  private async toggleFeature(u: UserView, key: string) {
    const features = { ...u.features, [key]: !u.features[key] };
    await apiUpdateUser(u.name, { features }).catch((e) => (this.msg = e.message));
    this.refresh();
  }

  private accessText(u: UserView): string {
    return u.access.map((r) => `${r.effect} ${r.type}:${r.pattern}`).join('\n');
  }

  private select(name: string) {
    this.selected = name;
    this.loadEffective();
  }

  render() {
    const u = this.sel();
    const effSvcs = this.effective?.services ? Object.entries(this.effective.services) : [];
    return html`
      <h2>Users</h2>
      ${this.msg ? html`<p class="muted">${this.msg}</p>` : ''}
      <details class="card" style="margin-bottom:1em">
        <summary><b>How permissions work</b> <span class="muted">— click to expand</span></summary>
        <ul class="muted" style="margin:.5em 0">
          <li><b>roles</b> (viewer/operator/admin) — admin bypasses everything; operator adds service actions</li>
          <li><b>features</b> — per-capability switches (compose, files, backups, exec…); admin ignores them</li>
          <li><b>access rules</b> — per-service allow/deny (exact/glob/regex, first match wins); unmatched services fall back to the server's <code>default_access</code></li>
          <li><b>compose policy</b> — which compose features this user may use (strict/relaxed/unrestricted); "default" inherits the server policy</li>
          <li><b>restrictions</b> — hard denies (privileged, host namespaces, docker socket, devices…) applied on top of everything except admin</li>
          <li>scoped <a href="#/token">tokens</a> can only ever narrow these — never widen</li>
        </ul>
      </details>
      <div class="row" style="align-items:flex-start">
        <div class="card" style="min-width:320px">
          <div class="toolbar" style="justify-content:flex-end">
            <button class="small danger" @click=${this.logoutAll}>logout all sessions</button>
          </div>
          <table>
            <thead><tr><th>name</th><th>roles</th><th></th></tr></thead>
            <tbody>
              ${this.users.map(
                (x) => html`<tr>
                  <td><a href="#" @click=${(e: Event) => { e.preventDefault(); this.select(x.name); }}
                    style="color:var(--link)">${x.name}</a></td>
                  <td class="muted">${x.roles.join(', ')}</td>
                  <td>
                    <button class="small secondary" @click=${() => this.changePw(x.name)}>pw</button>
                    <button class="small danger" @click=${() => this.removeUser(x.name)}>×</button>
                  </td>
                </tr>`,
              )}
            </tbody>
          </table>
          <h3>Add user</h3>
          <form @submit=${this.addUser}>
            <div class="row">
              <input name="name" placeholder="name" required>
              <input name="password" type="password" placeholder="password" required>
              <select name="role">
                <option value="viewer">viewer</option>
                <option value="operator">operator</option>
                <option value="admin">admin</option>
              </select>
              <button>add</button>
            </div>
          </form>
        </div>
        ${u
          ? html`<div class="card" style="flex:1">
              <h3>${u.name}</h3>
              <div class="row"><span class="muted">roles:</span>
                <input .value=${u.roles.join(',')} id="roles-in">
                <button class="small" @click=${() =>
                  this.saveRoles(u, (this.shadowRoot!.getElementById('roles-in') as HTMLInputElement).value)
                }>save</button>
              </div>
              <div class="row"><span class="muted">compose policy:</span>
                <select id="policy-sel">
                  <option value="default">default</option>
                  ${['strict', 'relaxed', 'unrestricted'].map(
                    (p) => html`<option value=${p} ?selected=${u.compose_policy === p}>${p}</option>`,
                  )}
                </select>
                <button class="small" @click=${() =>
                  this.savePolicy(u, (this.shadowRoot!.getElementById('policy-sel') as HTMLSelectElement).value)
                }>save</button>
              </div>
              <h4>Features <span class="muted">(ignored for admin)</span></h4>
              <div class="checks" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:.2em">
                ${Object.keys(FEATURE_LABELS).map(
                  (k) => html`<label style="margin-right:1em">
                    <input type="checkbox" .checked=${!!u.features[k]}
                      @change=${() => this.toggleFeature(u, k)}> ${FEATURE_LABELS[k]}
                  </label>`,
                )}
              </div>
              ${u.restrictions && Object.values(u.restrictions).some(Boolean)
                ? html`<p class="muted">restrictions: ${Object.entries(u.restrictions)
                    .filter(([, v]) => v)
                    .map(([k]) => k.replace('deny_', ''))
                    .join(', ')} <span class="badge warn">hard denies</span></p>`
                : ''}
              ${this.effective
                ? html`<h4>Effective access <span class="muted">(as enforced — default_access: ${this.effective.default_access}, compose policy: ${this.effective.compose_policy})</span></h4>
                    <div class="checks">
                      ${effSvcs.map(
                        ([name, ok]) => html`<span class="badge ${ok ? 'ok' : 'err'}"
                          title="${name}: ${ok ? 'allowed' : 'denied'}">${name}</span>`,
                      )}
                      ${!effSvcs.length ? html`<span class="muted">no services</span>` : ''}
                    </div>`
                : html`<p class="muted">loading effective access…</p>`}
              <h4>Access rules <span class="muted">(first match wins; deny first)</span></h4>
              <textarea style="width:100%;min-height:8em" id="access-ta"
                placeholder="deny exact:core&#10;allow glob:web-*&#10;allow regex:^stg-[0-9]+$">${this.accessText(u)}</textarea>
              <div class="toolbar">
                <button class="small" @click=${() =>
                  this.saveAccess(u, (this.shadowRoot!.getElementById('access-ta') as HTMLTextAreaElement).value)
                }>save rules</button>
              </div>
            </div>`
          : html`<p class="muted">select a user</p>`}
      </div>
    `;
  }
}
