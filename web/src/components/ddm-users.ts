import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  apiUsers, apiCreateUser, apiDeleteUser, apiSetPassword, apiSetAccess,
  apiUpdateUser, UserView,
} from '../api';
import { sharedStyles } from '../styles';

@customElement('ddm-users')
export class DdmUsers extends LitElement {
  static styles = [
    sharedStyles,
    css`td input, td select { width: 100%; }`,
  ];

  @state() private users: UserView[] = [];
  @state() private selected = '';
  @state() private msg = '';

  connectedCallback() {
    super.connectedCallback();
    this.refresh();
  }

  private async refresh() {
    this.users = await apiUsers().catch(() => []);
  }

  private sel() {
    return this.users.find((u) => u.name === this.selected);
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
    if (!confirm(`delete user ${name}?`)) return;
    await apiDeleteUser(name).catch((e) => (this.msg = e.message));
    if (this.selected === name) this.selected = '';
    this.refresh();
  }

  private async changePw(name: string) {
    const password = prompt(`new password for ${name} (min 8 chars)`);
    if (!password) return;
    try {
      await apiSetPassword(name, password);
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

  render() {
    const u = this.sel();
    return html`
      <h2>Users</h2>
      ${this.msg ? html`<p class="muted">${this.msg}</p>` : ''}
      <div class="row" style="align-items:flex-start">
        <div class="card" style="min-width:320px">
          <table>
            <thead><tr><th>name</th><th>roles</th><th></th></tr></thead>
            <tbody>
              ${this.users.map(
                (x) => html`<tr>
                  <td><a href="#" @click=${(e: Event) => { e.preventDefault(); this.selected = x.name; }}
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
              <h4>Features</h4>
              ${['create_services', 'edit_compose', 'edit_units', 'run_commands', 'manage_backup', 'manage_monitoring', 'exec_containers'].map(
                (k) => html`<label style="margin-right:1em">
                  <input type="checkbox" .checked=${!!u.features[k]}
                    @change=${() => this.toggleFeature(u, k)}> ${k}
                </label>`,
              )}
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
