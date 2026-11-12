import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  apiIssueToken, apiMe, apiServices, apiTokens, apiRevokeToken, getToken, ServiceSummary,
} from '../api';
import { sharedStyles } from '../styles';

const OPS: { id: string; label: string }[] = [
  { id: 'read', label: 'read (status, files, configs)' },
  { id: 'logs', label: 'container logs' },
  { id: 'files', label: 'write files' },
  { id: 'compose', label: 'compose files & actions' },
  { id: 'meta', label: 'edit service metadata' },
  { id: 'monitoring', label: 'monitoring & notifiers' },
  { id: 'backup', label: 'backups' },
  { id: 'git', label: 'git operations' },
  { id: 'units', label: 'systemd units' },
  { id: 'services', label: 'create/delete services' },
  { id: 'exec', label: 'run commands & exec' },
  { id: 'registry', label: 'image registry (docker load)' },
];

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

@customElement('ddm-token')
export class DdmToken extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .checks { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 0.3em; }
      .checks label { display: flex; gap: 0.4em; align-items: center; }
      .token-out { width: 100%; font-family: ui-monospace, monospace; font-size: 0.8em; }
    `,
  ];

  @state() private me: any = null;
  @state() private services: ServiceSummary[] = [];
  @state() private ttlValue = 60;
  @state() private ttlUnit: 'minutes' | 'hours' | 'days' | 'months' | 'years' = 'minutes';
  @state() private scopeServices = false;
  @state() private scopeActions = false;
  @state() private scopeOps = false;
  @state() private tokenName = '';
  @state() private selServices = new Set<string>();
  @state() private selActions = new Set<string>();
  @state() private selOps = new Set<string>();
  @state() private issued: { token: string; expires_at: number } | null = null;
  @state() private tokens: any[] = [];
  @state() private msg = '';

  connectedCallback() {
    super.connectedCallback();
    apiMe().then((me: any) => (this.me = me)).catch(() => {});
    apiServices().then((s) => (this.services = s)).catch(() => {});
    this.loadTokens();
  }

  /** jti of the current login session, decoded client-side — used only
   *  to label "(this session)"; revocation stays server-enforced. */
  private get myJti(): string {
    try {
      const t = getToken();
      const payload = JSON.parse(atob(t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
      return payload.jti ?? '';
    } catch {
      return '';
    }
  }

  private async loadTokens() {
    try {
      this.tokens = await apiTokens();
    } catch {
      this.tokens = [];
    }
  }

  private async revoke(jti: string) {
    try {
      await apiRevokeToken(jti);
      this.msg = 'revoked';
      this.loadTokens();
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  /** Capabilities this user actually has — a scope can only narrow. */
  private capabilities(): { id: string; label: string }[] {
    const caps: { id: string; label: string }[] = [];
    for (const r of this.me?.roles ?? []) caps.push({ id: r, label: `role: ${r}` });
    for (const [k, label] of Object.entries(FEATURE_LABELS)) {
      if (this.me?.features?.[k]) caps.push({ id: k, label });
    }
    if (this.me?.compose_policy === 'unrestricted') {
      caps.push({ id: 'unrestricted', label: 'unrestricted compose policy' });
    }
    return caps;
  }

  private toggleSet(set: Set<string>, key: string, on: boolean): Set<string> {
    const s = new Set(set);
    if (on) s.add(key); else s.delete(key);
    return s;
  }

  /** Convert the value+unit selection to minutes, capped at 10 years. */
  private ttlMinutes(): number {
    const per: Record<typeof this.ttlUnit, number> = {
      minutes: 1, hours: 60, days: 1440, months: 43200, years: 525600,
    };
    return Math.min(Math.max(1, this.ttlValue) * per[this.ttlUnit], 5_256_000);
  }

  private async generate() {
    this.msg = '';
    this.issued = null;
    const body: {
      ttl_minutes: number;
      services?: string[];
      actions?: string[];
      ops?: string[];
      name?: string;
    } = { ttl_minutes: this.ttlMinutes() };
    const name = this.tokenName.trim();
    if (name) body.name = name;
    if (this.scopeServices) body.services = [...this.selServices];
    if (this.scopeActions) body.actions = [...this.selActions];
    if (this.scopeOps) body.ops = [...this.selOps];
    try {
      this.issued = await apiIssueToken(body);
      this.loadTokens();
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  /** Condense a User-Agent string to something scannable. */
  private shortUa(ua: string): string {
    const known: [RegExp, string][] = [
      [/Firefox\/([\d.]+)/, 'Firefox $1'],
      [/Edg\/([\d.]+)/, 'Edge $1'],
      [/Chrome\/([\d.]+)/, 'Chrome $1'],
      [/Version\/[\d.]+ Safari/, 'Safari'],
      [/curl\/([\d.]+)/, 'curl $1'],
      [/python-requests\/([\d.]+)/, 'python $1'],
    ];
    for (const [re, name] of known) {
      const m = ua.match(re);
      if (m) return name;
    }
    return ua.slice(0, 32);
  }

  private copy(text: string) {
    navigator.clipboard?.writeText(text).then(() => (this.msg = 'copied'));
  }

  private clientConfig(token: string): string {
    const url = `${location.origin}/mcp`;
    return JSON.stringify(
      {
        mcpServers: {
          ddm: {
            url,
            headers: { Authorization: `Bearer ${token}` },
          },
        },
      },
      null,
      2,
    );
  }

  private restExample(token: string): string {
    return `curl -H "Authorization: Bearer ${token}" \\\n  ${location.origin}/api/services`;
  }

  render() {
    return html`
      <h2>Access tokens</h2>
      <p class="muted">
        Issue a time-limited bearer token for agents — it works on the
        REST API (<code>/api/*</code>) and the MCP endpoint
        (<code>${location.origin}/mcp</code>). The token acts as
        <b>${this.me?.name ?? '…'}</b>; scope selections below can only narrow
        your permissions.
      </p>
      ${this.msg ? html`<p class="muted">${this.msg}</p>` : ''}
      <div class="card">
        <div class="row">
          <label>name <input type="text" maxlength="80" style="width:14em" placeholder="optional label"
            .value=${this.tokenName}
            @input=${(e: Event) => (this.tokenName = (e.target as HTMLInputElement).value)}></label>
          <label>lifetime
            <input type="number" min="1" style="width:6em" .value=${String(this.ttlValue)}
              @input=${(e: Event) => (this.ttlValue = Math.max(1, +(e.target as HTMLInputElement).value || 60))}>
            <select .value=${this.ttlUnit}
              @change=${(e: Event) => (this.ttlUnit = (e.target as HTMLSelectElement).value as typeof this.ttlUnit)}>
              <option value="minutes">minutes</option>
              <option value="hours">hours</option>
              <option value="days">days</option>
              <option value="months">months</option>
              <option value="years">years</option>
            </select>
          </label>
          ${([[1, 'hours'], [12, 'hours'], [1, 'days'], [7, 'days'], [30, 'days'], [90, 'days'], [1, 'years'], [10, 'years']] as const).map(
            ([v, u]) => html`<button class="small secondary"
              @click=${() => { this.ttlValue = v; this.ttlUnit = u; }}>
              ${v}${u === 'hours' ? 'h' : u === 'days' ? 'd' : u === 'years' ? 'y' : 'mo'}</button>`,
          )}
        </div>

        <fieldset>
          <legend>
            <label><input type="checkbox" .checked=${this.scopeServices}
              @change=${(e: Event) => (this.scopeServices = (e.target as HTMLInputElement).checked)}>
              limit to services</label>
          </legend>
          ${this.scopeServices
            ? html`<div class="checks">
                ${this.services.map(
                  (s) => html`<label><input type="checkbox"
                      .checked=${this.selServices.has(s.name)}
                      @change=${(e: Event) =>
                        (this.selServices = this.toggleSet(
                          this.selServices, s.name, (e.target as HTMLInputElement).checked))}>
                    ${s.name}</label>`,
                )}
              </div>`
            : html`<p class="muted">token can access all services you can access</p>`}
        </fieldset>

        <fieldset>
          <legend>
            <label><input type="checkbox" .checked=${this.scopeActions}
              @change=${(e: Event) => (this.scopeActions = (e.target as HTMLInputElement).checked)}>
              limit to capabilities</label>
          </legend>
          ${this.scopeActions
            ? html`<div class="checks">
                ${this.capabilities().map(
                  (c) => html`<label><input type="checkbox"
                      .checked=${this.selActions.has(c.id)}
                      @change=${(e: Event) =>
                        (this.selActions = this.toggleSet(
                          this.selActions, c.id, (e.target as HTMLInputElement).checked))}>
                    ${c.label}</label>`,
                )}
              </div>
              <p class="muted">read access is always included; uncheck everything for a read-only token</p>`
            : html`<p class="muted">token has your full capabilities</p>`}
        </fieldset>

        <fieldset>
          <legend>
            <label><input type="checkbox" .checked=${this.scopeOps}
              @change=${(e: Event) => (this.scopeOps = (e.target as HTMLInputElement).checked)}>
              limit to operations</label>
          </legend>
          ${this.scopeOps
            ? html`<div class="checks">
                ${OPS.map(
                  (o) => html`<label><input type="checkbox"
                      .checked=${this.selOps.has(o.id)}
                      @change=${(e: Event) =>
                        (this.selOps = this.toggleSet(
                          this.selOps, o.id, (e.target as HTMLInputElement).checked))}>
                    ${o.label}</label>`,
                )}
              </div>
              <p class="muted">unchecked categories are denied entirely — e.g. only "read" gives a view-only token</p>`
            : html`<p class="muted">token may perform all operations your capabilities allow</p>`}
        </fieldset>

        <button @click=${this.generate}>generate token</button>
      </div>

      ${this.issued
        ? html`<div class="card">
            <h3>token <span class="muted">expires ${new Date(this.issued.expires_at * 1000).toLocaleString()}</span></h3>
            <textarea class="token-out" readonly rows="3">${this.issued.token}</textarea>
            <div class="toolbar">
              <button class="small" @click=${() => this.copy(this.issued!.token)}>copy token</button>
              <button class="small secondary" @click=${() => this.copy(this.clientConfig(this.issued!.token))}>
                copy MCP client config</button>
              <button class="small secondary" @click=${() => this.copy(this.restExample(this.issued!.token))}>
                copy REST example</button>
            </div>
            <p class="muted">REST API usage:</p>
            <pre>${this.restExample(this.issued.token)}</pre>
            <p class="muted">MCP client configuration:</p>
            <pre>${this.clientConfig(this.issued.token)}</pre>
          </div>`
        : ''}

      <div class="card">
        <h3>sessions &amp; tokens</h3>
        ${this.tokens.length
          ? html`<table><thead><tr>
              <th></th><th>kind</th><th>name</th><th>user</th><th>client</th><th>scope</th><th>issued</th><th>expires</th><th>state</th>
            </tr></thead>
            <tbody>${[...this.tokens]
              .sort((a, b) => (a.kind === 'session' ? 0 : 1) - (b.kind === 'session' ? 0 : 1))
              .map(
              (t) => html`<tr>
                <td>${!t.revoked && t.exp * 1000 > Date.now()
                  ? html`<button class="small danger" @click=${() => this.revoke(t.jti)}>${t.kind === 'session' ? 'sign out' : 'revoke'}</button>`
                  : ''}</td>
                <td><span class="badge ${t.kind === 'session' ? 'muted' : ''}">${t.kind || 'token'}</span></td>
                <td>${t.name ?? html`<span class="muted">—</span>`}</td>
                <td>${t.user}${t.jti === this.myJti ? html` <span class="muted">(this session)</span>` : ''}</td>
                <td class="muted" style="max-width:14em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
                  title=${t.ua ?? ''}>${t.ua ? this.shortUa(t.ua) : '—'}</td>
                <td class="muted">${
                  [
                    t.services ? `svc: ${t.services.join(',')}` : '',
                    t.actions ? `act: ${t.actions.join(',')}` : '',
                    t.ops ? `ops: ${t.ops.join(',')}` : '',
                  ].filter(Boolean).join(' · ') || (t.kind === 'session' ? 'login' : 'full')
                }</td>
                <td class="muted">${new Date(t.iat * 1000).toLocaleString()}</td>
                <td class="muted">${new Date(t.exp * 1000).toLocaleString()}</td>
                <td>${t.revoked
                  ? html`<span class="badge err">revoked</span>`
                  : t.exp * 1000 < Date.now()
                    ? html`<span class="badge">expired</span>`
                    : html`<span class="badge ok">active</span>`}</td>
              </tr>`,
            )}</tbody></table>`
          : html`<p class="muted">nothing yet — login sessions and tokens you generate above appear here</p>`}
        <p class="muted">admins see all users' sessions and tokens; other users see only their own. Revoking a session signs that browser out on its next request.</p>
      </div>
    `;
  }
}
