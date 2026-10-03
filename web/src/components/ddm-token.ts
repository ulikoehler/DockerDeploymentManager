import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  apiIssueToken, apiMe, apiServices, ServiceSummary,
} from '../api';
import { sharedStyles } from '../styles';

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
  @state() private ttl = 60;
  @state() private scopeServices = false;
  @state() private scopeActions = false;
  @state() private selServices = new Set<string>();
  @state() private selActions = new Set<string>();
  @state() private issued: { token: string; expires_at: number } | null = null;
  @state() private msg = '';

  connectedCallback() {
    super.connectedCallback();
    apiMe().then((me: any) => (this.me = me)).catch(() => {});
    apiServices().then((s) => (this.services = s)).catch(() => {});
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

  private async generate() {
    this.msg = '';
    this.issued = null;
    const body: { ttl_minutes: number; services?: string[]; actions?: string[] } = {
      ttl_minutes: this.ttl,
    };
    if (this.scopeServices) body.services = [...this.selServices];
    if (this.scopeActions) body.actions = [...this.selActions];
    try {
      this.issued = await apiIssueToken(body);
    } catch (e: any) {
      this.msg = e.message;
    }
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

  render() {
    return html`
      <h2>MCP access token</h2>
      <p class="muted">
        Issue a time-limited bearer token for MCP clients (endpoint
        <code>${location.origin}/mcp</code>). The token acts as
        <b>${this.me?.name ?? '…'}</b>; scope selections below can only narrow
        your permissions.
      </p>
      ${this.msg ? html`<p class="muted">${this.msg}</p>` : ''}
      <div class="card">
        <div class="row">
          <label>lifetime
            <input type="number" min="1" style="width:7em" .value=${String(this.ttl)}
              @input=${(e: Event) => (this.ttl = Math.max(1, +(e.target as HTMLInputElement).value || 60))}>
            minutes
          </label>
          ${[60, 480, 1440, 10080].map(
            (m) => html`<button class="small secondary" @click=${() => (this.ttl = m)}>
              ${m < 1440 ? `${m / 60}h` : `${m / 1440}d`}</button>`,
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

        <button @click=${this.generate}>generate token</button>
      </div>

      ${this.issued
        ? html`<div class="card">
            <h3>token <span class="muted">expires ${new Date(this.issued.expires_at * 1000).toLocaleString()}</span></h3>
            <textarea class="token-out" readonly rows="3">${this.issued.token}</textarea>
            <div class="toolbar">
              <button class="small" @click=${() => this.copy(this.issued!.token)}>copy token</button>
              <button class="small secondary" @click=${() => this.copy(this.clientConfig(this.issued!.token))}>
                copy client config</button>
            </div>
            <p class="muted">MCP client configuration:</p>
            <pre>${this.clientConfig(this.issued.token)}</pre>
          </div>`
        : ''}
    `;
  }
}
