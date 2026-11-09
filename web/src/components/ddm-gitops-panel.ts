import { LitElement, html } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
  apiGitopsStatus, apiGitopsSync, apiGitopsPush,
  apiGitopsConfig, apiPutGitopsConfig,
} from '../api';
import { sharedStyles } from '../styles';

interface GitsyncStatus {
  enabled: boolean;
  url: string;
  branch: string;
  targets: string[];
  last_sync_at?: number;
  last_sync_ok?: boolean;
  last_error?: string;
  synced_rev?: string;
  pending_push: number;
  last_push_at?: number;
  push_changes: boolean;
}

/** GitOps status, manual sync/push and configuration (admin). */
@customElement('ddm-gitops-panel')
export class DdmGitopsPanel extends LitElement {
  static styles = sharedStyles;
  @property({ type: Boolean }) admin = false;
  @state() private status?: GitsyncStatus;
  @state() private cfg: any = null;
  @state() private editing = false;
  @state() private targetsJson = '[]';
  @state() private error = '';
  @state() private msg = '';
  @state() private busy = false;

  connectedCallback() {
    super.connectedCallback();
    void this.load();
    this.timer = setInterval(() => void this.load(), 15000);
  }
  disconnectedCallback() {
    super.disconnectedCallback();
    clearInterval(this.timer);
  }
  private timer?: number;

  private async load() {
    try {
      this.status = await apiGitopsStatus();
      if (this.admin && this.cfg === null && !this.editing) {
        this.cfg = await apiGitopsConfig();
      }
      this.error = '';
    } catch (e) {
      this.error = String(e);
    }
  }

  private startEdit() {
    this.cfg = { ...(this.cfg ?? {}) };
    this.targetsJson = JSON.stringify(this.cfg.targets ?? [], null, 2);
    this.editing = true;
    this.msg = '';
  }

  private field(key: string, label: string, type = 'text', ph = '') {
    const c = this.cfg ?? {};
    const val = c[key] ?? '';
    if (type === 'checkbox') {
      return html`<label><input type="checkbox" .checked=${!!val}
        @change=${(e: any) => (this.cfg = { ...this.cfg, [key]: e.target.checked })}> ${label}</label>`;
    }
    if (type === 'number') {
      return html`<label class="muted">${label}
        <input type="number" style="width:8em" .value=${String(val)}
          @input=${(e: any) => (this.cfg = { ...this.cfg, [key]: Number(e.target.value) || 0 })}></label>`;
    }
    return html`<label class="muted" style="flex:1">${label}
      <input style="width:100%" placeholder=${ph} .value=${String(val)}
        @input=${(e: any) => (this.cfg = { ...this.cfg, [key]: e.target.value })}></label>`;
  }

  private async saveCfg() {
    try {
      const targets = JSON.parse(this.targetsJson || '[]');
      const body = { ...this.cfg, targets };
      await apiPutGitopsConfig(body);
      this.editing = false;
      this.msg = 'gitops config saved — sync runs on the configured interval or webhook';
      await this.load();
      this.cfg = await apiGitopsConfig();
    } catch (e: any) {
      this.msg = `error: ${e.message}`;
    }
  }

  private async act(fn: () => Promise<unknown>) {
    this.busy = true;
    this.error = '';
    try {
      await fn();
      await this.load();
    } catch (e) {
      this.error = String(e);
    } finally {
      this.busy = false;
    }
  }

  private ts(sec?: number) {
    return sec ? new Date(sec * 1000).toLocaleString() : '—';
  }

  render() {
    const s = this.status;
    const c = this.cfg ?? {};
    return html`
      <h2>GitOps</h2>
      ${this.error ? html`<p class="error">${this.error}</p>` : ''}
      ${this.msg ? html`<p class="muted">${this.msg}</p>` : ''}
      ${!s
        ? html`<p>loading…</p>`
        : html`
          <div class="card">
            ${!s.enabled && !this.editing
              ? html`<p>GitOps is <b>disabled</b>. ${this.admin ? 'Configure it below or' : ''} see <code>docs/GITOPS.md</code>.</p>`
              : html`
                <table>
                  <tr><td>repository</td><td><code>${s.url}</code></td></tr>
                  <tr><td>branch</td><td><code>${s.branch}</code></td></tr>
                  <tr>
                    <td>targets</td>
                    <td>${s.targets.map((t) => html`<code>${t}</code> `)}</td>
                  </tr>
                  <tr><td>last sync</td><td>${this.ts(s.last_sync_at)}</td></tr>
                  <tr>
                    <td>result</td>
                    <td>
                      ${s.last_sync_ok === undefined
                        ? '—'
                        : s.last_sync_ok
                          ? html`<span class="ok">ok @ ${s.synced_rev}</span>`
                          : html`<span class="error">failed</span>`}
                    </td>
                  </tr>
                  ${s.last_error
                    ? html`<tr><td>error</td><td class="error">${s.last_error}</td></tr>`
                    : ''}
                  <tr><td>push-back</td><td>${s.push_changes ? 'enabled' : 'disabled'}</td></tr>
                  ${s.push_changes
                    ? html`
                        <tr><td>pending changes</td><td>${s.pending_push} file(s)</td></tr>
                        <tr><td>last push</td><td>${this.ts(s.last_push_at)}</td></tr>
                      `
                    : ''}
                </table>`}
            ${this.admin
              ? html`
                <div class="toolbar">
                  <button class="small secondary" ?disabled=${this.busy}
                    @click=${() => this.act(apiGitopsSync)}>sync now</button>
                  ${s.push_changes
                    ? html`<button class="small secondary" ?disabled=${this.busy}
                        @click=${() => this.act(apiGitopsPush)}>push local changes</button>`
                    : ''}
                  <span style="flex:1"></span>
                  ${!this.editing
                    ? html`<button class="small" @click=${this.startEdit}>configure</button>`
                    : html`<button class="small secondary" @click=${() => (this.editing = false)}>cancel</button>`}
                </div>`
              : ''}
          </div>

          ${this.editing
            ? html`
              <div class="card">
                <h3>GitOps configuration</h3>
                <div class="row" style="flex-wrap:wrap;gap:.6em">
                  <label><input type="checkbox" .checked=${!!c.enabled}
                    @change=${(e: any) => (this.cfg = { ...this.cfg, enabled: e.target.checked })}> enabled</label>
                  ${this.field('url', 'clone URL', 'text', 'https://github.com/org/repo.git')}
                  ${this.field('branch', 'branch')}
                  ${this.field('interval_secs', 'poll interval (s, 0=webhook only)', 'number')}
                  ${this.field('token_env', 'token env var (preferred over token)')}
                  ${this.field('token', 'token (leave empty/*** to keep)', 'text', 'write-only')}
                  ${this.field('webhook_secret_env', 'webhook secret env var')}
                  ${this.field('webhook_secret', 'webhook secret (leave empty/*** to keep)', 'text', 'write-only')}
                </div>
                <div class="row" style="flex-wrap:wrap;gap:.6em;margin-top:.5em">
                  <label><input type="checkbox" .checked=${!!c.push_changes}
                    @change=${(e: any) => (this.cfg = { ...this.cfg, push_changes: e.target.checked })}> push local changes back</label>
                  ${this.field('push_interval_secs', 'push interval (s)', 'number')}
                  ${this.field('commit_name', 'commit name')}
                  ${this.field('commit_email', 'commit email')}
                  <label><input type="checkbox" .checked=${!!c.prune}
                    @change=${(e: any) => (this.cfg = { ...this.cfg, prune: e.target.checked })}> prune deleted files</label>
                </div>
                <h4>targets <span class="muted">— [{"into":"services"|"config","path":"subdir"}]</span></h4>
                <textarea style="width:100%;min-height:6em;font-family:ui-monospace,monospace"
                  .value=${this.targetsJson}
                  @input=${(e: any) => (this.targetsJson = e.target.value)}></textarea>
                <div class="toolbar">
                  <button @click=${this.saveCfg}>save</button>
                  <span class="muted">secrets marked *** keep their stored value</span>
                </div>
              </div>`
            : ''}`}
    `;
  }
}
