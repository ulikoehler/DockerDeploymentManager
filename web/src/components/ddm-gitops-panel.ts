import { LitElement, html } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { apiGitopsStatus, apiGitopsSync, apiGitopsPush } from '../api';
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

/** GitOps status & manual sync/push (admin). Config lives in config.yaml. */
@customElement('ddm-gitops-panel')
export class DdmGitopsPanel extends LitElement {
  static styles = sharedStyles;
  @property({ type: Boolean }) admin = false;
  @state() private status?: GitsyncStatus;
  @state() private error = '';
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
      this.error = '';
    } catch (e) {
      this.error = String(e);
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
    return html`
      <h2>GitOps</h2>
      ${this.error ? html`<p class="error">${this.error}</p>` : ''}
      ${!s
        ? html`<p>loading…</p>`
        : !s.enabled
          ? html`<div class="card">
              GitOps is <b>disabled</b>. Configure the
              <code>gitops:</code> section in <code>config.yaml</code> — see
              <code>docs/GITOPS.md</code>.
            </div>`
          : html`
              <div class="card">
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
                </table>
                ${this.admin
                  ? html`
                      <p>
                        <button ?disabled=${this.busy}
                          @click=${() => this.act(apiGitopsSync)}>
                          sync now
                        </button>
                        ${s.push_changes
                          ? html`<button ?disabled=${this.busy}
                              @click=${() => this.act(apiGitopsPush)}>
                              push local changes
                            </button>`
                          : ''}
                      </p>
                    `
                  : ''}
              </div>
            `}
    `;
  }
}
