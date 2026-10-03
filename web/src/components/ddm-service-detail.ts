import { LitElement, html, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { apiService, apiAction, apiCheckUnit, apiDeleteService, apiExecContainer, wsUrl } from '../api';
import { sharedStyles } from '../styles';
import './ddm-log-viewer';
import './ddm-compose-editor';
import './ddm-unit-editor';
import './ddm-backup-panel';
import './ddm-service-monitoring';
import './ddm-files';
import './ddm-git';

@customElement('ddm-service-detail')
export class DdmServiceDetail extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .tabs {
        display: flex; gap: 0.2em; flex-wrap: wrap;
        border-bottom: 1px solid rgba(255, 255, 255, 0.07);
        padding-bottom: 0.4em; margin-bottom: 0.6em;
      }
      .tabs button {
        background: transparent; color: var(--text-dim);
        border-color: transparent; border-radius: 999px;
        box-shadow: none; padding: 0.35em 0.9em;
      }
      .tabs button:hover { color: #fff; background: rgba(255,255,255,0.07); transform: none; }
      .tabs button.active {
        color: #fff;
        background: rgba(255, 255, 255, 0.09);
        border-color: var(--glass-border);
        box-shadow: inset 0 1px 0 var(--glass-hi);
      }
    `,
  ];

  @property() name = '';
  @state() private detail: any = null;
  @state() private tab = 'overview';
  @state() private unitReport: any = null;
  @state() private error = '';
  @state() private execTarget: string | null = null;
  @state() private execLabel = '';
  @state() private execCmd = 'sh';
  @state() private execOutput = '';
  @state() private execRunning = false;
  private execWs?: WebSocket;

  connectedCallback() {
    super.connectedCallback();
    this.refresh();
  }

  disconnectedCallback() {
    this.execWs?.close();
    super.disconnectedCallback();
  }

  private openExec(c: any) {
    this.execTarget = c.id;
    this.execLabel = c.name;
    this.execOutput = '';
  }

  private async runExec() {
    if (!this.execTarget || !this.execCmd.trim()) return;
    this.execOutput = '';
    this.execRunning = true;
    try {
      const r: any = await apiExecContainer(this.name, this.execTarget, this.execCmd);
      const id = r.execution_id;
      this.execWs = new WebSocket(wsUrl(`/ws/executions/${id}`));
      this.execWs.onmessage = (ev) => {
        try {
          const m = JSON.parse(ev.data);
          const text = m.data?.text ?? '';
          if (m.type === 'log_output' || text) {
            this.execOutput += m.data?.stream === 'stderr' ? `[stderr] ${text}` : text;
          }
          if (m.type === 'execution_finished' || m.data?.success !== undefined) {
            this.execOutput += `\n— finished (success=${m.data?.success})\n`;
            this.execRunning = false;
          }
        } catch { /* ignore */ }
      };
      this.execWs.onclose = () => (this.execRunning = false);
    } catch (e: any) {
      this.execOutput = `error: ${e.message}`;
      this.execRunning = false;
    }
  }

  private async refresh() {
    try {
      this.detail = await apiService(this.name);
      this.unitReport = await apiCheckUnit(this.name).catch(() => null);
      this.error = '';
    } catch (e: any) {
      this.error = e.message;
    }
  }

  private async act(action: string) {
    try {
      const r: any = await apiAction(this.name, action);
      location.hash = '#/service/' + this.name;
      setTimeout(() => this.refresh(), 1500);
      if (r?.execution_id) this.tab = 'logs';
    } catch (e: any) {
      this.error = e.message;
    }
  }

  private async removeService() {
    if (!confirm(`Delete service ${this.name}? (containers will be stopped)`)) return;
    try {
      await apiDeleteService(this.name, true);
      location.hash = '#/';
    } catch (e: any) {
      this.error = e.message;
    }
  }

  private tabBtn(id: string, label: string) {
    return html`<button class="${this.tab === id ? 'active' : ''}"
      @click=${() => { this.tab = id; }}>${label}</button>`;
  }

  render() {
    if (this.error) return html`<p class="error">${this.error}</p>`;
    if (!this.detail) return html`<p class="muted">loading…</p>`;
    const d = this.detail;
    return html`
      <div class="row">
        <h2><a href="#/" style="color:var(--link);text-decoration:none">←</a> ${d.name}</h2>
        <span class="muted">${d.meta?.description || ''}</span>
        <span style="flex:1"></span>
        <button class="danger small" @click=${this.removeService}>delete</button>
      </div>
      <div class="toolbar">
        ${['update', 'pull', 'up', 'down', 'restart', 'enable', 'disable'].map(
          (a) => html`<button class="small ${a === 'down' ? 'danger' : 'secondary'}"
            @click=${() => this.act(a)}>${a}</button>`,
        )}
      </div>
      <div class="tabs">
        ${this.tabBtn('overview', 'Overview')}
        ${this.tabBtn('logs', 'Logs')}
        ${this.tabBtn('compose', 'Compose')}
        ${this.tabBtn('files', 'Files')}
        ${this.tabBtn('git', 'Git')}
        ${this.tabBtn('unit', 'Unit')}
        ${this.tabBtn('backup', 'Backup')}
        ${this.tabBtn('monitoring', 'Monitoring')}
      </div>
      ${this.renderTab()}
    `;
  }

  private renderTab() {
    switch (this.tab) {
      case 'logs':
        return html`<ddm-log-viewer name=${this.name}></ddm-log-viewer>`;
      case 'compose':
        return html`<ddm-compose-editor name=${this.name}></ddm-compose-editor>`;
      case 'files':
        return html`<ddm-files name=${this.name}></ddm-files>`;
      case 'git':
        return html`<ddm-git name=${this.name}></ddm-git>`;
      case 'unit':
        return html`<ddm-unit-editor name=${this.name}
          .report=${this.unitReport}></ddm-unit-editor>`;
      case 'backup':
        return html`<ddm-backup-panel name=${this.name}></ddm-backup-panel>`;
      case 'monitoring':
        return html`<ddm-service-monitoring name=${this.name}></ddm-service-monitoring>`;
      default:
        return this.renderOverview();
    }
  }

  private renderOverview() {
    const d = this.detail;
    return html`
      <div class="card">
        <h3>Containers</h3>
        <table>
          <thead><tr><th>container</th><th>service</th><th>state</th><th>status</th><th></th></tr></thead>
          <tbody>
            ${(d.containers || []).map(
              (c: any) => html`<tr>
                <td>${c.name}</td><td>${c.service}</td>
                <td><span class="${c.state === 'running' ? 'ok-text' : 'error'}">${c.state}</span></td>
                <td class="muted">${c.status}</td>
                <td><button class="small" @click=${() => this.openExec(c)}>exec</button></td>
              </tr>`,
            )}
          </tbody>
        </table>
      </div>
      ${this.execTarget
        ? html`<div class="card">
            <h3>exec — ${this.execLabel}</h3>
            <div class="row">
              <input style="flex:1" placeholder="command (sh -c)" .value=${this.execCmd}
                @input=${(e: any) => (this.execCmd = e.target.value)}
                @keydown=${(e: any) => e.key === 'Enter' && this.runExec()}>
              <button class="small" ?disabled=${this.execRunning} @click=${this.runExec}>run</button>
              <button class="small secondary" @click=${() => (this.execTarget = null)}>close</button>
            </div>
            <pre class="log-view" style="min-height:6em">${this.execOutput}</pre>
          </div>`
        : ''}
      <div class="card">
        <h3>Systemd unit</h3>
        ${this.unitReport
          ? html`
              <p>
                exists: ${this.unitReport.exists ? 'yes' : 'no'} ·
                enabled: ${this.unitReport.enabled ?? '?'} ·
                active: ${this.unitReport.active ?? '?'} ·
                in sync: ${this.unitReport.in_sync ? 'yes' : 'no'}
              </p>
              ${this.unitReport.issues?.length
                ? html`<ul>${this.unitReport.issues.map(
                    (i: any) => html`<li class="error">[${i.code}] ${i.message}</li>`,
                  )}</ul>`
                : html`<p class="ok-text">no issues</p>`}
            `
          : html`<p class="muted">check unavailable</p>`}
      </div>
      <div class="card">
        <h3>Meta</h3>
        <pre class="muted">${JSON.stringify(d.meta, null, 2)}</pre>
      </div>
    `;
  }
}
