import { LitElement, html, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { apiService, apiAction, apiCheckUnit, apiDeleteService } from '../api';
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
      .tabs button { background: transparent; color: #9aa4b2; border-radius: 6px 6px 0 0; }
      .tabs button.active { color: #fff; background: #1d4ed8; }
      .tabs { border-bottom: 1px solid #232a35; }
    `,
  ];

  @property() name = '';
  @state() private detail: any = null;
  @state() private tab = 'overview';
  @state() private unitReport: any = null;
  @state() private error = '';

  connectedCallback() {
    super.connectedCallback();
    this.refresh();
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
        <h2><a href="#/" style="color:#60a5fa;text-decoration:none">←</a> ${d.name}</h2>
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
          <thead><tr><th>container</th><th>service</th><th>state</th><th>status</th></tr></thead>
          <tbody>
            ${(d.containers || []).map(
              (c: any) => html`<tr>
                <td>${c.name}</td><td>${c.service}</td>
                <td><span class="${c.state === 'running' ? 'ok-text' : 'error'}">${c.state}</span></td>
                <td class="muted">${c.status}</td>
              </tr>`,
            )}
          </tbody>
        </table>
      </div>
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
