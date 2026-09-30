import { LitElement, html } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
  apiBackup, apiPutBackup, apiBackupCheck, apiBackupProvision,
  apiBackupRun, apiSnapshots, apiBackupForget, apiBackupRestore,
} from '../api';
import { sharedStyles } from '../styles';

@customElement('ddm-backup-panel')
export class DdmBackupPanel extends LitElement {
  static styles = [sharedStyles];

  @property() name = '';
  @state() private info: any = null;
  @state() private check: any = null;
  @state() private snapshots: any[] = [];
  @state() private msg = '';
  @state() private editing = false;
  @state() private cfgText = '';

  connectedCallback() {
    super.connectedCallback();
    this.refresh();
  }

  private async refresh() {
    try {
      this.info = await apiBackup(this.name);
      this.check = await apiBackupCheck(this.name).catch(() => null);
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async provision() {
    try {
      const steps: any = await apiBackupProvision(this.name);
      this.msg = steps.join('; ');
      this.refresh();
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async run() {
    try {
      await apiBackupRun(this.name);
      this.msg = 'backup started';
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async loadSnapshots() {
    try {
      const r: any = await apiSnapshots(this.name);
      this.snapshots = Array.isArray(r) ? r : [];
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async forget() {
    if (!confirm('run restic forget --prune?')) return;
    try {
      await apiBackupForget(this.name);
      this.msg = 'forget started';
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async restore(snapshot: string) {
    const target = prompt('restore target dir (absolute path on host):', '/tmp/restore-' + this.name);
    if (!target) return;
    try {
      await apiBackupRestore(this.name, snapshot, target);
      this.msg = `restore ${snapshot} → ${target} started`;
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private startEdit() {
    this.cfgText = JSON.stringify(this.info?.config ?? {
      enabled: true, paths: [], excludes: [], stdin_dumps: [], schedule_enabled: true,
    }, null, 2);
    this.editing = true;
  }

  private async saveCfg() {
    try {
      const cfg = JSON.parse(this.cfgText);
      await apiPutBackup(this.name, cfg);
      this.editing = false;
      this.msg = 'config saved';
      this.refresh();
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  render() {
    return html`
      <div class="card">
        <h3>Backup <span class="muted">${this.name}</span></h3>
        ${!this.info?.enabled_global
          ? html`<p class="badge warn">backup disabled globally (backup.enabled=false)</p>`
          : ''}
        <p class="muted">repository: ${this.info?.repository ?? '—'}</p>
        ${this.check
          ? html`
              <p>
                password: ${this.check.password_file ? '✓' : '✗'} ·
                script: ${this.check.script ? '✓' : '✗'} ·
                repo inited: ${this.check.repo_inited ? '✓' : '✗'} ·
                timer: ${this.check.timer_exists ? `${this.check.timer_active}` : '✗'} ·
                last run: ${this.check.last_run ?? 'never'}
              </p>
              ${this.check.issues?.length
                ? html`<ul>${this.check.issues.map(
                    (i: any) => html`<li class="error">[${i.code}] ${i.message}</li>`,
                  )}</ul>`
                : html`<p class="ok-text">no issues</p>`}
            `
          : ''}
        <div class="toolbar">
          <button class="small" @click=${this.provision}>provision</button>
          <button class="small" @click=${this.run}>run now</button>
          <button class="small secondary" @click=${this.loadSnapshots}>snapshots</button>
          <button class="small secondary" @click=${this.forget}>forget --prune</button>
          <button class="small secondary" @click=${this.startEdit}>config</button>
          <span class="muted">${this.msg}</span>
        </div>
        ${this.editing
          ? html`<textarea style="width:100%;min-height:14em;font-family:ui-monospace,monospace"
              .value=${this.cfgText} @input=${(e: any) => (this.cfgText = e.target.value)}></textarea>
              <div class="toolbar">
                <button @click=${this.saveCfg}>save</button>
                <button class="secondary" @click=${() => (this.editing = false)}>cancel</button>
              </div>`
          : ''}
        ${this.snapshots.length
          ? html`<table><thead><tr><th>snapshot</th><th>time</th><th></th></tr></thead>
              <tbody>${this.snapshots.map(
                (s: any) => html`<tr><td class="muted">${s.short_id || s.id}</td>
                  <td class="muted">${s.time}</td>
                  <td><button class="small secondary"
                    @click=${() => this.restore(s.short_id || s.id)}>restore</button></td></tr>`,
              )}</tbody></table>`
          : ''}
      </div>
    `;
  }
}
