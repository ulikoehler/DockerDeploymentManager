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
  // structured form state
  @state() private fEnabled = true;
  @state() private fSchedule = true;
  @state() private fPaths = '';
  @state() private fExcludes = '';
  @state() private fDumpsJson = '[]';
  @state() private showAdvanced = false;

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
      const r: any = await apiBackupRun(this.name);
      this.msg = r?.execution_id
        ? `backup started — execution ${String(r.execution_id).slice(0, 8)} (see Events)`
        : 'backup started';
      setTimeout(() => this.refresh(), 3000);
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
      const r: any = await apiBackupForget(this.name);
      this.msg = r?.execution_id
        ? `forget started — execution ${String(r.execution_id).slice(0, 8)} (see Events)`
        : 'forget started';
      setTimeout(() => this.refresh(), 3000);
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async restore(snapshot: string) {
    const target = prompt('restore target dir (absolute path on host):', '/tmp/restore-' + this.name);
    if (!target) return;
    try {
      const r: any = await apiBackupRestore(this.name, snapshot, target);
      this.msg = r?.execution_id
        ? `restore ${snapshot} → ${target} started — execution ${String(r.execution_id).slice(0, 8)} (see Events)`
        : `restore ${snapshot} → ${target} started`;
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private startEdit() {
    const c: any = this.info?.config ?? {};
    this.fEnabled = c.enabled !== false;
    this.fSchedule = c.schedule_enabled !== false;
    this.fPaths = (c.paths ?? []).join('\n');
    this.fExcludes = (c.excludes ?? []).join('\n');
    this.fDumpsJson = JSON.stringify(c.stdin_dumps ?? [], null, 2);
    this.editing = true;
  }

  private lines(v: string): string[] {
    return v.split('\n').map((s) => s.trim()).filter(Boolean);
  }

  private async saveCfg() {
    try {
      const cfg = {
        enabled: this.fEnabled,
        schedule_enabled: this.fSchedule,
        paths: this.lines(this.fPaths),
        excludes: this.lines(this.fExcludes),
        stdin_dumps: JSON.parse(this.fDumpsJson || '[]'),
      };
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
          ? html`<div class="card">
              <h3>Backup configuration</h3>
              <div class="row" style="flex-wrap:wrap;gap:.8em">
                <label><input type="checkbox" .checked=${this.fEnabled}
                  @change=${(e: any) => (this.fEnabled = e.target.checked)}> enabled</label>
                <label><input type="checkbox" .checked=${this.fSchedule}
                  @change=${(e: any) => (this.fSchedule = e.target.checked)}> scheduled backups</label>
              </div>
              <div class="row" style="margin-top:.5em">
                <label class="muted" style="width:10em">paths <span class="muted">(one per line, relative to service dir; empty = compose file + backup.sh)</span></label>
                <textarea style="flex:1;min-height:4em;font-family:ui-monospace,monospace"
                  placeholder="docker-compose.yml&#10;backup.sh"
                  .value=${this.fPaths}
                  @input=${(e: any) => (this.fPaths = e.target.value)}></textarea>
              </div>
              <div class="row" style="margin-top:.4em">
                <label class="muted" style="width:10em">excludes</label>
                <textarea style="flex:1;min-height:3em;font-family:ui-monospace,monospace"
                  .value=${this.fExcludes}
                  @input=${(e: any) => (this.fExcludes = e.target.value)}></textarea>
              </div>
              <details style="margin-top:.5em" @toggle=${(e: any) => (this.showAdvanced = e.target.open)}>
                <summary class="muted">advanced: stdin dumps (JSON)</summary>
                <textarea style="width:100%;min-height:6em;font-family:ui-monospace,monospace"
                  .value=${this.fDumpsJson}
                  @input=${(e: any) => (this.fDumpsJson = e.target.value)}></textarea>
                <p class="muted">[{"name","program","args"?,"when"?}] — dump command output into the snapshot</p>
              </details>
              <div class="toolbar">
                <button @click=${this.saveCfg}>save</button>
                <button class="secondary" @click=${() => (this.editing = false)}>cancel</button>
              </div>
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
