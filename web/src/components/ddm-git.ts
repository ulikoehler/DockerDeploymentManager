import { LitElement, html } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
  apiGitRepos,
  apiGitStatus,
  apiGitLog,
  apiGitBranches,
  apiGitClone,
  apiGitAction,
} from '../api';
import { sharedStyles } from '../styles';

@customElement('ddm-git')
export class DdmGit extends LitElement {
  static styles = [sharedStyles];

  @property() name = '';
  @state() private repos: any[] = [];
  @state() private selected: any = null; // {path, status, branches, log}
  @state() private msg = '';
  @state() private cloneUrl = '';
  @state() private clonePath = '';
  @state() private cloneBranch = '';
  @state() private showClone = false;

  connectedCallback() {
    super.connectedCallback();
    this.refresh();
  }

  private async refresh() {
    this.repos = await apiGitRepos(this.name).catch(() => []);
    if (this.selected) await this.select(this.selected.path);
  }

  private async select(path: string) {
    try {
      const [status, branches, log] = await Promise.all([
        apiGitStatus(this.name, path),
        apiGitBranches(this.name, path),
        apiGitLog(this.name, path, 30),
      ]);
      this.selected = { path, status, branches, log };
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async doClone() {
    try {
      const r: any = await apiGitClone(
        this.name,
        this.cloneUrl,
        this.clonePath,
        this.cloneBranch || undefined,
      );
      this.msg = `clone started (execution ${r.execution_id})`;
      this.showClone = false;
      setTimeout(() => this.refresh(), 3000);
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async action(op: string, ref?: string) {
    try {
      const r: any = await apiGitAction(this.name, this.selected.path, op, ref);
      this.msg = `${op} started (execution ${r.execution_id})`;
      setTimeout(() => this.refresh(), 2000);
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  render() {
    const s = this.selected;
    return html`
      <div class="card">
        <div class="row">
          <h3>Git repositories</h3>
          <button class="small secondary" @click=${() => (this.showClone = !this.showClone)}>
            clone…</button>
          <button class="small secondary" @click=${this.refresh}>refresh</button>
        </div>
        ${this.showClone
          ? html`<div class="row" style="margin:.4em 0">
              <input style="flex:2" placeholder="https://github.com/user/repo.git" .value=${this.cloneUrl}
                @input=${(e: any) => (this.cloneUrl = e.target.value)} />
              <input placeholder="subdirectory (empty = service dir)" .value=${this.clonePath}
                @input=${(e: any) => (this.clonePath = e.target.value)} />
              <input placeholder="branch (optional)" .value=${this.cloneBranch}
                @input=${(e: any) => (this.cloneBranch = e.target.value)} />
              <button class="small" ?disabled=${!this.cloneUrl} @click=${this.doClone}>clone</button>
            </div>`
          : ''}
        ${this.repos.length
          ? html`<table><thead><tr><th>path</th><th>branch</th><th>remote</th><th>state</th></tr></thead>
              <tbody>${this.repos.map(
                (r) => html`<tr>
                  <td><a href="#" style="color:#60a5fa;text-decoration:none"
                    @click=${(e: Event) => { e.preventDefault(); this.select(r.path); }}>${r.path}</a></td>
                  <td>${r.branch}</td>
                  <td class="muted" style="max-width:22em;overflow:hidden;text-overflow:ellipsis">${r.remote ?? ''}</td>
                  <td>${r.dirty ? html`<span class="badge warn">dirty</span>` : html`<span class="badge ok">clean</span>`}</td>
                </tr>`,
              )}</tbody></table>`
          : html`<p class="muted">no git repositories in this service directory</p>`}
        ${this.msg ? html`<p class="muted">${this.msg}</p>` : ''}
      </div>
      ${s
        ? html`<div class="card">
            <div class="row">
              <h3>${s.path}</h3>
              <span class="badge muted">${s.status.branch}</span>
              <button class="small" @click=${() => this.action('pull')}>pull</button>
              <button class="small secondary" @click=${() => this.action('fetch')}>fetch</button>
              <select @change=${(e: any) => e.target.value && this.action('checkout', e.target.value)}>
                <option value="">switch branch…</option>
                ${s.branches.local.map(
                  (b: string) => html`<option value=${b} ?selected=${b === s.branches.current}>${b}</option>`,
                )}
                ${s.branches.remote.map(
                  (b: string) => html`<option value=${b}>${b}</option>`,
                )}
              </select>
            </div>
            <p class="muted">${s.status.tracking}</p>
            ${s.status.changes.length
              ? html`<pre>${s.status.changes.join('\n')}</pre>`
              : html`<p class="muted">working tree clean</p>`}
            <h3>Log</h3>
            <pre>${s.log.join('\n')}</pre>
          </div>`
        : ''}
    `;
  }
}
