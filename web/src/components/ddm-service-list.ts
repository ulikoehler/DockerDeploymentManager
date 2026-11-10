import { LitElement, html } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { apiServices, apiAction, ServiceSummary } from '../api';
import { sharedStyles } from '../styles';

@customElement('ddm-service-list')
export class DdmServiceList extends LitElement {
  static styles = [sharedStyles];

  @state() private services: ServiceSummary[] = [];
  @state() private error = '';
  @state() private query = '';
  @state() private filter = 'all';
  @state() private favs = new Set<string>(this.loadFavs());
  private timer?: number;

  private loadFavs(): Set<string> {
    try {
      return new Set(JSON.parse(localStorage.getItem('ddm:favs') ?? '[]'));
    } catch {
      return new Set();
    }
  }

  private toggleFav(name: string, e: Event) {
    e.preventDefault();
    e.stopPropagation();
    const s = new Set(this.favs);
    if (s.has(name)) s.delete(name); else s.add(name);
    this.favs = s;
    localStorage.setItem('ddm:favs', JSON.stringify([...s]));
  }

  connectedCallback() {
    super.connectedCallback();
    this.refresh();
    this.timer = window.setInterval(() => this.refresh(), 15000);
  }
  disconnectedCallback() {
    window.clearInterval(this.timer);
    super.disconnectedCallback();
  }

  private async refresh() {
    try {
      this.services = await apiServices();
      this.error = '';
    } catch (e: any) {
      this.error = e.message;
    }
  }

  private async act(name: string, action: string) {
    try {
      await apiAction(name, action);
      setTimeout(() => this.refresh(), 1500);
    } catch (e: any) {
      this.error = e.message;
    }
  }

  private filtered(): ServiceSummary[] {
    const q = this.query.trim().toLowerCase();
    const rows = this.services.filter((s) => {
      if (this.filter === 'favorites' && !this.favs.has(s.name)) return false;
      if (this.filter === 'running' && s.running === 0) return false;
      if (this.filter === 'down' && s.running >= s.total && s.total > 0) return false;
      if (this.filter === 'alerting' && s.monitor_state !== 'alerting') return false;
      if (this.filter === 'unmonitored' && s.monitor_state) return false;
      if (!q) return true;
      return (
        s.name.toLowerCase().includes(q) ||
        (s.description ?? '').toLowerCase().includes(q) ||
        s.containers.some((c) => c.service.toLowerCase().includes(q))
      );
    });
    // favorites pinned to the top, stable within each group
    return [...rows].sort(
      (a, b) => Number(this.favs.has(b.name)) - Number(this.favs.has(a.name)),
    );
  }

  private unitBadge(s: ServiceSummary) {
    if (!s.unit.exists) return html`<span class="badge warn">no unit</span>`;
    if (s.unit.active === 'active')
      return html`<span class="badge ok">unit active</span>`;
    return html`<span class="badge warn">unit ${s.unit.active ?? '?'}</span>`;
  }

  private monBadge(s: ServiceSummary) {
    if (s.monitor_state === 'alerting')
      return html`<span class="badge err">alerting</span>`;
    if (s.monitor_state === 'ok')
      return html`<span class="badge ok">monitored</span>`;
    return html`<span class="badge muted">unmonitored</span>`;
  }

  render() {
    const rows = this.filtered();
    return html`
      <div class="row">
        <h2>Services</h2>
        <span class="spacer" style="flex:1"></span>
        <a href="#/create"><button>+ new service</button></a>
      </div>
      <div class="row" style="margin-bottom:.5em">
        <input placeholder="filter by name, description or container…"
          style="flex:1;max-width:22em"
          .value=${this.query}
          @input=${(e: any) => (this.query = e.target.value)}>
        <select .value=${this.filter}
          @change=${(e: any) => (this.filter = e.target.value)}>
          <option value="all">all</option>
          <option value="favorites">★ favorites</option>
          <option value="running">with running containers</option>
          <option value="down">with stopped containers</option>
          <option value="alerting">alerting</option>
          <option value="unmonitored">unmonitored</option>
        </select>
        <span class="muted">${rows.length}/${this.services.length}</span>
      </div>
      ${this.error ? html`<p class="error">${this.error}</p>` : ''}
      ${!this.services.length && !this.query
        ? html`<div class="card">
            <h3>Welcome to DDM</h3>
            <p>No services yet. Get started:</p>
            <ol>
              <li>Create your first service — <a href="#/create">+ new service</a> — paste a
                <code>docker-compose.yml</code> or pick a template.</li>
              <li>Manage users &amp; permissions under <a href="#/users">Users</a> (admin)
                and API tokens under <a href="#/token">Tokens</a>.</li>
              <li>Docs: <a href="https://github.com/ulikoehler/DockerDeploymentManager" target="_blank" rel="noopener">github.com/ulikoehler/DockerDeploymentManager</a></li>
            </ol>
          </div>`
        : ''}
      <table>
        <thead>
          <tr><th>name</th><th>containers</th><th>unit</th><th>monitor</th><th>actions</th></tr>
        </thead>
        <tbody>
          ${rows.map(
            (s) => html`
              <tr>
                <td>
                  <a href="#/service/${s.name}" style="color:var(--link)">${s.name}</a>
                  <button class="small secondary" style="padding:.1em .4em;margin-left:.3em"
                    title=${this.favs.has(s.name) ? 'remove from favorites' : 'add to favorites'}
                    @click=${(e: Event) => this.toggleFav(s.name, e)}>${this.favs.has(s.name) ? '★' : '☆'}</button>
                  <div class="muted">${s.description}</div>
                </td>
                <td>
                  ${s.running}/${s.total} running
                  ${s.containers.map(
                    (c) => html`<div class="muted">
                      ${c.service}:
                      <span class="${c.state === 'running' ? 'ok-text' : 'error'}">
                        ${c.state}${c.health ? ` (${c.health})` : ''}
                      </span>
                    </div>`,
                  )}
                </td>
                <td>${this.unitBadge(s)}</td>
                <td>${this.monBadge(s)}</td>
                <td>
                  <button class="small" @click=${() => this.act(s.name, 'update')}>update</button>
                  <button class="small secondary" @click=${() => this.act(s.name, 'restart')}>restart</button>
                  <button class="small secondary" @click=${() => this.act(s.name, 'down')}>down</button>
                </td>
              </tr>
            `,
          )}
          ${!rows.length
            ? html`<tr><td colspan="5" class="muted">no services match</td></tr>`
            : ''}
        </tbody>
      </table>
    `;
  }
}
