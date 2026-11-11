import { LitElement, html } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { apiAudit } from '../api';
import { timeAgo } from '../time';
import { sharedStyles } from '../styles';

@customElement('ddm-audit')
export class DdmAudit extends LitElement {
  static styles = [sharedStyles];

  @state() private entries: any[] = [];
  @state() private msg = '';
  @state() private query = '';

  connectedCallback() {
    super.connectedCallback();
    this.refresh();
  }

  private async refresh() {
    try {
      this.entries = await apiAudit();
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private get filtered() {
    const q = this.query.trim().toLowerCase();
    const rows = [...this.entries].reverse();
    if (!q) return rows;
    return rows.filter((e) =>
      `${e.user} ${e.action} ${e.target} ${e.detail}`.toLowerCase().includes(q),
    );
  }

  render() {
    const rows = this.filtered;
    return html`
      <h2>Audit log</h2>
      <p class="muted">sensitive actions recorded by the server — newest first (persisted to audit.jsonl, last ~2000 entries)</p>
      ${this.msg ? html`<p class="error">${this.msg}</p>` : ''}
      <div class="row" style="margin-bottom:.5em">
        <input placeholder="filter user/action/target…" style="flex:1;max-width:22em"
          .value=${this.query} @input=${(e: any) => (this.query = e.target.value)}>
        <span class="muted">${rows.length}/${this.entries.length}</span>
      </div>
      <div class="card">
        ${rows.length
          ? html`<table><thead><tr>
              <th>time</th><th>user</th><th>action</th><th>target</th><th>detail</th>
            </tr></thead>
            <tbody>${rows.map(
              (e) => html`<tr>
                <td class="muted" title=${new Date(e.at).toLocaleString()}>${timeAgo(e.at)}</td>
                <td>${e.user}</td>
                <td><code>${e.action}</code></td>
                <td class="muted">${e.target}</td>
                <td class="muted">${e.detail}</td>
              </tr>`,
            )}</tbody></table>`
          : html`<p class="muted">${this.entries.length ? 'no entries match the filter' : 'no entries yet'}</p>`}
      </div>
    `;
  }
}
