import { LitElement, html } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { apiAudit } from '../api';
import { sharedStyles } from '../styles';

@customElement('ddm-audit')
export class DdmAudit extends LitElement {
  static styles = [sharedStyles];

  @state() private entries: any[] = [];
  @state() private msg = '';

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

  render() {
    return html`
      <h2>Audit log</h2>
      <p class="muted">sensitive actions recorded by the server — newest first (persisted to audit.jsonl, last ~2000 entries)</p>
      ${this.msg ? html`<p class="error">${this.msg}</p>` : ''}
      <div class="card">
        ${this.entries.length
          ? html`<table><thead><tr>
              <th>time</th><th>user</th><th>action</th><th>target</th><th>detail</th>
            </tr></thead>
            <tbody>${[...this.entries].reverse().map(
              (e) => html`<tr>
                <td class="muted">${new Date(e.at).toLocaleString()}</td>
                <td>${e.user}</td>
                <td><code>${e.action}</code></td>
                <td class="muted">${e.target}</td>
                <td class="muted">${e.detail}</td>
              </tr>`,
            )}</tbody></table>`
          : html`<p class="muted">no entries yet</p>`}
      </div>
    `;
  }
}
