import { LitElement, html } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { apiMonitorStatus, apiNotifiers, apiNotifierTest } from '../api';
import { sharedStyles } from '../styles';

@customElement('ddm-monitor-panel')
export class DdmMonitorPanel extends LitElement {
  static styles = [sharedStyles];

  @state() private status: Record<string, any> = {};
  @state() private notifiers: any[] = [];
  @state() private msg = '';
  private timer?: number;

  connectedCallback() {
    super.connectedCallback();
    this.refresh();
    this.timer = window.setInterval(() => this.refresh(), 10000);
  }
  disconnectedCallback() {
    window.clearInterval(this.timer);
    super.disconnectedCallback();
  }

  private async refresh() {
    this.status = await apiMonitorStatus().catch(() => ({}));
    apiNotifiers().then((n: any) => (this.notifiers = n)).catch(() => {});
  }

  private stateBadge(s: string) {
    const cls = s === 'ok' ? 'ok' : s === 'down' || s === 'firing' ? 'err' : 'warn';
    return html`<span class="badge ${cls}">${s}</span>`;
  }

  render() {
    const entries = Object.entries(this.status);
    return html`
      <h2>Monitoring</h2>
      <div class="card">
        <h3>Notifiers</h3>
        ${this.notifiers.length
          ? html`<table><tbody>
              ${this.notifiers.map(
                (n: any) => html`<tr>
                  <td>${n.id || n.type}</td><td class="muted">${n.type}</td>
                  <td><button class="small secondary" @click=${async () => {
                    try { await apiNotifierTest(n.id, 'test from ddm UI'); this.msg = 'sent'; }
                    catch (e: any) { this.msg = e.message; }
                  }}>test</button></td>
                </tr>`,
              )}
            </tbody></table>`
          : html`<p class="muted">none configured</p>`}
        ${this.msg ? html`<p class="muted">${this.msg}</p>` : ''}
      </div>
      <div class="card">
        <h3>Service checks</h3>
        ${entries.length
          ? html`<table>
              <thead><tr><th>service</th><th>check</th><th>state</th><th>failures</th><th>last match</th></tr></thead>
              <tbody>
                ${entries.flatMap(([svc, st]: [string, any]) =>
                  (st.checks || []).map(
                    (c: any) => html`<tr>
                      <td><a href="#/service/${svc}" style="color:#60a5fa">${svc}</a></td>
                      <td class="muted">${c.kind}:${c.id}</td>
                      <td>${this.stateBadge(c.state)}</td>
                      <td>${c.failures}</td>
                      <td class="muted" style="max-width:24em;overflow:hidden;text-overflow:ellipsis">${c.last_match ?? ''}</td>
                    </tr>`,
                  ),
                )}
              </tbody>
            </table>`
          : html`<p class="muted">no checks configured</p>`}
      </div>
    `;
  }
}
