import { LitElement, html } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { apiMonitorEvents, wsUrl } from '../api';
import { sharedStyles } from '../styles';

@customElement('ddm-events-view')
export class DdmEventsView extends LitElement {
  static styles = [sharedStyles];

  @state() private events: any[] = [];
  @state() private serviceFilter = '';
  private ws?: WebSocket;
  private timer?: number;

  connectedCallback() {
    super.connectedCallback();
    this.refresh();
    this.timer = window.setInterval(() => this.refresh(), 10000);
    this.ws = new WebSocket(wsUrl('/ws/events'));
    this.ws.onmessage = () => this.refresh();
  }
  disconnectedCallback() {
    this.ws?.close();
    window.clearInterval(this.timer);
    super.disconnectedCallback();
  }

  private async refresh() {
    this.events = await apiMonitorEvents(
      this.serviceFilter || undefined, 200,
    ).catch(() => []);
  }

  render() {
    return html`
      <h2>Events</h2>
      <div class="toolbar">
        <input placeholder="filter service…" .value=${this.serviceFilter}
          @input=${(e: any) => { this.serviceFilter = e.target.value; this.refresh(); }}>
      </div>
      <table>
        <thead><tr><th>time</th><th>service</th><th>kind</th><th>rule</th><th>state</th><th>message</th></tr></thead>
        <tbody>
          ${this.events.map(
            (e: any) => html`<tr>
              <td class="muted">${new Date(e.at).toLocaleString()}</td>
              <td><a href="#/service/${e.service}" style="color:#60a5fa">${e.service}</a></td>
              <td class="muted">${e.kind}</td>
              <td class="muted">${e.rule}</td>
              <td><span class="badge ${e.state === 'resolved' ? 'ok' : 'err'}">${e.state}</span></td>
              <td>${e.message}${e.detail ? html`<div class="muted">${e.detail}</div>` : ''}</td>
            </tr>`,
          )}
        </tbody>
      </table>
    `;
  }
}
