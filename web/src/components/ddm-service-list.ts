import { LitElement, html } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { apiServices, apiAction, ServiceSummary } from '../api';
import { sharedStyles } from '../styles';

@customElement('ddm-service-list')
export class DdmServiceList extends LitElement {
  static styles = [sharedStyles];

  @state() private services: ServiceSummary[] = [];
  @state() private error = '';
  private timer?: number;

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
    return '';
  }

  render() {
    return html`
      <div class="row">
        <h2>Services</h2>
        <span class="spacer" style="flex:1"></span>
        <a href="#/create"><button>+ new service</button></a>
      </div>
      ${this.error ? html`<p class="error">${this.error}</p>` : ''}
      <table>
        <thead>
          <tr><th>name</th><th>containers</th><th>unit</th><th>monitor</th><th>actions</th></tr>
        </thead>
        <tbody>
          ${this.services.map(
            (s) => html`
              <tr>
                <td>
                  <a href="#/service/${s.name}" style="color:#60a5fa">${s.name}</a>
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
        </tbody>
      </table>
    `;
  }
}
