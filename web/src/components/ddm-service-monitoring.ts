import { LitElement, html } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { apiGetMonitoring, apiPutMonitoring } from '../api';
import { sharedStyles } from '../styles';

@customElement('ddm-service-monitoring')
export class DdmServiceMonitoring extends LitElement {
  static styles = [sharedStyles];

  @property() name = '';
  @state() private data: any = null;
  @state() private editing = false;
  @state() private cfgText = '';
  @state() private msg = '';

  connectedCallback() {
    super.connectedCallback();
    this.load();
  }

  private async load() {
    try {
      this.data = await apiGetMonitoring(this.name);
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private startEdit() {
    this.cfgText = JSON.stringify(this.data?.config ?? {
      health: { kind: 'docker_healthcheck', enabled: true },
      log_alerts: [],
    }, null, 2);
    this.editing = true;
  }

  private async save() {
    try {
      const cfg = JSON.parse(this.cfgText);
      await apiPutMonitoring(this.name, cfg);
      this.editing = false;
      this.msg = 'saved';
      this.load();
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  render() {
    const st = this.data?.state;
    return html`
      <div class="card">
        <h3>Monitoring <span class="muted">${this.name}</span></h3>
        ${st?.checks?.length
          ? html`<table><thead><tr><th>check</th><th>state</th><th>failures</th></tr></thead>
              <tbody>${st.checks.map(
                (c: any) => html`<tr>
                  <td class="muted">${c.kind}:${c.id}</td>
                  <td><span class="badge ${c.state === 'ok' ? 'ok' : 'err'}">${c.state}</span></td>
                  <td>${c.failures}</td>
                </tr>`,
              )}</tbody></table>`
          : html`<p class="muted">no active checks</p>`}
        <div class="toolbar">
          <button class="small secondary" @click=${this.startEdit}>edit config</button>
          <span class="muted">${this.msg}</span>
        </div>
        ${this.editing
          ? html`
              <p class="muted">YAML/JSON config: health {kind: docker_healthcheck|http|tcp|container_running, target, port, interval_secs, failure_threshold, notify[], actions[]} · log_alerts [{id, regex, exclude_regex, container, notify[], cooldown_secs, actions[]}]</p>
              <textarea style="width:100%;min-height:16em;font-family:ui-monospace,monospace"
                .value=${this.cfgText} @input=${(e: any) => (this.cfgText = e.target.value)}></textarea>
              <div class="toolbar">
                <button @click=${this.save}>save</button>
                <button class="secondary" @click=${() => (this.editing = false)}>cancel</button>
              </div>`
          : html`<pre class="muted">${JSON.stringify(this.data?.config ?? null, null, 2)}</pre>`}
      </div>
    `;
  }
}
