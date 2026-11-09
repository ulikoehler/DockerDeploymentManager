import { LitElement, html } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
  apiGetMonitoring,
  apiPutMonitoring,
  apiNotifiers,
  apiMonitoringTest,
} from '../api';
import { sharedStyles } from '../styles';
import './ddm-code-editor';

const HEALTH_KINDS = [
  { id: 'docker_healthcheck', label: 'docker healthcheck' },
  { id: 'http', label: 'http' },
  { id: 'tcp', label: 'tcp' },
  { id: 'container_running', label: 'container running' },
] as const;

function num(v: string): number | undefined {
  const n = Number(v);
  return v.trim() !== '' && Number.isFinite(n) ? n : undefined;
}

@customElement('ddm-service-monitoring')
export class DdmServiceMonitoring extends LitElement {
  static styles = [sharedStyles];

  @property() name = '';
  @state() private data: any = null;
  @state() private editing = false;
  @state() private notifiers: any[] = [];
  @state() private msg = '';

  // health-check form state
  @state() private fEnabled = true;
  @state() private fKind = 'docker_healthcheck';
  @state() private fTarget = '';
  @state() private fPort = '';
  @state() private fExpect = '';
  @state() private fTimeout = '';
  @state() private fInterval = '';
  @state() private fFailure = '';
  @state() private fRecovery = '';
  @state() private fNotify = new Set<string>();
  @state() private fActionsJson = '';
  // log alerts stay JSON (advanced) — validated on save
  @state() private fLogAlertsJson = '[]';

  connectedCallback() {
    super.connectedCallback();
    this.load();
    apiNotifiers()
      .then((n: any) => (this.notifiers = n ?? []))
      .catch(() => {});
  }

  private async load() {
    try {
      this.data = await apiGetMonitoring(this.name);
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private startEdit() {
    const h: any = this.data?.config?.health ?? {};
    this.fEnabled = h.enabled !== false;
    this.fKind = h.kind ?? 'docker_healthcheck';
    this.fTarget = h.target ?? '';
    this.fPort = h.port != null ? String(h.port) : '';
    this.fExpect = h.expect_status != null ? String(h.expect_status) : '';
    this.fTimeout = h.timeout_secs != null ? String(h.timeout_secs) : '';
    this.fInterval = h.interval_secs != null ? String(h.interval_secs) : '';
    this.fFailure = h.failure_threshold != null ? String(h.failure_threshold) : '';
    this.fRecovery = h.recovery_threshold != null ? String(h.recovery_threshold) : '';
    this.fNotify = new Set(h.notify ?? []);
    this.fActionsJson = (h.actions ?? []).length
      ? JSON.stringify(h.actions, null, 2)
      : '';
    this.fLogAlertsJson = JSON.stringify(this.data?.config?.log_alerts ?? [], null, 2);
    this.editing = true;
    this.msg = '';
  }

  private toggleNotify(id: string, on: boolean) {
    const s = new Set(this.fNotify);
    if (on) s.add(id);
    else s.delete(id);
    this.fNotify = s;
  }

  private buildConfig(): unknown {
    const health: Record<string, unknown> = {
      enabled: this.fEnabled,
      kind: this.fKind,
    };
    const put = (k: string, v: unknown) => {
      if (v !== undefined && v !== '') health[k] = v;
    };
    put('target', this.fTarget.trim());
    put('port', num(this.fPort));
    put('expect_status', num(this.fExpect));
    put('timeout_secs', num(this.fTimeout));
    put('interval_secs', num(this.fInterval));
    put('failure_threshold', num(this.fFailure));
    put('recovery_threshold', num(this.fRecovery));
    health.notify = [...this.fNotify];
    health.actions = this.fActionsJson.trim()
      ? JSON.parse(this.fActionsJson)
      : [];
    return {
      health,
      log_alerts: JSON.parse(this.fLogAlertsJson || '[]'),
    };
  }

  private async save() {
    try {
      await apiPutMonitoring(this.name, this.buildConfig());
      this.editing = false;
      this.msg = 'saved';
      this.load();
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async checkNow() {
    try {
      const r: any = await apiMonitoringTest(this.name);
      const cs = (r?.containers ?? []).map(
        (c: any) => `${c.container}: ${c.state}${c.health ? ` (${c.health})` : ''}`,
      );
      this.msg = cs.length ? cs.join(' · ') : 'no containers';
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private numInput(key: 'fPort' | 'fExpect' | 'fTimeout' | 'fInterval' | 'fFailure' | 'fRecovery', label: string, ph = '') {
    const val = this[key] as string;
    const set = (v: string) => {
      (this as any)[key] = v;
    };
    return html`<label class="muted" style="width:12em">${label}</label>
      <input style="width:8em" type="number" min="0" placeholder=${ph}
        .value=${val} @input=${(e: any) => set(e.target.value)} />`;
  }

  render() {
    const st = this.data?.state;
    const cfg = this.data?.config;
    return html`
      <div class="card">
        <div class="row">
          <h3>Monitoring <span class="muted">${this.name}</span></h3>
          <span style="flex:1"></span>
          <button class="small secondary" @click=${this.checkNow}>check now</button>
          <button class="small secondary" @click=${this.startEdit}>edit config</button>
        </div>
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
        ${this.msg ? html`<p class="muted">${this.msg}</p>` : ''}
      </div>

      ${this.editing
        ? html`
        <div class="card">
          <h3>Health check</h3>
          <div class="row">
            <label><input type="checkbox" .checked=${this.fEnabled}
              @change=${(e: Event) => (this.fEnabled = (e.target as HTMLInputElement).checked)}>
              enabled</label>
            <select .value=${this.fKind}
              @change=${(e: any) => (this.fKind = e.target.value)}>
              ${HEALTH_KINDS.map((k) => html`<option value=${k.id}>${k.label}</option>`)}
            </select>
          </div>
          ${this.fKind === 'http' || this.fKind === 'tcp'
            ? html`
              <div class="row" style="margin-top:.4em">
                <label class="muted" style="width:12em">${this.fKind === 'http' ? 'URL' : 'host[:port]'}</label>
                <input style="flex:1" placeholder=${this.fKind === 'http' ? 'http://host:8123/' : '192.168.1.10'}
                  .value=${this.fTarget}
                  @input=${(e: any) => (this.fTarget = e.target.value)} />
              </div>
              <div class="row" style="margin-top:.3em">
                ${this.numInput('fPort', 'port', '8123')}
                ${this.fKind === 'http' ? this.numInput('fExpect', 'expect status', '200') : ''}
              </div>`
            : ''}
          <div class="row" style="margin-top:.3em">
            ${this.numInput('fInterval', 'interval secs', '30')}
            ${this.numInput('fTimeout', 'timeout secs', '5')}
            ${this.numInput('fFailure', 'failure threshold', '3')}
            ${this.numInput('fRecovery', 'recovery threshold', '2')}
          </div>
          <div class="row" style="margin-top:.5em">
            <label class="muted" style="width:12em">notify</label>
            ${this.notifiers.length
              ? this.notifiers.map(
                  (n: any) => html`<label style="margin-right:.8em">
                    <input type="checkbox" .checked=${this.fNotify.has(n.id)}
                      @change=${(e: Event) => this.toggleNotify(n.id, (e.target as HTMLInputElement).checked)}>
                    ${n.id}</label>`,
                )
              : html`<span class="muted">no notifiers — add some under Monitoring → Notifiers</span>`}
          </div>
          <details style="margin-top:.5em">
            <summary class="muted">advanced: auto-actions (JSON)</summary>
            <textarea rows="3" style="width:100%;font-family:ui-monospace,monospace"
              placeholder='[{"type":"restart"}] or [{"type":"stop"}]'
              .value=${this.fActionsJson}
              @input=${(e: any) => (this.fActionsJson = e.target.value)}></textarea>
          </details>
        </div>

        <div class="card">
          <h3>Log alerts <span class="muted">(JSON — advanced)</span></h3>
          <p class="muted">[{"id","regex","exclude_regex"?,"container"?,"notify"?,"cooldown_secs"?,"actions"?}]</p>
          <ddm-code-editor .value=${this.fLogAlertsJson} lang="json" height="12rem"
            @change=${(e: any) => (this.fLogAlertsJson = e.detail.value)}></ddm-code-editor>
        </div>

        <div class="toolbar">
          <button @click=${this.save}>save</button>
          <button class="secondary" @click=${() => (this.editing = false)}>cancel</button>
          <span class="muted">${cfg ? '' : 'no monitoring config yet — saving creates one'}</span>
        </div>`
        : html`<div class="card">
            <pre class="muted">${JSON.stringify(cfg ?? null, null, 2)}</pre>
          </div>`}
    `;
  }
}
