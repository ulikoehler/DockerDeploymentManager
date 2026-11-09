import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { apiExecutions, apiExecution, wsUrl } from '../api';
import { sharedStyles } from '../styles';

/** Execution history — every async action (service ops, backups, commands,
 *  git syncs) lands here. Click a row to replay its captured output. */
@customElement('ddm-executions')
export class DdmExecutions extends LitElement {
  static styles = [
    sharedStyles,
    css`.output { min-height: 12em; max-height: 24em; overflow:auto; }`,
  ];

  @state() private execs: any[] = [];
  @state() private selected: any = null;
  @state() private output = '';
  @state() private loading = false;
  @state() private error = '';
  @state() private filter = '';
  @state() private statusFilter = '';
  @state() private serviceFilter = '';
  private ws?: WebSocket;
  private timer?: number;

  connectedCallback() {
    super.connectedCallback();
    this.refresh();
    this.timer = setInterval(() => this.refresh(), 10000);
  }
  disconnectedCallback() {
    super.disconnectedCallback();
    clearInterval(this.timer);
    this.ws?.close();
  }

  private async refresh() {
    try {
      this.execs = await apiExecutions();
      this.error = '';
    } catch (e: any) {
      this.error = e.message;
    }
  }

  private async select(id: string) {
    this.output = '';
    this.selected = null;
    this.loading = true;
    this.ws?.close();
    try {
      this.selected = await apiExecution(id);
    } catch (e: any) {
      this.error = e.message;
      this.loading = false;
      return;
    }
    this.loading = false;
    // Replay the captured stream — the WS endpoint replays frames for
    // finished executions, so late viewers see full output.
    this.ws = new WebSocket(wsUrl(`/ws/executions/${id}`));
    this.ws.onmessage = (ev) => {
      try {
        const m = JSON.parse(ev.data);
        const text = m.data?.text ?? m.text ?? '';
        if (text) {
          const stream = m.data?.stream;
          this.output += stream === 'stderr' ? `[stderr] ${text}` : text;
          this.scrollBottom();
        }
        if (m.type === 'execution_finished' || m.data?.success !== undefined) {
          this.output += `\n— finished (success=${m.data?.success ?? m.success})\n`;
        }
      } catch { /* ignore */ }
    };
  }

  private scrollBottom() {
    requestAnimationFrame(() => {
      const el = this.shadowRoot?.querySelector('.output');
      if (el) el.scrollTop = el.scrollHeight;
    });
  }

  private fmt(ts?: string) {
    return ts ? new Date(ts).toLocaleString() : '—';
  }

  private badge(e: any) {
    if (e.success === true) return html`<span class="badge ok">ok</span>`;
    if (e.success === false) return html`<span class="badge err">failed</span>`;
    return html`<span class="badge warn">running</span>`;
  }

  private get filtered() {
    const q = this.filter.trim().toLowerCase();
    return this.execs.filter((e) => {
      if (this.statusFilter === 'ok' && e.success !== true) return false;
      if (this.statusFilter === 'failed' && e.success !== false) return false;
      if (this.statusFilter === 'running' && e.success !== null && e.finished_at) return false;
      if (this.serviceFilter && e.service !== this.serviceFilter) return false;
      if (q && !`${e.title} ${e.service ?? ''} ${e.user} ${e.id}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }

  private get services(): string[] {
    return [...new Set(this.execs.map((e) => e.service).filter(Boolean))].sort() as string[];
  }

  render() {
    const rows = this.filtered;
    return html`
      <h2>Executions</h2>
      <p class="muted">async actions — service operations, backups, commands, git syncs.
        newest first; click a row to replay output.</p>
      <div class="row" style="gap:.5em;flex-wrap:wrap;margin-bottom:.6em">
        <input placeholder="filter title/service/user/id…" style="flex:1;min-width:12em"
          .value=${this.filter} @input=${(e: any) => (this.filter = e.target.value)}>
        <select .value=${this.statusFilter} @change=${(e: any) => (this.statusFilter = e.target.value)}>
          <option value="">all statuses</option>
          <option value="ok">ok</option>
          <option value="failed">failed</option>
          <option value="running">running</option>
        </select>
        <select .value=${this.serviceFilter} @change=${(e: any) => (this.serviceFilter = e.target.value)}>
          <option value="">all services</option>
          ${this.services.map((s) => html`<option value=${s}>${s}</option>`)}
        </select>
      </div>
      ${this.error ? html`<p class="error">${this.error}</p>` : ''}
      <table>
        <thead><tr>
          <th>started</th><th>title</th><th>service</th><th>user</th><th>result</th>
        </tr></thead>
        <tbody>
          ${rows.map(
            (e) => html`<tr style="cursor:pointer" @click=${() => this.select(e.id)}>
              <td class="muted">${this.fmt(e.started_at)}</td>
              <td>${e.title}</td>
              <td class="muted">${e.service ?? '—'}</td>
              <td class="muted">${e.user}</td>
              <td>${this.badge(e)}</td>
            </tr>`,
          )}
          ${!rows.length
            ? html`<tr><td colspan="5" class="muted">${this.execs.length ? 'no executions match the filter' : 'no executions yet'}</td></tr>`
            : ''}
        </tbody>
      </table>
      ${this.loading ? html`<p class="muted">loading…</p>` : ''}
      ${this.selected
        ? html`<div class="card" style="margin-top:1em">
            <h3>${this.selected.title}
              <span class="muted">${this.selected.id.slice(0, 8)} — ${this.fmt(this.selected.started_at)}
              ${this.selected.finished_at ? `→ ${this.fmt(this.selected.finished_at)}` : '→ running'}</span></h3>
            <pre class="output log-view">${this.output || '(no output captured yet)'}</pre>
          </div>`
        : ''}
    `;
  }
}
