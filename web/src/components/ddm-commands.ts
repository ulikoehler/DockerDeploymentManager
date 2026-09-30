import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { apiCommands, apiRunCommand, wsUrl } from '../api';
import { sharedStyles } from '../styles';

@customElement('ddm-commands')
export class DdmCommands extends LitElement {
  static styles = [
    sharedStyles,
    css`.output { min-height: 10em; }`,
  ];

  @state() private sections: any[] = [];
  @state() private output = '';
  @state() private params: Record<string, string> = {};
  @state() private running = false;
  private ws?: WebSocket;

  connectedCallback() {
    super.connectedCallback();
    apiCommands().then((s: any) => (this.sections = s)).catch(() => {});
  }

  disconnectedCallback() {
    this.ws?.close();
    super.disconnectedCallback();
  }

  private async run(si: number, item: any) {
    this.output = '';
    this.running = true;
    try {
      const r: any = await apiRunCommand(si, item.index, this.params);
      const id = r.execution_id;
      this.ws = new WebSocket(wsUrl(`/ws/executions/${id}`));
      this.ws.onmessage = (ev) => {
        try {
          const m = JSON.parse(ev.data);
          if (m.type === 'log_output' || m.data?.text) {
            const text = m.data?.text ?? '';
            const stream = m.data?.stream;
            this.output += stream === 'stderr' ? `[stderr] ${text}` : text;
            this.scrollBottom();
          }
          if (m.type === 'execution_finished' || m.data?.success !== undefined) {
            this.output += `\n— finished (success=${m.data?.success})\n`;
            this.running = false;
          }
        } catch { /* ignore */ }
      };
      this.ws.onclose = () => (this.running = false);
    } catch (e: any) {
      this.output = `error: ${e.message}`;
      this.running = false;
    }
  }

  private scrollBottom() {
    requestAnimationFrame(() => {
      const el = this.shadowRoot?.querySelector('.output');
      if (el) el.scrollTop = el.scrollHeight;
    });
  }

  private paramFields(item: any, si: number) {
    if (!item.parameters?.length) return '';
    return item.parameters.map((p: any) => {
      const key = p.name;
      if (p.type === 'boolean') {
        return html`<label>
          <input type="checkbox" .checked=${p.default ?? false}
            @change=${(e: any) => (this.params = { ...this.params, [key]: String(e.target.checked) })}>
          ${p.label}</label>`;
      }
      return html`<input placeholder="${p.label}${p.required ? ' *' : ''}"
        title="${p.help || ''}" .value=${this.params[key] ?? p.default ?? ''}
        @input=${(e: any) => (this.params = { ...this.params, [key]: e.target.value })}>`;
    });
  }

  render() {
    return html`
      <h2>Commands</h2>
      ${this.sections.map(
        (s) => html`
          <div class="card">
            <h3>${s.title}</h3>
            ${s.items.map(
              (item: any) => html`
                <div class="row" style="margin:0.4em 0">
                  <button class="small" ?disabled=${this.running}
                    @click=${() => this.run(s.index, item)}>${item.button_label || 'Run'}</button>
                  <span>${item.title}</span>
                  ${this.paramFields(item, s.index)}
                  <span class="muted">${item.description}</span>
                </div>
              `,
            )}
          </div>
        `,
      )}
      <h3>Output</h3>
      <pre class="output log-view">${this.output}</pre>
    `;
  }
}
