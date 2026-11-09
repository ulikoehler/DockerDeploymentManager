import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  apiCommands, apiRunCommand, apiSectionsRaw, apiSectionsMut, apiMe, wsUrl,
} from '../api';
import { sharedStyles } from '../styles';

const SECTION_TEMPLATE = `{
  "title": "New section",
  "collapsed": false,
  "items": [
    {
      "title": "Example command",
      "description": "runs echo hello",
      "icon": "",
      "button_label": "Run",
      "command_sequence": [
        { "program": "echo", "args": [{ "type": "value", "value": "hello" }] }
      ],
      "parameters": []
    }
  ]
}`;

@customElement('ddm-commands')
export class DdmCommands extends LitElement {
  static styles = [
    sharedStyles,
    css`.output { min-height: 10em; }`,
  ];

  @state() private sections: any[] = [];
  @state() private rawSections: any[] | null = null;
  @state() private editing = false;
  @state() private editJson: Record<number, string> = {};
  @state() private newJson = '';
  @state() private isAdmin = false;
  @state() private output = '';
  @state() private params: Record<string, string> = {};
  @state() private running = false;
  private ws?: WebSocket;

  connectedCallback() {
    super.connectedCallback();
    apiCommands().then((s: any) => (this.sections = s)).catch(() => {});
    apiMe()
      .then((m: any) => (this.isAdmin = (m?.roles ?? []).includes('admin')))
      .catch(() => {});
  }

  disconnectedCallback() {
    this.ws?.close();
    super.disconnectedCallback();
  }

  private async startEdit() {
    try {
      this.rawSections = await apiSectionsRaw();
      this.editJson = {};
      this.rawSections.forEach((s, i) => (this.editJson[i] = JSON.stringify(s, null, 2)));
      this.editing = true;
    } catch (e: any) {
      this.output = `error: ${e.message}`;
    }
  }

  private async saveSection(i: number) {
    try {
      const section = JSON.parse(this.editJson[i]);
      await apiSectionsMut({ op: 'update', index: i, section });
      this.output = `section ${i} saved`;
      await this.startEdit();
      apiCommands().then((s: any) => (this.sections = s)).catch(() => {});
    } catch (e: any) {
      this.output = `error: ${e.message}`;
    }
  }

  private async deleteSection(i: number) {
    if (!confirm(`delete section "${this.rawSections?.[i]?.title}" and all its items?`)) return;
    try {
      await apiSectionsMut({ op: 'delete', index: i });
      await this.startEdit();
      apiCommands().then((s: any) => (this.sections = s)).catch(() => {});
    } catch (e: any) {
      this.output = `error: ${e.message}`;
    }
  }

  private async addSection() {
    try {
      const section = JSON.parse(this.newJson || SECTION_TEMPLATE);
      await apiSectionsMut({ op: 'add', section });
      this.newJson = '';
      this.output = 'section added';
      await this.startEdit();
      apiCommands().then((s: any) => (this.sections = s)).catch(() => {});
    } catch (e: any) {
      this.output = `error: ${e.message}`;
    }
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
      <h2>Commands
        ${this.isAdmin && !this.editing
          ? html`<button class="small secondary" style="float:right" @click=${this.startEdit}>edit sections</button>`
          : ''}
        ${this.isAdmin && this.editing
          ? html`<button class="small secondary" style="float:right" @click=${() => (this.editing = false)}>done editing</button>`
          : ''}
      </h2>
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
      ${!this.sections.length && !this.editing
        ? html`<div class="card"><p class="muted">no commands configured — sections live in <code>config.yaml</code>; as admin you can add them here</p></div>`
        : ''}

      ${this.editing && this.rawSections
        ? html`
          <h3>Edit sections <span class="muted">(JSON — stored in config.yaml, hot-reloaded)</span></h3>
          ${this.rawSections.map(
            (s, i) => html`
              <div class="card">
                <div class="toolbar">
                  <b>${s.title || `section ${i}`}</b>
                  <span style="flex:1"></span>
                  <button class="small" @click=${() => this.saveSection(i)}>save</button>
                  <button class="small danger" @click=${() => this.deleteSection(i)}>delete</button>
                </div>
                <textarea style="width:100%;min-height:12em;font-family:ui-monospace,monospace"
                  .value=${this.editJson[i] ?? ''}
                  @input=${(e: any) => (this.editJson = { ...this.editJson, [i]: e.target.value })}></textarea>
              </div>`,
          )}
          <div class="card">
            <h3>New section</h3>
            <textarea style="width:100%;min-height:12em;font-family:ui-monospace,monospace"
              placeholder=${SECTION_TEMPLATE}
              .value=${this.newJson}
              @input=${(e: any) => (this.newJson = e.target.value)}></textarea>
            <div class="toolbar"><button class="small" @click=${this.addSection}>add section</button></div>
          </div>`
        : ''}

      <h3>Output</h3>
      <pre class="output log-view">${this.output}</pre>
    `;
  }
}
