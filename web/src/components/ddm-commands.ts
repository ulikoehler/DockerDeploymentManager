import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  apiCommands, apiRunCommand, apiSectionsRaw, apiSectionsMut, apiMe, wsTicketUrl,
} from '../api';
import { sharedStyles } from '../styles';
import { ddmConfirm } from '../dialog';

const ARG_TYPES = ['value', 'variable', 'optional', 'conditional'];
const PARAM_TYPES = ['string', 'boolean', 'number'];

function blankArg() { return { type: 'value', value: '' }; }
function blankParam() { return { type: 'string', name: '', label: '', required: false, help: '', default: '' }; }
function blankStep() { return { program: '', args: [] }; }
function blankItem() {
  return {
    title: '', description: '', icon: '', button_label: 'Run',
    work_dir: '.', on_host: true, required_role: '',
    parameters: [], command_sequence: [blankStep()],
  };
}

@customElement('ddm-commands')
export class DdmCommands extends LitElement {
  static styles = [
    sharedStyles,
    css`.output { min-height: 10em; }
       .item-edit { border-left: 3px solid var(--accent, #8fb0ff); }
       .arg-row, .param-row, .step-row { display:flex; gap:.4em; align-items:center; flex-wrap:wrap; margin:.25em 0; }
       .arg-row input, .param-row input, .step-row input { flex:1; min-width:8em; }
       select { background: var(--bg, #1a1d24); color: inherit; border: 1px solid var(--border, #333); border-radius: 4px; padding: .25em .4em; }`,
  ];

  @state() private sections: any[] = [];
  @state() private drafts: any[] | null = null;
  @state() private editing = false;
  @state() private isAdmin = false;
  @state() private output = '';
  @state() private params: Record<string, string> = {};
  @state() private running = false;
  @state() private itemEdit: { si: number; ii: number } | null = null;
  @state() private itemDraft: any = null;
  @state() private newSectionTitle = '';
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
      const raw = await apiSectionsRaw();
      this.drafts = JSON.parse(JSON.stringify(raw));
      this.editing = true;
      this.itemEdit = null;
    } catch (e: any) {
      this.output = `error: ${e.message}`;
    }
  }

  private async reload() {
    await this.startEdit();
    apiCommands().then((s: any) => (this.sections = s)).catch(() => {});
  }

  // ---- section ops ----------------------------------------------------

  private async saveSection(i: number) {
    try {
      await apiSectionsMut({ op: 'update', index: i, section: this.drafts![i] });
      this.output = `section "${this.drafts![i].title}" saved`;
      await this.reload();
    } catch (e: any) {
      this.output = `error: ${e.message}`;
    }
  }

  private async deleteSection(i: number) {
    if (!(await ddmConfirm(`delete section "${this.drafts?.[i]?.title}" and all its items?`, { danger: true }))) return;
    try {
      await apiSectionsMut({ op: 'delete', index: i });
      await this.reload();
    } catch (e: any) {
      this.output = `error: ${e.message}`;
    }
  }

  private async addSection() {
    const title = this.newSectionTitle.trim();
    if (!title) { this.output = 'section title required'; return; }
    try {
      await apiSectionsMut({
        op: 'add',
        section: { title, collapsed: false, items: [], required_role: null },
      });
      this.newSectionTitle = '';
      this.output = `section "${title}" added — add items below`;
      await this.reload();
    } catch (e: any) {
      this.output = `error: ${e.message}`;
    }
  }

  // ---- item ops --------------------------------------------------------

  private openItem(si: number, ii: number) {
    this.itemDraft = ii === -1
      ? { ...blankItem(), parameters: [], command_sequence: [blankStep()] }
      : JSON.parse(JSON.stringify(this.drafts![si].items[ii]));
    // normalize for the form
    this.itemDraft.parameters = (this.itemDraft.parameters ?? []).map((p: any) => ({
      type: p.type ?? 'string', name: p.name ?? '', label: p.label ?? p.name ?? '',
      required: !!p.required, help: p.help ?? '', default: p.default ?? '',
      placeholder: p.placeholder ?? '', min: p.min ?? '', max: p.max ?? '',
    }));
    this.itemDraft.command_sequence = (this.itemDraft.command_sequence ?? []).map((s: any) => ({
      program: s.program ?? '',
      args: (s.args ?? []).map((a: any) => ({ ...a })),
    }));
    this.itemEdit = { si, ii };
  }

  private saveItem() {
    const d = this.itemDraft;
    if (!d.title.trim()) { this.output = 'item title required'; return; }
    if (!d.command_sequence?.length) { this.output = 'at least one command step required'; return; }
    for (const s of d.command_sequence) {
      if (!s.program.trim()) { this.output = 'every step needs a program'; return; }
    }
    // serialize parameters back to the tagged enum, dropping empty defaults
    const parameters = (d.parameters ?? [])
      .filter((p: any) => p.name.trim())
      .map((p: any) => {
        const base: any = { type: p.type, name: p.name.trim(), label: p.label || p.name.trim() };
        if (p.type === 'boolean') {
          base.default = p.default === 'true' || p.default === true;
          if (p.help) base.help = p.help;
        } else {
          base.required = !!p.required;
          if (p.help) base.help = p.help;
          if (p.default !== '' && p.default != null) {
            base.default = p.type === 'number' ? Number(p.default) : String(p.default);
          }
          if (p.type === 'string' && p.placeholder) base.placeholder = p.placeholder;
          if (p.type === 'number') {
            if (p.min !== '' && p.min != null) base.min = Number(p.min);
            if (p.max !== '' && p.max != null) base.max = Number(p.max);
          }
        }
        return base;
      });
    const item: any = {
      title: d.title.trim(),
      description: d.description ?? '',
      work_dir: d.work_dir || '.',
      icon: d.icon ?? '',
      button_label: d.button_label || 'Run',
      parameters,
      command_sequence: d.command_sequence,
      on_host: d.on_host !== false,
    };
    if (d.required_role) item.required_role = d.required_role;
    const { si, ii } = this.itemEdit!;
    if (ii === -1) this.drafts![si].items.push(item);
    else this.drafts![si].items[ii] = item;
    this.itemEdit = null;
    this.itemDraft = null;
    this.output = `item "${item.title}" staged — save the section to persist`;
  }

  private async deleteItem(si: number, ii: number) {
    const it = this.drafts![si].items[ii];
    if (!(await ddmConfirm(`delete item "${it.title}"?`, { danger: true }))) return;
    this.drafts![si].items.splice(ii, 1);
    this.output = `item "${it.title}" removed — save the section to persist`;
  }

  // ---- run --------------------------------------------------------------

  private async run(si: number, item: any) {
    this.output = '';
    this.running = true;
    try {
      const r: any = await apiRunCommand(si, item.index, this.params);
      const id = r.execution_id;
      this.ws = new WebSocket(await wsTicketUrl(`/ws/executions/${id}`));
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

  // ---- item editor sub-renderers ---------------------------------------

  private argEditor(si: number, ci: number, ai: number) {
    const d = this.itemDraft;
    const a = d.command_sequence[ci].args[ai];
    const set = (patch: any) => {
      const seq = [...this.itemDraft.command_sequence];
      const step = { ...seq[ci], args: [...seq[ci].args] };
      step.args[ai] = { ...step.args[ai], ...patch };
      seq[ci] = step;
      this.itemDraft = { ...this.itemDraft, command_sequence: seq };
    };
    return html`
      <div class="arg-row">
        <select .value=${a.type} @change=${(e: any) => set({ type: e.target.value, value: a.value ?? '', name: a.name ?? '', flag: a.flag ?? '', variable: a.variable ?? '' })}>
          ${ARG_TYPES.map((t) => html`<option value=${t}>${t}</option>`)}
        </select>
        ${a.type === 'value' ? html`<input placeholder="literal value" .value=${a.value ?? ''} @input=${(e: any) => set({ value: e.target.value })}>` : ''}
        ${a.type === 'variable' || a.type === 'optional' ? html`<input placeholder="parameter name" .value=${a.name ?? a.variable ?? ''} @input=${(e: any) => set(a.type === 'optional' ? { variable: e.target.value } : { name: e.target.value })}>` : ''}
        ${a.type === 'optional' ? html`<input placeholder="flag (e.g. --verbose)" style="max-width:10em" .value=${a.flag ?? ''} @input=${(e: any) => set({ flag: e.target.value })}>` : ''}
        ${a.type === 'conditional' ? html`<input placeholder="variable" .value=${a.variable ?? ''} @input=${(e: any) => set({ variable: e.target.value })}>` : ''}
        <button class="small danger" @click=${() => {
          const seq = [...this.itemDraft.command_sequence];
          seq[ci] = { ...seq[ci], args: seq[ci].args.filter((_: any, j: number) => j !== ai) };
          this.itemDraft = { ...this.itemDraft, command_sequence: seq };
        }}>×</button>
      </div>
      ${a.type === 'conditional'
        ? html`<div class="arg-row" style="padding-left:1.5em">
            <span class="muted">true args (comma-sep)</span>
            <input .value=${(a.true_args ?? []).join(',')} @input=${(e: any) => set({ true_args: e.target.value.split(',').map((s: string) => s.trim()).filter(Boolean) })}>
            <span class="muted">false args</span>
            <input .value=${(a.false_args ?? []).join(',')} @input=${(e: any) => set({ false_args: e.target.value.split(',').map((s: string) => s.trim()).filter(Boolean) })}>
          </div>`
        : ''}`;
  }

  private paramEditor(pi: number) {
    const d = this.itemDraft;
    const p = d.parameters[pi];
    const set = (patch: any) => {
      const params = [...this.itemDraft.parameters];
      params[pi] = { ...params[pi], ...patch };
      this.itemDraft = { ...this.itemDraft, parameters: params };
    };
    return html`
      <div class="param-row">
        <select .value=${p.type} @change=${(e: any) => set({ type: e.target.value })}>
          ${PARAM_TYPES.map((t) => html`<option value=${t}>${t}</option>`)}
        </select>
        <input placeholder="name" style="max-width:9em" .value=${p.name} @input=${(e: any) => set({ name: e.target.value })}>
        <input placeholder="label" style="max-width:9em" .value=${p.label} @input=${(e: any) => set({ label: e.target.value })}>
        ${p.type !== 'boolean'
          ? html`<label class="muted"><input type="checkbox" .checked=${!!p.required} @change=${(e: any) => set({ required: e.target.checked })}> required</label>`
          : ''}
        ${p.type === 'boolean'
          ? html`<label class="muted"><input type="checkbox" .checked=${p.default === true || p.default === 'true'} @change=${(e: any) => set({ default: e.target.checked ? 'true' : 'false' })}> default on</label>`
          : html`<input placeholder="default" style="max-width:7em" .value=${p.default ?? ''} @input=${(e: any) => set({ default: e.target.value })}>`}
        <input placeholder="help" style="max-width:10em" .value=${p.help ?? ''} @input=${(e: any) => set({ help: e.target.value })}>
        ${p.type === 'string' ? html`<input placeholder="placeholder" style="max-width:9em" .value=${p.placeholder ?? ''} @input=${(e: any) => set({ placeholder: e.target.value })}>` : ''}
        ${p.type === 'number' ? html`<input placeholder="min" style="max-width:4.5em" .value=${p.min ?? ''} @input=${(e: any) => set({ min: e.target.value })}>
          <input placeholder="max" style="max-width:4.5em" .value=${p.max ?? ''} @input=${(e: any) => set({ max: e.target.value })}>` : ''}
        <button class="small danger" @click=${() => {
          this.itemDraft = { ...this.itemDraft, parameters: this.itemDraft.parameters.filter((_: any, j: number) => j !== pi) };
        }}>×</button>
      </div>`;
  }

  private itemEditor() {
    const d = this.itemDraft!;
    const set = (patch: any) => { this.itemDraft = { ...this.itemDraft, ...patch }; };
    return html`
      <div class="card item-edit">
        <h3>${this.itemEdit!.ii === -1 ? 'New item' : 'Edit item'}</h3>
        <div class="row" style="flex-wrap:wrap;gap:.5em">
          <input placeholder="title *" style="flex:2;min-width:12em" .value=${d.title}
            @input=${(e: any) => set({ title: e.target.value })}>
          <input placeholder="button label" style="width:7em" .value=${d.button_label}
            @input=${(e: any) => set({ button_label: e.target.value })}>
          <input placeholder="icon (emoji/short text)" style="width:8em" .value=${d.icon}
            @input=${(e: any) => set({ icon: e.target.value })}>
        </div>
        <div class="row" style="flex-wrap:wrap;gap:.5em;margin-top:.4em">
          <input placeholder="description" style="flex:2;min-width:12em" .value=${d.description}
            @input=${(e: any) => set({ description: e.target.value })}>
          <input placeholder="work dir" style="width:7em" .value=${d.work_dir}
            @input=${(e: any) => set({ work_dir: e.target.value })}>
          <input placeholder="required role (optional)" style="width:11em" .value=${d.required_role ?? ''}
            @input=${(e: any) => set({ required_role: e.target.value })}>
          <label class="muted"><input type="checkbox" .checked=${d.on_host !== false}
            @change=${(e: any) => set({ on_host: e.target.checked })}> run on host</label>
        </div>

        <h4>Parameters</h4>
        ${d.parameters.map((_: any, i: number) => this.paramEditor(i))}
        <button class="small secondary" @click=${() => {
          this.itemDraft = { ...this.itemDraft, parameters: [...this.itemDraft.parameters, blankParam()] };
        }}>+ parameter</button>

        <h4>Command steps</h4>
        ${d.command_sequence.map((s: any, ci: number) => html`
          <div class="card" style="padding:.6em">
            <div class="arg-row">
              <span class="muted">step ${ci + 1}</span>
              <input placeholder="program (e.g. docker, /bin/sh)" .value=${s.program}
                @input=${(e: any) => {
                  const seq = [...this.itemDraft.command_sequence];
                  seq[ci] = { ...seq[ci], program: e.target.value };
                  this.itemDraft = { ...this.itemDraft, command_sequence: seq };
                }}>
              <button class="small danger" ?disabled=${d.command_sequence.length <= 1}
                @click=${() => {
                  this.itemDraft = { ...this.itemDraft, command_sequence: this.itemDraft.command_sequence.filter((_: any, j: number) => j !== ci) };
                }}>×</button>
            </div>
            ${s.args.map((_: any, ai: number) => this.argEditor(0, ci, ai))}
            <button class="small secondary" @click=${() => {
              const seq = [...this.itemDraft.command_sequence];
              seq[ci] = { ...seq[ci], args: [...seq[ci].args, blankArg()] };
              this.itemDraft = { ...this.itemDraft, command_sequence: seq };
            }}>+ arg</button>
          </div>`)}
        <button class="small secondary" @click=${() => {
          this.itemDraft = { ...this.itemDraft, command_sequence: [...this.itemDraft.command_sequence, blankStep()] };
        }}>+ step</button>

        <div class="toolbar" style="margin-top:.8em">
          <button @click=${this.saveItem}>stage item</button>
          <button class="secondary" @click=${() => { this.itemEdit = null; this.itemDraft = null; }}>cancel</button>
        </div>
      </div>`;
  }

  // ---- render ------------------------------------------------------------

  render() {
    return html`
      <h2>Commands
        ${this.isAdmin && !this.editing
          ? html`<button class="small secondary" style="float:right" @click=${this.startEdit}>edit sections</button>`
          : ''}
        ${this.isAdmin && this.editing
          ? html`<button class="small secondary" style="float:right" @click=${() => { this.editing = false; this.drafts = null; this.itemEdit = null; }}>done editing</button>`
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

      ${this.editing && this.drafts
        ? html`
          ${this.drafts.map(
            (s, si) => html`
              <div class="card">
                <div class="toolbar">
                  <b>${s.title || `section ${si}`}</b>
                  <span class="muted">${(s.items ?? []).length} items</span>
                  <span style="flex:1"></span>
                  <button class="small" @click=${() => { this.openItem(si, -1); }}>+ item</button>
                  <button class="small" @click=${() => this.saveSection(si)}>save</button>
                  <button class="small danger" @click=${() => this.deleteSection(si)}>delete</button>
                </div>
                ${(s.items ?? []).map(
                  (it: any, ii: number) => html`
                    <div class="row" style="margin:.35em 0">
                      <span style="flex:1">${it.title}
                        <span class="muted">— ${(it.command_sequence ?? []).map((c: any) => c.program).join(' → ')}</span></span>
                      <button class="small secondary" @click=${() => this.openItem(si, ii)}>edit</button>
                      <button class="small danger" @click=${() => this.deleteItem(si, ii)}>×</button>
                    </div>`,
                )}
                ${!s.items?.length ? html`<p class="muted">no items yet</p>` : ''}
              </div>`,
          )}
          <div class="card">
            <h3>New section</h3>
            <div class="row">
              <input placeholder="section title" style="flex:1" .value=${this.newSectionTitle}
                @input=${(e: any) => (this.newSectionTitle = e.target.value)}
                @keydown=${(e: any) => e.key === 'Enter' && this.addSection()}>
              <button class="small" @click=${this.addSection}>add section</button>
            </div>
          </div>`
        : ''}

      ${this.itemEdit ? this.itemEditor() : ''}

      <h3>Output</h3>
      <pre class="output log-view">${this.output}</pre>
    `;
  }
}
