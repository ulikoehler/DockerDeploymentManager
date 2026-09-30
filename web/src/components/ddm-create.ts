import { LitElement, html } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { apiCreateService, apiTemplates } from '../api';
import { sharedStyles } from '../styles';

@customElement('ddm-create')
export class DdmCreate extends LitElement {
  static styles = [sharedStyles];

  @state() private name = '';
  @state() private description = '';
  @state() private compose = '';
  @state() private templateId = '';
  @state() private vars: Record<string, string> = {};
  @state() private createUnit = true;
  @state() private enable = true;
  @state() private start = false;
  @state() private templates: any[] = [];
  @state() private msg = '';

  connectedCallback() {
    super.connectedCallback();
    apiTemplates().then((t: any) => (this.templates = t)).catch(() => {});
  }

  private selectedTemplate() {
    return this.templates.find((t) => t.id === this.templateId);
  }

  private async submit() {
    this.msg = '';
    try {
      const body: any = {
        name: this.name,
        description: this.description,
        create_unit: this.createUnit,
        enable: this.enable,
        start: this.start,
      };
      if (this.templateId) {
        body.template_id = this.templateId;
        body.vars = this.vars;
      } else {
        body.compose = this.compose;
      }
      await apiCreateService(body);
      location.hash = '#/service/' + this.name;
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  render() {
    const tpl = this.selectedTemplate();
    return html`
      <div class="card" style="max-width:760px">
        <h2>Create service</h2>
        <div class="row"><input placeholder="service-name" .value=${this.name}
          @input=${(e: any) => (this.name = e.target.value)} required>
        <input placeholder="description" .value=${this.description}
          @input=${(e: any) => (this.description = e.target.value)}></div>

        <h3>Source</h3>
        <select @change=${(e: any) => (this.templateId = e.target.value)}>
          <option value="">raw compose YAML</option>
          ${this.templates.map((t) => html`<option value=${t.id}>${t.title}</option>`)}
        </select>
        ${tpl
          ? html`<p class="muted">${tpl.description}</p>
              ${(tpl.vars || []).map(
                (v: any) => html`<div class="row">
                  <input placeholder="${v.label || v.name}${v.required ? ' *' : ''}"
                    .value=${this.vars[v.name] || v.default || ''}
                    @input=${(e: any) => (this.vars = { ...this.vars, [v.name]: e.target.value })}>
                </div>`,
              )}`
          : html`<textarea style="width:100%;min-height:30vh;font-family:ui-monospace,monospace"
              placeholder="services: …" .value=${this.compose}
              @input=${(e: any) => (this.compose = e.target.value)}></textarea>`}

        <h3>Systemd</h3>
        <label><input type="checkbox" .checked=${this.createUnit}
          @change=${(e: any) => (this.createUnit = e.target.checked)}> create unit</label>
        <label><input type="checkbox" .checked=${this.enable}
          @change=${(e: any) => (this.enable = e.target.checked)}> enable</label>
        <label><input type="checkbox" .checked=${this.start}
          @change=${(e: any) => (this.start = e.target.checked)}> start now</label>

        <div class="toolbar">
          <button @click=${this.submit} ?disabled=${!this.name}>create</button>
          <a href="#/"><button class="secondary">cancel</button></a>
          <span class="error">${this.msg}</span>
        </div>
      </div>
    `;
  }
}
