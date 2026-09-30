import { LitElement, html, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { apiGetCompose, apiPutCompose } from '../api';
import { sharedStyles } from '../styles';

@customElement('ddm-compose-editor')
export class DdmComposeEditor extends LitElement {
  static styles = [
    sharedStyles,
    css`textarea { width: 100%; min-height: 50vh; font-family: ui-monospace, monospace; }`,
  ];

  @property() name = '';
  @state() private content = '';
  @state() private violations: { path: string; message: string }[] = [];
  @state() private msg = '';

  connectedCallback() {
    super.connectedCallback();
    this.load();
  }

  private async load() {
    try {
      const r: any = await apiGetCompose(this.name);
      this.content = r.content;
      this.violations = r.violations || [];
      this.msg = '';
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async save(recreate: boolean) {
    try {
      await apiPutCompose(this.name, this.content, recreate);
      this.msg = 'saved';
      this.violations = [];
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  render() {
    return html`
      <textarea .value=${this.content}
        @input=${(e: any) => (this.content = e.target.value)}
        spellcheck="false"></textarea>
      ${this.violations.length
        ? html`<ul>${this.violations.map(
            (v) => html`<li class="error">${v.path}: ${v.message}</li>`,
          )}</ul>`
        : ''}
      <div class="toolbar">
        <button @click=${() => this.save(false)}>save</button>
        <button class="secondary" @click=${() => this.save(true)}>save &amp; recreate</button>
        <button class="secondary" @click=${this.load}>reload</button>
        <span class="${this.msg === 'saved' ? 'ok-text' : 'error'}">${this.msg}</span>
      </div>
    `;
  }
}
