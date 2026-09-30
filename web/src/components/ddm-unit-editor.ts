import { LitElement, html, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { apiGetUnit, apiPutUnit, apiCheckUnit, apiRegenUnit } from '../api';
import { sharedStyles } from '../styles';

@customElement('ddm-unit-editor')
export class DdmUnitEditor extends LitElement {
  static styles = [
    sharedStyles,
    css`textarea { width: 100%; min-height: 40vh; font-family: ui-monospace, monospace; }`,
  ];

  @property() name = '';
  @property({ attribute: false }) report: any = null;
  @state() private content = '';
  @state() private exists = false;
  @state() private msg = '';
  @state() private check: any = null;

  connectedCallback() {
    super.connectedCallback();
    this.load();
  }

  private async load() {
    try {
      const r: any = await apiGetUnit(this.name);
      this.content = r.content || r.rendered_template || '';
      this.exists = r.exists;
      this.msg = '';
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async runCheck() {
    try {
      this.check = await apiCheckUnit(this.name);
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async save(restart: boolean) {
    try {
      await apiPutUnit(this.name, this.content, restart);
      this.msg = 'saved';
      this.exists = true;
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async regen() {
    try {
      await apiRegenUnit(this.name, true, false);
      this.msg = 'regenerated';
      this.load();
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  render() {
    return html`
      <div class="toolbar">
        <button class="small secondary" @click=${this.runCheck}>check</button>
        <button class="small secondary" @click=${this.regen}>regenerate</button>
        ${!this.exists ? html`<span class="badge warn">unit file missing</span>` : ''}
      </div>
      ${this.check?.issues?.length
        ? html`<ul>${this.check.issues.map(
            (i: any) => html`<li class="error">[${i.code}] ${i.message}</li>`,
          )}</ul>`
        : this.check
          ? html`<p class="ok-text">unit ok</p>`
          : ''}
      <textarea .value=${this.content}
        @input=${(e: any) => (this.content = e.target.value)}
        spellcheck="false"></textarea>
      <div class="toolbar">
        <button @click=${() => this.save(false)}>save</button>
        <button class="secondary" @click=${() => this.save(true)}>save &amp; restart</button>
        <span class="${this.msg.includes('ed') ? 'ok-text' : 'error'}">${this.msg}</span>
      </div>
    `;
  }
}
