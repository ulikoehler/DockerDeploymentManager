import { LitElement, html, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { apiGetCompose, apiPutCompose, apiPolicy } from '../api';
import { sharedStyles } from '../styles';
import './ddm-code-editor';

@customElement('ddm-compose-editor')
export class DdmComposeEditor extends LitElement {
  static styles = [
    sharedStyles,
    
  ];

  @property() name = '';
  @state() private content = '';
  @state() private violations: { path: string; message: string }[] = [];
  @state() private msg = '';
  @state() private policyName = '';

  connectedCallback() {
    super.connectedCallback();
    this.load();
    apiPolicy()
      .then((p: any) => (this.policyName = p?.policy ?? ''))
      .catch(() => {});
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
      // policy rejections need remediation context — the bare violation
      // list doesn't say WHO can change it
      if (/policy violation/i.test(e.message) && this.policyName) {
        this.msg += ` — blocked by compose policy '${this.policyName}'; ` +
          `an admin can change your user's policy under Users → compose policy`;
      }
    }
  }

  render() {
    return html`
      ${this.policyName
        ? html`<p class="muted">enforced compose policy: <b>${this.policyName}</b></p>`
        : ''}
      <ddm-code-editor .value=${this.content} lang="yaml" height="50vh"
        @change=${(e: any) => (this.content = e.detail.value)}></ddm-code-editor>
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
