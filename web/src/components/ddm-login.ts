import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { apiLogin, setToken, ApiError } from '../api';
import { sharedStyles } from '../styles';

@customElement('ddm-login')
export class DdmLogin extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .box { max-width: 340px; margin: 15vh auto; }
      input { width: 100%; margin: 0.3em 0; }
      button { width: 100%; margin-top: 0.6em; }
    `,
  ];

  @state() private error = '';
  @state() private busy = false;

  private async submit(e: Event) {
    e.preventDefault();
    const form = e.target as HTMLFormElement;
    const name = (form.elements.namedItem('name') as HTMLInputElement).value;
    const password = (form.elements.namedItem('password') as HTMLInputElement).value;
    this.busy = true;
    this.error = '';
    try {
      const r = await apiLogin(name, password);
      setToken(r.token);
      this.dispatchEvent(new CustomEvent('login', { detail: r }));
    } catch (err) {
      this.error = err instanceof ApiError ? err.message : 'login failed';
    } finally {
      this.busy = false;
    }
  }

  render() {
    return html`
      <div class="box card">
        <h2>DDM login</h2>
        <form @submit=${this.submit}>
          <input name="name" placeholder="username" autocomplete="username" required>
          <input name="password" type="password" placeholder="password"
                 autocomplete="current-password" required>
          <button ?disabled=${this.busy}>${this.busy ? '…' : 'Login'}</button>
        </form>
        ${this.error ? html`<p class="error">${this.error}</p>` : ''}
      </div>
    `;
  }
}
