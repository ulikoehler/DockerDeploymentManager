import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { apiLogin, setToken, ApiError } from '../api';
import { sharedStyles } from '../styles';

@customElement('ddm-login')
export class DdmLogin extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .box {
        max-width: 360px; margin: 16vh auto; padding: 1.8em 1.7em;
        text-align: center;
      }
      .brand {
        font-size: 1.7em; font-weight: 800; letter-spacing: 0.02em;
        background: linear-gradient(120deg, #8fb0ff, #b48cff 60%, #7dd8f0);
        -webkit-background-clip: text; background-clip: text;
        -webkit-text-fill-color: transparent; color: transparent;
        margin: 0 0 0.1em;
      }
      .sub { color: var(--text-dim); font-size: 0.85em; margin: 0 0 1.2em; }
      input { width: 100%; margin: 0.35em 0; text-align: left; }
      button { width: 100%; margin-top: 0.8em; padding: 0.6em 0; font-size: 0.95em; }
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
        <p class="brand">DDM</p>
        <p class="sub">Docker Deployment Manager</p>
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
