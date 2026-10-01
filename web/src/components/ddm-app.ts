import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { getToken, clearToken, apiMe } from '../api';
import { sharedStyles } from '../styles';
import './ddm-login';
import './ddm-service-list';
import './ddm-service-detail';
import './ddm-create';
import './ddm-users';
import './ddm-commands';
import './ddm-monitor-panel';
import './ddm-gitops-panel';
import './ddm-events-view';
import './ddm-token';

type View = { name: string; service?: string };

function parseHash(): View {
  const h = location.hash.replace(/^#\/?/, '');
  const [head, arg] = h.split('/');
  if (head === 'service' && arg) return { name: 'service', service: arg };
  return { name: head || 'services' };
}

@customElement('ddm-app')
export class DdmApp extends LitElement {
  static styles = [
    sharedStyles,
    css`
      header {
        display: flex; align-items: center; gap: 1em;
        padding: 0.6em 1.2em; background: #11151c;
        border-bottom: 1px solid #232a35; position: sticky; top: 0; z-index: 10;
      }
      header .brand { font-weight: 700; color: #60a5fa; }
      nav a { color: #9aa4b2; text-decoration: none; padding: 0.3em 0.7em; border-radius: 6px; }
      nav a.active { color: #fff; background: #1d4ed8; }
      main { padding: 0 1.2em 2em; }
      .spacer { flex: 1; }
    `,
  ];

  @state() private view: View = parseHash();
  @state() private authed = false;
  @state() private userName = '';
  @state() private isAdmin = false;

  private onNav = () => { this.view = parseHash(); };

  connectedCallback() {
    super.connectedCallback();
    window.addEventListener('hashchange', this.onNav);
    if (getToken()) {
      apiMe()
        .then((me: any) => {
          this.authed = true;
          this.userName = me.name;
          this.isAdmin = me.roles?.includes('admin');
        })
        .catch(() => clearToken());
    }
  }

  disconnectedCallback() {
    window.removeEventListener('hashchange', this.onNav);
    super.disconnectedCallback();
  }

  private onLogin(e: CustomEvent) {
    this.authed = true;
    this.userName = e.detail.name;
    this.isAdmin = e.detail.roles?.includes('admin');
  }

  private logout() {
    clearToken();
    this.authed = false;
  }

  private navLink(v: string, label: string) {
    const active = this.view.name === v || (v === 'services' && this.view.name === 'service');
    return html`<a class="${active ? 'active' : ''}" href="#/${v === 'services' ? '' : v}">${label}</a>`;
  }

  render() {
    if (!this.authed) {
      return html`<ddm-login @login=${this.onLogin}></ddm-login>`;
    }
    return html`
      <header>
        <span class="brand">DDM</span>
        <nav>
          ${this.navLink('services', 'Services')}
          ${this.navLink('commands', 'Commands')}
          ${this.navLink('monitor', 'Monitoring')}
          ${this.navLink('events', 'Events')}
          ${this.isAdmin ? this.navLink('users', 'Users') : ''}
          ${this.isAdmin ? this.navLink('gitops', 'GitOps') : ''}
          ${this.navLink('token', 'MCP')}
        </nav>
        <span class="spacer"></span>
        <span class="muted">${this.userName}</span>
        <button class="secondary small" @click=${this.logout}>logout</button>
      </header>
      <main>
        ${this.renderView()}
      </main>
    `;
  }

  private renderView() {
    switch (this.view.name) {
      case 'service':
        return html`<ddm-service-detail name=${this.view.service}></ddm-service-detail>`;
      case 'create':
        return html`<ddm-create></ddm-create>`;
      case 'users':
        return this.isAdmin ? html`<ddm-users></ddm-users>` : html`<p class="error">forbidden</p>`;
      case 'commands':
        return html`<ddm-commands></ddm-commands>`;
      case 'monitor':
        return html`<ddm-monitor-panel .admin=${this.isAdmin}></ddm-monitor-panel>`;
      case 'gitops':
        return this.isAdmin
          ? html`<ddm-gitops-panel .admin=${this.isAdmin}></ddm-gitops-panel>`
          : html`<p class="error">forbidden</p>`;
      case 'events':
        return html`<ddm-events-view></ddm-events-view>`;
      case 'token':
        return html`<ddm-token></ddm-token>`;
      default:
        return html`<ddm-service-list></ddm-service-list>`;
    }
  }
}
