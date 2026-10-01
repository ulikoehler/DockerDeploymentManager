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
        display: flex; align-items: center; gap: 0.8em; flex-wrap: wrap;
        position: sticky; top: 12px; z-index: 10;
        margin: 12px 14px 4px; padding: 0.55em 1.1em;
        background: rgba(14, 19, 27, 0.62);
        -webkit-backdrop-filter: blur(24px) saturate(160%);
        backdrop-filter: blur(24px) saturate(160%);
        border: 1px solid var(--glass-border);
        border-radius: 16px;
        box-shadow:
          0 10px 32px rgba(0, 0, 0, 0.4),
          inset 0 1px 0 var(--glass-hi);
      }
      header .brand {
        font-weight: 800; letter-spacing: 0.02em; font-size: 1.05em;
        background: linear-gradient(120deg, #8fb0ff, #b48cff 60%, #7dd8f0);
        -webkit-background-clip: text; background-clip: text;
        -webkit-text-fill-color: transparent; color: transparent;
      }
      nav { display: flex; gap: 0.15em; flex-wrap: wrap; }
      nav a {
        color: var(--text-dim); text-decoration: none;
        padding: 0.38em 0.85em; border-radius: 999px;
        font-size: 0.88em; font-weight: 500;
        transition: color .15s ease, background .15s ease, box-shadow .15s ease;
      }
      nav a:hover { color: #fff; background: rgba(255, 255, 255, 0.08); }
      nav a.active {
        color: #fff;
        background: linear-gradient(135deg, rgba(99, 144, 255, 0.9), rgba(139, 92, 246, 0.9));
        box-shadow: 0 4px 14px rgba(88, 116, 246, 0.35), inset 0 1px 0 rgba(255,255,255,0.2);
      }
      main { padding: 0 1.4em 2.5em; }
      .spacer { flex: 1; }
      .user-chip {
        display: inline-flex; align-items: center; gap: 0.45em;
        color: var(--text-dim); font-size: 0.85em;
        padding: 0.25em 0.7em; border-radius: 999px;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.07);
      }
      .user-chip .dot {
        width: 7px; height: 7px; border-radius: 999px;
        background: #6ee7a0; box-shadow: 0 0 8px #6ee7a0aa;
      }
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
        <span class="user-chip"><span class="dot"></span>${this.userName}</span>
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
