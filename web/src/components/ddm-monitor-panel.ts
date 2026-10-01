import { LitElement, html } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
  apiMonitorStatus,
  apiNotifiers,
  apiNotifierTest,
  apiCreateNotifier,
  apiUpdateNotifier,
  apiDeleteNotifier,
} from '../api';
import { sharedStyles } from '../styles';

const NOTIFIER_TYPES = ['slack_webhook', 'telegram', 'email', 'webhook'] as const;
type NotifierType = (typeof NOTIFIER_TYPES)[number];

interface FieldDef {
  key: string;
  label: string;
  secret?: boolean;
  textarea?: boolean;
  placeholder?: string;
}

const TYPE_FIELDS: Record<NotifierType, FieldDef[]> = {
  slack_webhook: [
    { key: 'url', label: 'webhook URL', secret: true, placeholder: 'https://hooks.slack.com/…' },
    { key: 'url_env', label: '…or env var name', placeholder: 'SLACK_WEBHOOK_URL' },
  ],
  telegram: [
    { key: 'bot_token', label: 'bot token', secret: true },
    { key: 'bot_token_env', label: '…or env var name', placeholder: 'TELEGRAM_BOT_TOKEN' },
    { key: 'chat_id', label: 'chat id' },
  ],
  email: [
    { key: 'smtp_host', label: 'SMTP host' },
    { key: 'smtp_port', label: 'SMTP port', placeholder: '587' },
    { key: 'smtp_tls', label: 'TLS (none/starttls/tls)', placeholder: 'starttls' },
    { key: 'username', label: 'username', secret: true },
    { key: 'password', label: 'password', secret: true },
    { key: 'username_env', label: '…or username env', placeholder: 'SMTP_USER' },
    { key: 'password_env', label: '…or password env', placeholder: 'SMTP_PASS' },
    { key: 'from', label: 'from' },
    { key: 'to', label: 'to (comma separated)' },
  ],
  webhook: [
    { key: 'url', label: 'URL', secret: true, placeholder: 'https://ntfy.example.com/ddm' },
    { key: 'headers', label: 'headers (one k=v per line)', textarea: true },
  ],
};

@customElement('ddm-monitor-panel')
export class DdmMonitorPanel extends LitElement {
  static styles = [sharedStyles];

  @state() private status: Record<string, any> = {};
  @state() private notifiers: any[] = [];
  @state() private msg = '';
  @state() private editing: string | null = null; // notifier id or 'new'
  @state() private form: Record<string, string> = { type: 'slack_webhook' };
  @property({ type: Boolean }) admin = false;
  private timer?: number;

  connectedCallback() {
    super.connectedCallback();
    this.refresh();
    this.timer = window.setInterval(() => this.refresh(), 10000);
  }
  disconnectedCallback() {
    window.clearInterval(this.timer);
    super.disconnectedCallback();
  }

  private async refresh() {
    this.status = await apiMonitorStatus().catch(() => ({}));
    apiNotifiers().then((n: any) => (this.notifiers = n)).catch(() => {});
  }

  private stateBadge(s: string) {
    const cls = s === 'ok' ? 'ok' : s === 'down' || s === 'firing' ? 'err' : 'warn';
    return html`<span class="badge ${cls}">${s}</span>`;
  }

  private startEdit(n?: any) {
    this.editing = n ? (n.id as string) : 'new';
    const f: Record<string, string> = { type: n?.type ?? 'slack_webhook', id: n?.id ?? '' };
    for (const [k, v] of Object.entries(n ?? {})) {
      if (k === 'type' || k === 'id') continue;
      if (v === '***') continue; // secret — leave blank to keep
      if (Array.isArray(v)) f[k] = v.join(', ');
      else if (typeof v === 'object' && v)
        f[k] = Object.entries(v).map(([a, b]) => `${a}=${b}`).join('\n');
      else f[k] = String(v ?? '');
    }
    this.form = f;
  }

  private buildNotifier(): Record<string, unknown> {
    const f = this.form;
    const t = f.type as NotifierType;
    const out: Record<string, unknown> = { type: t, id: f.id.trim() };
    const str = (k: string) => (f[k] ?? '').trim();
    const opt = (k: string) => (str(k) ? str(k) : undefined);
    if (t === 'slack_webhook') {
      if (str('url')) out.url = str('url');
      if (str('url_env')) out.url_env = str('url_env');
    } else if (t === 'telegram') {
      out.chat_id = str('chat_id');
      if (str('bot_token')) out.bot_token = str('bot_token');
      if (str('bot_token_env')) out.bot_token_env = str('bot_token_env');
    } else if (t === 'email') {
      out.smtp_host = str('smtp_host');
      out.smtp_port = Number(str('smtp_port') || '587');
      out.smtp_tls = str('smtp_tls') || 'starttls';
      out.from = str('from');
      out.to = str('to').split(',').map((s) => s.trim()).filter(Boolean);
      for (const k of ['username', 'password', 'username_env', 'password_env']) {
        if (opt(k)) out[k] = opt(k);
      }
    } else {
      out.url = str('url');
      const headers: Record<string, string> = {};
      for (const line of str('headers').split('\n')) {
        const i = line.indexOf('=');
        if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
      }
      out.headers = headers;
    }
    return out;
  }

  private async save() {
    try {
      const body = this.buildNotifier();
      if (!body.id) throw new Error('id required');
      if (this.editing === 'new') await apiCreateNotifier(body);
      else await apiUpdateNotifier(this.editing!, body);
      this.msg = 'saved';
      this.editing = null;
      this.refresh();
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async removeNotifier(id: string) {
    if (!confirm(`Delete notifier '${id}'?`)) return;
    try {
      await apiDeleteNotifier(id);
      this.msg = 'deleted';
      this.refresh();
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private renderForm() {
    const f = this.form;
    const fields = TYPE_FIELDS[f.type as NotifierType] ?? [];
    return html`
      <div class="card">
        <div class="row">
          <input placeholder="id" .value=${f.id ?? ''}
            ?disabled=${this.editing !== 'new'}
            @input=${(e: any) => (this.form = { ...f, id: e.target.value })} />
          <select .value=${f.type} ?disabled=${this.editing !== 'new'}
            @change=${(e: any) => (this.form = { ...f, type: e.target.value })}>
            ${NOTIFIER_TYPES.map((t) => html`<option value=${t}>${t}</option>`)}
          </select>
        </div>
        ${fields.map(
          (fd) => html`<div class="row" style="margin-top:.4em">
            <label class="muted" style="width:14em">${fd.label}</label>
            ${fd.textarea
              ? html`<textarea rows="3" style="flex:1" placeholder=${fd.placeholder ?? ''}
                  .value=${f[fd.key] ?? ''}
                  @input=${(e: any) => (this.form = { ...f, [fd.key]: e.target.value })}></textarea>`
              : html`<input style="flex:1"
                  type=${fd.secret ? 'password' : 'text'}
                  placeholder=${this.editing === 'new' ? fd.placeholder ?? '' : '(unchanged)'}
                  .value=${f[fd.key] ?? ''}
                  @input=${(e: any) => (this.form = { ...f, [fd.key]: e.target.value })} />`}
          </div>`,
        )}
        <div class="row" style="margin-top:.6em">
          <button @click=${this.save}>save</button>
          <button class="secondary" @click=${() => (this.editing = null)}>cancel</button>
          <span class="muted">Secret fields left blank keep their current value.</span>
        </div>
      </div>`;
  }

  render() {
    const entries = Object.entries(this.status);
    return html`
      <h2>Monitoring</h2>
      <div class="card">
        <div class="row">
          <h3>Notifiers</h3>
          ${this.admin && !this.editing
            ? html`<button class="small" @click=${() => this.startEdit()}>add</button>`
            : ''}
        </div>
        ${this.editing ? this.renderForm() : ''}
        ${this.notifiers.length
          ? html`<table><tbody>
              ${this.notifiers.map(
                (n: any) => html`<tr>
                  <td>${n.id || n.type}</td><td class="muted">${n.type}</td>
                  <td class="row">
                    <button class="small secondary" @click=${async () => {
                      try { await apiNotifierTest(n.id, 'test from ddm UI'); this.msg = 'sent'; }
                      catch (e: any) { this.msg = e.message; }
                    }}>test</button>
                    ${this.admin
                      ? html`<button class="small secondary" @click=${() => this.startEdit(n)}>edit</button>
                          <button class="small danger" @click=${() => this.removeNotifier(n.id)}>delete</button>`
                      : ''}
                  </td>
                </tr>`,
              )}
            </tbody></table>`
          : html`<p class="muted">none configured</p>`}
        ${this.msg ? html`<p class="muted">${this.msg}</p>` : ''}
      </div>
      <div class="card">
        <h3>Service checks</h3>
        ${entries.length
          ? html`<table>
              <thead><tr><th>service</th><th>check</th><th>state</th><th>failures</th><th>last match</th></tr></thead>
              <tbody>
                ${entries.flatMap(([svc, st]: [string, any]) =>
                  (st.checks || []).map(
                    (c: any) => html`<tr>
                      <td><a href="#/service/${svc}" style="color:var(--link)">${svc}</a></td>
                      <td class="muted">${c.kind}:${c.id}</td>
                      <td>${this.stateBadge(c.state)}</td>
                      <td>${c.failures}</td>
                      <td class="muted" style="max-width:24em;overflow:hidden;text-overflow:ellipsis">${c.last_match ?? ''}</td>
                    </tr>`,
                  ),
                )}
              </tbody>
            </table>`
          : html`<p class="muted">no checks configured</p>`}
      </div>
    `;
  }
}
