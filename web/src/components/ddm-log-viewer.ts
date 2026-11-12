import { LitElement, html, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { unsafeHTML } from 'lit/directives/unsafe-html.js';
import { wsTicketUrl, apiLogs } from '../api';
import { ansiToHtml } from '../ansi';
import { sharedStyles } from '../styles';

interface Line { container: string; service: string; stream: string; text: string }

@customElement('ddm-log-viewer')
export class DdmLogViewer extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .controls input, .controls select { width: 12em; }
      pre.log-view { max-height: 70vh; }
    `,
  ];

  @property() name = '';
  @state() private lines: Line[] = [];
  @state() private follow = true;
  @state() private grep = '';
  @state() private regex = '';
  @state() private stream = '';
  @state() private tail = 200;
  private ws?: WebSocket;
  private wantStream = true;
  private retryDelay = 1000;
  private retryTimer?: number;

  connectedCallback() {
    super.connectedCallback();
    this.startFollow();
  }

  disconnectedCallback() {
    this.wantStream = false;
    clearTimeout(this.retryTimer);
    this.ws?.close();
    super.disconnectedCallback();
  }

  private async loadSnapshot() {
    this.lines = await apiLogs(this.name, {
      tail: this.tail,
      grep: this.grep || undefined,
      regex: this.regex || undefined,
      stream: this.stream || undefined,
    });
  }

  private async download() {
    try {
      const lines: any[] = await apiLogs(this.name, {
        tail: 10000,
        grep: this.grep || undefined,
        regex: this.regex || undefined,
        stream: this.stream || undefined,
      });
      const text = lines.map((l) => l.text ?? '').join('');
      const blob = new Blob([text], { type: 'text/plain' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `${this.name}-logs.txt`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch { /* surfaced via msg-less UI; download is best-effort */ }
  }

  private startFollow() {
    this.wantStream = true;
    this.retryDelay = 1000;
    this.lines = [];
    void this.connect();
  }

  private async connect() {
    this.ws?.close();
    const url = await wsTicketUrl(`/ws/services/${this.name}/logs`, {
      follow: true,
      tail: this.tail,
      grep: this.grep || undefined,
      regex: this.regex || undefined,
      stream: this.stream || undefined,
    });
    this.ws = new WebSocket(url);
    this.ws.onopen = () => { this.retryDelay = 1000; };
    this.ws.onmessage = (ev) => {
      try {
        const l = JSON.parse(ev.data);
        if (l.text !== undefined) {
          this.lines = [...this.lines.slice(-4000), l as Line];
          this.scrollBottom();
        }
      } catch { /* ignore */ }
    };
    this.ws.onclose = () => {
      // auto-reconnect with backoff unless the user hit "stop" or the
      // component was unmounted — transient drops shouldn't kill follow
      if (!this.wantStream || !this.isConnected) return;
      this.retryTimer = setTimeout(() => {
        this.retryDelay = Math.min(this.retryDelay * 2, 30000);
        void this.connect();
      }, this.retryDelay) as unknown as number;
    };
  }

  private scrollBottom() {
    requestAnimationFrame(() => {
      const el = this.shadowRoot?.querySelector('pre');
      if (el && this.follow) el.scrollTop = el.scrollHeight;
    });
  }

  render() {
    return html`
      <div class="controls toolbar">
        <input placeholder="grep…" .value=${this.grep}
          @input=${(e: any) => (this.grep = e.target.value)}>
        <input placeholder="regex…" .value=${this.regex}
          @input=${(e: any) => (this.regex = e.target.value)}>
        <select @change=${(e: any) => (this.stream = e.target.value)}>
          <option value="">all streams</option>
          <option value="stdout">stdout</option>
          <option value="stderr">stderr</option>
        </select>
        <input type="number" style="width:5em" .value=${String(this.tail)}
          @input=${(e: any) => (this.tail = +e.target.value)}>
        <button class="small" @click=${this.loadSnapshot}>snapshot</button>
        <button class="small secondary" @click=${this.download}>download</button>
        <button class="small secondary" @click=${() => { this.follow = true; this.startFollow(); }}>
          follow
        </button>
        <button class="small secondary" @click=${() => { this.follow = false; this.wantStream = false; clearTimeout(this.retryTimer); this.ws?.close(); }}>
          stop
        </button>
      </div>
      <pre class="log-view">${this.lines.map(
        (l) => html`<span class="${l.stream === 'stderr' ? 'log-stderr' : ''}"
          ><span class="muted">[${l.service}]</span> ${unsafeHTML(ansiToHtml(l.text))}</span>`,
      )}</pre>
    `;
  }
}
