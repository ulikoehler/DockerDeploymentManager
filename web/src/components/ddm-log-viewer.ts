import { LitElement, html, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { wsUrl, apiLogs } from '../api';
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

  disconnectedCallback() {
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

  private startFollow() {
    this.ws?.close();
    this.lines = [];
    const url = wsUrl(`/ws/services/${this.name}/logs`, {
      follow: true,
      tail: this.tail,
      grep: this.grep || undefined,
      regex: this.regex || undefined,
      stream: this.stream || undefined,
    });
    this.ws = new WebSocket(url);
    this.ws.onmessage = (ev) => {
      try {
        const l = JSON.parse(ev.data);
        if (l.text !== undefined) {
          this.lines = [...this.lines.slice(-4000), l as Line];
          this.scrollBottom();
        }
      } catch { /* ignore */ }
    };
    this.ws.onclose = () => { this.follow = false; };
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
        <button class="small secondary" @click=${() => { this.follow = true; this.startFollow(); }}>
          follow
        </button>
        <button class="small secondary" @click=${() => { this.follow = false; this.ws?.close(); }}>
          stop
        </button>
      </div>
      <pre class="log-view">${this.lines.map(
        (l) => html`<span class="${l.stream === 'stderr' ? 'log-stderr' : ''}"
          ><span class="muted">[${l.service}]</span> ${l.text}</span>`,
      )}</pre>
    `;
  }
}
