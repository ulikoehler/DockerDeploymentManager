import { LitElement, html } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
  apiServiceContainers,
  apiServiceVolumes,
  cfileDownloadUrl,
  apiCfileUpload,
  getToken,
} from '../api';
import { sharedStyles } from '../styles';

interface ContainerRow {
  id: string;
  name: string;
  service: string;
  state: string;
}

@customElement('ddm-cfiles')
export class DdmCfiles extends LitElement {
  static styles = [sharedStyles];

  @property() name = '';
  @state() private kind: 'container' | 'volume' = 'container';
  @state() private containers: ContainerRow[] = [];
  @state() private volumes: string[] = [];
  @state() private target = '';
  @state() private path = '/';
  @state() private dlFormat: 'raw' | 'tar' | 'targz' = 'targz';
  @state() private ulFormat: 'raw' | 'tar' | 'targz' = 'raw';
  @state() private msg = '';
  @state() private busy = false;

  connectedCallback() {
    super.connectedCallback();
    this.refresh();
  }

  private async refresh() {
    this.msg = '';
    try {
      const [cs, vs]: [any, any] = await Promise.all([
        apiServiceContainers(this.name).catch(() => []),
        apiServiceVolumes(this.name).catch(() => []),
      ]);
      this.containers = cs ?? [];
      this.volumes = vs ?? [];
      if (!this.target) {
        this.target = this.kind === 'container'
          ? (this.containers[0]?.id ?? '')
          : (this.volumes[0] ?? '');
      }
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private setKind(k: 'container' | 'volume') {
    this.kind = k;
    this.target = k === 'container'
      ? (this.containers[0]?.id ?? '')
      : (this.volumes[0] ?? '');
  }

  private async download() {
    if (!this.target || this.busy) return;
    this.busy = true;
    this.msg = '';
    try {
      const res = await fetch(
        cfileDownloadUrl(this.name, this.kind, this.target, this.path, this.dlFormat),
        { headers: getToken() ? { Authorization: `Bearer ${getToken()}` } : {} },
      );
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.error || `HTTP ${res.status}`);
      }
      const blob = await res.blob();
      const base = this.path.replace(/\/+$/, '').split('/').pop() || this.target;
      const ext = this.dlFormat === 'raw' ? '' : this.dlFormat === 'tar' ? '.tar' : '.tar.gz';
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `${base}${ext}`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e: any) {
      this.msg = `download failed: ${e.message}`;
    } finally {
      this.busy = false;
    }
  }

  private pickUpload() {
    const input = document.createElement('input');
    input.type = 'file';
    input.onchange = () => {
      const f = input.files?.[0];
      if (f) void this.upload(f);
    };
    input.click();
  }

  private async upload(file: File) {
    if (!this.target || this.busy) return;
    this.busy = true;
    this.msg = '';
    try {
      // raw: file lands at `path` (container: parent dir + basename;
      // volume: exact path). tar/targz: archive extracts into `path` dir.
      const dest = this.ulFormat === 'raw'
        ? this.path
        : this.path;
      await apiCfileUpload(
        this.name, this.kind, this.target, dest, this.ulFormat, await file.arrayBuffer(),
      );
      this.msg = `uploaded ${file.name} (${this.ulFormat})`;
    } catch (e: any) {
      this.msg = `upload failed: ${e.message}`;
    } finally {
      this.busy = false;
    }
  }

  private targetOptions() {
    if (this.kind === 'container') {
      return this.containers.map(
        (c) => html`<option value=${c.id} ?selected=${c.id === this.target}>
          ${c.name || c.id} (${c.state})
        </option>`,
      );
    }
    return this.volumes.map(
      (v) => html`<option value=${v} ?selected=${v === this.target}>${v}</option>`,
    );
  }

  render() {
    const isContainer = this.kind === 'container';
    const pathHint = isContainer
      ? 'absolute path inside the container, e.g. /etc/nginx/nginx.conf or /var/log'
      : 'path inside the volume, e.g. / or /config (empty = volume root)';
    return html`
      <div class="card">
        <h3>Container / volume files</h3>
        <p class="muted" style="margin:.2em 0 .6em">
          Transfer files directly to/from a container filesystem or a named
          volume — no service restart or bind mount needed.
          <b>Download</b>: pick a path; <code>raw</code> for a single file,
          <code>tar</code>/<code>targz</code> for directories or multi-file sets.
          <b>Upload</b>: <code>raw</code> writes one file at the path;
          <code>tar</code>/<code>targz</code> extracts an archive into the path.
        </p>
        <div class="row" style="flex-wrap:wrap;gap:.5em;align-items:center">
          <span class="muted">source:</span>
          <button class="small ${isContainer ? '' : 'secondary'}" @click=${() => this.setKind('container')}>container</button>
          <button class="small ${!isContainer ? '' : 'secondary'}" @click=${() => this.setKind('volume')}>volume</button>
          <select .value=${this.target} @change=${(e: any) => (this.target = e.target.value)}>
            ${this.targetOptions()}
            ${!this.targetOptions().length ? html`<option value="">(none)</option>` : ''}
          </select>
          <button class="small secondary" @click=${this.refresh}>refresh</button>
        </div>
        <div class="row" style="flex-wrap:wrap;gap:.5em;align-items:center;margin-top:.5em">
          <input style="flex:1;min-width:16rem" placeholder=${pathHint}
            .value=${this.path} @input=${(e: any) => (this.path = e.target.value)} />
        </div>
        <div class="row" style="flex-wrap:wrap;gap:.5em;align-items:center;margin-top:.5em">
          <span class="muted">download as</span>
          <select .value=${this.dlFormat} @change=${(e: any) => (this.dlFormat = e.target.value)}>
            <option value="raw">raw file</option>
            <option value="tar">tar</option>
            <option value="targz">tar.gz</option>
          </select>
          <button class="small secondary" ?disabled=${this.busy || !this.target}
            @click=${this.download}>download</button>
          <span style="width:1em"></span>
          <span class="muted">upload as</span>
          <select .value=${this.ulFormat} @change=${(e: any) => (this.ulFormat = e.target.value)}>
            <option value="raw">raw file</option>
            <option value="tar">tar archive</option>
            <option value="targz">tar.gz archive</option>
          </select>
          <button class="small secondary" ?disabled=${this.busy || !this.target}
            @click=${this.pickUpload}>upload…</button>
        </div>
        ${this.msg ? html`<p class="muted" style="margin-top:.5em">${this.msg}</p>` : ''}
      </div>`;
  }
}
