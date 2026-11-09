import { LitElement, html } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
  apiFiles,
  apiWriteFile,
  apiMkdir,
  apiRename,
  apiDeleteFile,
  apiUploadFile,
  fileDownloadUrl,
  getToken,
  apiWebdavStatus,
} from '../api';
import { sharedStyles } from '../styles';
import './ddm-code-editor';

interface Entry {
  name: string;
  kind: string;
  size: number;
}

@customElement('ddm-files')
export class DdmFiles extends LitElement {
  static styles = [sharedStyles];

  @property() name = '';
  @state() private path = '';
  @state() private node: any = null;
  @state() private content = '';
  @state() private dirty = false;
  @state() private msg = '';
  @state() private newName = '';
  @state() private webdavEnabled = false;
  @state() private imgUrl: string | null = null;

  connectedCallback() {
    super.connectedCallback();
    this.browse('');
    apiWebdavStatus()
      .then((s: any) => (this.webdavEnabled = !!s?.enabled))
      .catch(() => {});
  }

  private async browse(path: string) {
    try {
      const n: any = await apiFiles(this.name, path);
      this.node = n;
      this.path = n.path ?? path;
      // node kind is a serde variant ("File"/"Dir"/"Binary") — normalize
      // before comparing or every file renders as an empty editor
      this.content = n.kind?.toLowerCase() === 'file' ? n.content : '';
      this.imgUrl = null;
      if (this.isImage(path) && (n.kind?.toLowerCase() === 'file' || n.kind?.toLowerCase() === 'binary')) {
        this.imageUrl().then((u) => { if (u) this.imgUrl = u; });
      }
      this.dirty = false;
      this.msg = '';
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private crumbs() {
    const parts = this.path ? this.path.split('/') : [];
    return html`<span class="row">
      <a href="#" @click=${(e: Event) => { e.preventDefault(); this.browse(''); }}>${this.name}</a>
      ${parts.map((p, i) => {
        const sub = parts.slice(0, i + 1).join('/');
        return html`/ <a href="#" @click=${(e: Event) => { e.preventDefault(); this.browse(sub); }}>${p}</a>`;
      })}
    </span>`;
  }

  private async saveFile() {
    try {
      await apiWriteFile(this.name, this.path, this.content);
      this.dirty = false;
      this.msg = 'saved';
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async mkdir() {
    if (!this.newName) return;
    const p = this.path ? `${this.path}/${this.newName}` : this.newName;
    try {
      await apiMkdir(this.name, p);
      this.newName = '';
      this.browse(this.path);
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async newFile() {
    if (!this.newName) return;
    const p = this.path ? `${this.path}/${this.newName}` : this.newName;
    try {
      await apiWriteFile(this.name, p, '');
      this.newName = '';
      this.browse(p);
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async del(path: string) {
    if (!confirm(`Delete ${path}?`)) return;
    try {
      await apiDeleteFile(this.name, path);
      this.browse(this.path);
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async mv(path: string) {
    const to = prompt('Rename/move to (relative to service dir):', path);
    if (!to || to === path) return;
    try {
      await apiRename(this.name, path, to);
      this.browse(this.path);
    } catch (e: any) {
      this.msg = e.message;
    }
  }

  private async download() {
    // the endpoint needs the bearer header — fetch→blob→object-url
    try {
      const res = await fetch(fileDownloadUrl(this.name, this.path), {
        headers: getToken() ? { Authorization: `Bearer ${getToken()}` } : {},
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = this.path.split('/').pop() || 'download';
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e: any) {
      this.msg = `download failed: ${e.message}`;
    }
  }

  private langFor(path: string): 'json' | 'yaml' | 'shell' | 'text' {
    const ext = (path.split('/').pop() ?? '').split('.').pop()?.toLowerCase() ?? '';
    if (ext === 'json') return 'json';
    if (ext === 'yaml' || ext === 'yml') return 'yaml';
    if (['sh', 'bash', 'zsh', 'ksh'].includes(ext)) return 'shell';
    return 'text';
  }

  private isImage(path: string): boolean {
    return /\.(png|jpe?g|gif|webp|svg|ico|bmp|avif)$/i.test(path);
  }

  private async imageUrl(): Promise<string | null> {
    try {
      const res = await fetch(fileDownloadUrl(this.name, this.path), {
        headers: getToken() ? { Authorization: `Bearer ${getToken()}` } : {},
      });
      if (!res.ok) return null;
      return URL.createObjectURL(await res.blob());
    } catch { return null; }
  }

  private async upload(file: File) {
    // dir view → upload into it; file view → replace the open file
    const target = this.node?.kind?.toLowerCase() === 'file'
      ? this.path
      : this.path ? `${this.path}/${file.name}` : file.name;
    try {
      await apiUploadFile(this.name, target, await file.arrayBuffer());
      this.msg = `uploaded ${target}`;
      this.browse(this.path);
    } catch (e: any) {
      this.msg = `upload failed: ${e.message}`;
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

  render() {
    const n = this.node;
    // API node kinds are serde variants ("Dir"/"File"/"Binary") while
    // entry kinds are lowercase — normalize before comparing.
    const kind = n?.kind?.toLowerCase();
    return html`
      <div class="card">
        <div class="row"><h3>Files</h3>${this.crumbs()}</div>
        ${this.webdavEnabled
          ? html`<p class="muted" style="margin:.2em 0 .6em">this service is also reachable via WebDAV at <code>/dav/${this.name}/</code> — mount it in Finder/Files or use any WebDAV client (requires the <code>mount_files</code> feature). Auth: send a JWT as <code>Authorization: Bearer …</code>, or Basic auth with any username and a <a href="#/token">minted token</a> as the password.</p>`
          : ''}
        ${kind === 'dir'
          ? html`
              <table><tbody>
                ${(n.entries as Entry[]).map((e) => {
                  const child = this.path ? `${this.path}/${e.name}` : e.name;
                  return html`<tr>
                    <td>
                      <a href="#" style="color:var(--link);text-decoration:none"
                        @click=${(ev: Event) => { ev.preventDefault(); this.browse(child); }}>
                        ${e.kind === 'dir' ? '📁 ' : ''}${e.name}</a>
                    </td>
                    <td class="muted">${e.kind}</td>
                    <td class="muted">${e.size}</td>
                    <td class="row">
                      <button class="small secondary" @click=${() => this.mv(child)}>rename</button>
                      <button class="small danger" @click=${() => this.del(child)}>delete</button>
                    </td>
                  </tr>`;
                })}
              </tbody></table>
              <div class="row" style="margin-top:.5em">
                <input placeholder="name" .value=${this.newName}
                  @input=${(e: any) => (this.newName = e.target.value)} />
                <button class="small secondary" @click=${this.mkdir}>mkdir</button>
                <button class="small secondary" @click=${this.newFile}>new file</button>
                <button class="small secondary" @click=${this.pickUpload}>upload…</button>
              </div>`
          : html`
              ${this.imgUrl
                ? html`<div class="card" style="text-align:center;padding:.6em">
                    <img src=${this.imgUrl} alt="preview" style="max-width:100%;max-height:60vh;border-radius:6px">
                    <div class="muted" style="margin-top:.3em">image preview — <a href="#" @click=${(e: Event) => { e.preventDefault(); this.imgUrl = null; }}>hide</a></div>
                  </div>`
                : ''}
              ${kind === 'file'
                ? html`
                    <ddm-code-editor .value=${this.content} lang=${this.langFor(this.path)} height="24rem"
                      @change=${(e: any) => { this.content = e.detail.value; this.dirty = true; }}></ddm-code-editor>
                    <div class="row" style="margin-top:.4em">
                      <button ?disabled=${!this.dirty} @click=${this.saveFile}>save</button>
                      <button class="small secondary" @click=${this.download}>download</button>
                      <button class="small secondary" @click=${this.pickUpload}>replace…</button>
                      ${n.truncated ? html`<span class="muted">(file truncated at 512 KiB)</span>` : ''}
                      <span class="muted">${n.size} bytes</span>
                    </div>`
                : html`<div class="row">
                    <p class="muted" style="margin:0">${kind === 'binary' ? `binary file (${n.size} bytes)` : ''}</p>
                    <button class="small secondary" @click=${this.download}>download</button>
                    <button class="small secondary" @click=${this.pickUpload}>replace…</button>
                  </div>`}
              ${this.msg ? html`<p class="muted">${this.msg}</p>` : ''}
            `}
      </div>`;
  }
}
