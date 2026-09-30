import { LitElement, html } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
  apiFiles,
  apiWriteFile,
  apiMkdir,
  apiRename,
  apiDeleteFile,
} from '../api';
import { sharedStyles } from '../styles';

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

  connectedCallback() {
    super.connectedCallback();
    this.browse('');
  }

  private async browse(path: string) {
    try {
      const n: any = await apiFiles(this.name, path);
      this.node = n;
      this.path = n.path ?? path;
      this.content = n.kind === 'file' ? n.content : '';
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

  render() {
    const n = this.node;
    return html`
      <div class="card">
        <div class="row"><h3>Files</h3>${this.crumbs()}</div>
        ${n?.kind === 'dir'
          ? html`
              <table><tbody>
                ${(n.entries as Entry[]).map((e) => {
                  const child = this.path ? `${this.path}/${e.name}` : e.name;
                  return html`<tr>
                    <td>
                      <a href="#" style="color:#60a5fa;text-decoration:none"
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
              </div>`
          : n?.kind === 'file'
            ? html`
                <textarea rows="24" style="width:100%" .value=${this.content}
                  @input=${(e: any) => { this.content = e.target.value; this.dirty = true; }}></textarea>
                <div class="row" style="margin-top:.4em">
                  <button ?disabled=${!this.dirty} @click=${this.saveFile}>save</button>
                  ${n.truncated ? html`<span class="muted">(file truncated at 512 KiB)</span>` : ''}
                  <span class="muted">${n.size} bytes</span>
                </div>`
            : html`<p class="muted">${n?.kind === 'binary' ? `binary file (${n.size} bytes)` : ''}</p>`}
        ${this.msg ? html`<p class="muted">${this.msg}</p>` : ''}
      </div>`;
  }
}
