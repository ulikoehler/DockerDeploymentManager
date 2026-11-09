import { LitElement, html, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { EditorView } from '@codemirror/view';
import { EditorState } from '@codemirror/state';
import { basicSetup } from 'codemirror';
import { json } from '@codemirror/lang-json';
import { yaml } from '@codemirror/lang-yaml';
import { StreamLanguage } from '@codemirror/language';
import { shell } from '@codemirror/legacy-modes/mode/shell';
import { oneDark } from '@codemirror/theme-one-dark';
import { sharedStyles } from '../styles';

export type CodeLang = 'text' | 'json' | 'yaml' | 'shell' | 'markdown';

function langExt(lang: CodeLang) {
  switch (lang) {
    case 'json': return json();
    case 'yaml': return yaml();
    case 'shell': return StreamLanguage.define(shell);
    default: return [];
  }
}

/** CodeMirror 6 editor with syntax highlighting, wrapped for Lit shadow DOM.
 *  `value` is two-way: external sets replace the doc; user edits emit
 *  `change` events carrying the new text. */
@customElement('ddm-code-editor')
export class DdmCodeEditor extends LitElement {
  static styles = [
    sharedStyles,
    // CodeMirror measures its own DOM; the host just needs to be a block.
    css`:host { display: block; }`,
  ];

  @property() value = '';
  @property() lang: CodeLang = 'text';
  @property() readonly = false;
  @property() height = 'auto';
  @property() placeholder = '';
  @state() private ready = false;

  private view?: EditorView;
  private host?: HTMLDivElement;

  connectedCallback() {
    super.connectedCallback();
  }

  disconnectedCallback() {
    this.view?.destroy();
    this.view = undefined;
    super.disconnectedCallback();
  }

  updated(changed: Map<string, unknown>) {
    if (!this.view) return;
    if (changed.has('value') && this.view.state.doc.toString() !== this.value) {
      this.view.dispatch({
        changes: { from: 0, to: this.view.state.doc.length, insert: this.value },
      });
    }
    if (changed.has('readonly') || changed.has('lang')) this.rebuild();
    if (changed.has('height') && this.host) this.host.style.height = this.height;
  }

  private rebuild() {
    this.view?.destroy();
    this.view = undefined;
    this.mount();
  }

  private mount() {
    if (this.view || !this.host) return;
    const parent = this;
    this.view = new EditorView({
      parent: this.host,
      state: EditorState.create({
        doc: this.value,
        extensions: [
          basicSetup,
          oneDark,
          langExt(this.lang),
          EditorView.lineWrapping,
          EditorView.updateListener.of((u) => {
            if (u.docChanged) {
              parent.value = u.state.doc.toString();
              parent.dispatchEvent(new CustomEvent('change', {
                detail: { value: parent.value }, bubbles: true, composed: true,
              }));
            }
          }),
          ...(this.readonly
            ? [EditorView.editable.of(false), EditorState.readOnly.of(true)]
            : []),
        ],
      }),
    });
    this.ready = true;
    if (this.height !== 'auto') this.host.style.height = this.height;
  }

  /** Imperative doc replace — goes through the view so the updateListener
   *  fires and parents receive a normal `change` event. */
  setDoc(v: string) {
    if (!this.view) { this.value = v; return; }
    this.view.dispatch({
      changes: { from: 0, to: this.view.state.doc.length, insert: v },
    });
  }

  firstUpdated() {
    // host div is rendered in shadowRoot; mount after first paint
    this.host = this.renderRoot.querySelector('#ed') as HTMLDivElement;
    this.mount();
  }

  render() {
    return html`<div id="ed" style="border:1px solid var(--border,#333);border-radius:6px;overflow:hidden"></div>`;
  }
}
