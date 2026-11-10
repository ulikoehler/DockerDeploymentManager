import { LitElement, html, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { EditorView } from '@codemirror/view';
import { EditorState } from '@codemirror/state';
import { basicSetup } from 'codemirror';
import { json } from '@codemirror/lang-json';
import { yaml } from '@codemirror/lang-yaml';
import { HighlightStyle, StreamLanguage, syntaxHighlighting } from '@codemirror/language';
import { shell } from '@codemirror/legacy-modes/mode/shell';
import { oneDark } from '@codemirror/theme-one-dark';
import { tags as t } from '@lezer/highlight';
import { sharedStyles } from '../styles';

/** Minimal light theme — GitHub-light-ish palette for when the app is
 *  in light mode. Dark mode uses the stock oneDark theme. */
const lightHighlight = HighlightStyle.define([
  { tag: t.keyword, color: '#cf222e' },
  { tag: [t.string, t.special(t.string), t.regexp], color: '#0a3069' },
  { tag: [t.number, t.bool, t.null], color: '#0550ae' },
  { tag: [t.comment, t.blockComment], color: '#6e7781', fontStyle: 'italic' },
  { tag: [t.variableName, t.propertyName], color: '#953800' },
  { tag: [t.typeName, t.className, t.definition(t.typeName)], color: '#8250df' },
  { tag: [t.operator, t.punctuation], color: '#1f2733' },
  { tag: t.heading, color: '#0550ae', fontWeight: 'bold' },
  { tag: t.link, color: '#0969da', textDecoration: 'underline' },
  { tag: t.emphasis, fontStyle: 'italic' },
  { tag: t.strong, fontWeight: 'bold' },
]);
const lightTheme = EditorView.theme({
  '&': { backgroundColor: '#ffffff', color: '#1f2733' },
  '.cm-content': { caretColor: '#1f2733' },
  '.cm-cursor': { borderLeftColor: '#1f2733' },
  '&.cm-focused .cm-selectionBackground, .cm-selectionBackground': {
    backgroundColor: 'rgba(9, 105, 218, 0.18) !important',
  },
  '.cm-activeLine': { backgroundColor: 'rgba(15, 23, 42, 0.05)' },
  '.cm-gutters': {
    backgroundColor: '#f6f8fa',
    color: '#8a93a3',
    border: 'none',
    borderRight: '1px solid rgba(15,23,42,0.1)',
  },
  '.cm-activeLineGutter': { backgroundColor: 'rgba(15,23,42,0.06)', color: '#1f2733' },
  '.cm-foldPlaceholder': { backgroundColor: 'rgba(15,23,42,0.06)', color: '#5b6472' },
  '.cm-selectionMatch': { backgroundColor: 'rgba(9,105,218,0.12)' },
});

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
  private themeObserver?: MutationObserver;

  private isLight() {
    return document.documentElement.dataset.theme === 'light';
  }

  connectedCallback() {
    super.connectedCallback();
    // Live-switch the editor theme when the app theme toggles.
    this.themeObserver = new MutationObserver(() => this.rebuild());
    this.themeObserver.observe(document.documentElement, {
      attributes: true, attributeFilter: ['data-theme'],
    });
  }

  disconnectedCallback() {
    this.themeObserver?.disconnect();
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
          ...(this.isLight()
            ? [lightTheme, syntaxHighlighting(lightHighlight)]
            : [oneDark]),
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
    return html`<div id="ed" style="border:1px solid var(--glass-border,#333);border-radius:10px;overflow:hidden"></div>`;
  }
}
