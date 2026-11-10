/**
 * Promise-based replacements for window.confirm / window.prompt —
 * styled modal dialogs consistent with the app's glass theme.
 * Usage:
 *   if (!(await ddmConfirm('delete it?'))) return;
 *   const v = await ddmPrompt('new password', 'hint');
 *   if (v === null) return; // cancelled
 */

let host: HTMLDivElement | null = null;

function ensureHost(): HTMLDivElement {
  if (!host) {
    host = document.createElement('div');
    host.id = 'ddm-dialog-root';
    const style = document.createElement('style');
    style.textContent = `
      #ddm-dialog-root .backdrop {
        position: fixed; inset: 0; z-index: 9999;
        background: rgba(4, 8, 15, 0.55);
        backdrop-filter: blur(3px);
        display: flex; align-items: center; justify-content: center;
      }
      #ddm-dialog-root .modal {
        background: rgba(18, 24, 34, 0.92);
        border: 1px solid rgba(255,255,255,0.12);
        border-radius: 14px;
        padding: 1.2em 1.4em;
        min-width: 22em; max-width: 34em;
        box-shadow: 0 20px 60px rgba(0,0,0,0.5);
        color: #e8edf4;
        font-family: Inter, system-ui, sans-serif;
      }
      #ddm-dialog-root .modal h3 { margin: 0 0 .5em; font-size: 1em; }
      #ddm-dialog-root .modal p { margin: 0 0 .9em; color: #98a3b5; font-size: .9em; white-space: pre-wrap; }
      #ddm-dialog-root .modal input {
        width: 100%; box-sizing: border-box;
        background: rgba(255,255,255,0.06);
        border: 1px solid rgba(255,255,255,0.14);
        border-radius: 8px; color: #e8edf4;
        padding: .5em .7em; font: inherit; margin-bottom: .9em;
      }
      #ddm-dialog-root .modal input:focus { outline: 2px solid #6390ff66; border-color: #6390ff; }
      #ddm-dialog-root .row { display: flex; gap: .6em; justify-content: flex-end; }
      #ddm-dialog-root button {
        background: linear-gradient(135deg, rgba(99,144,255,.92), rgba(139,92,246,.92));
        color: #fff; border: 1px solid rgba(255,255,255,.16);
        border-radius: 10px; padding: .45em 1.1em; cursor: pointer;
        font: inherit; font-size: .85em; font-weight: 550;
      }
      #ddm-dialog-root button.secondary {
        background: rgba(255,255,255,0.08);
        box-shadow: none;
      }
      #ddm-dialog-root button.danger {
        background: linear-gradient(135deg, rgba(239,68,68,.9), rgba(190,24,62,.9));
      }
    `;
    host.appendChild(style);
    document.body.appendChild(host);
  }
  return host;
}

interface DialogOpts {
  title?: string;
  danger?: boolean;
  placeholder?: string;
  confirmLabel?: string;
  /** When true, resolving gives `input.value` (possibly empty). */
  input?: boolean;
  defaultValue?: string;
}

function open(opts: DialogOpts): Promise<string | null> {
  return new Promise((resolve) => {
    const root = ensureHost();
    root.innerHTML = '';
    const backdrop = document.createElement('div');
    backdrop.className = 'backdrop';
    const modal = document.createElement('div');
    modal.className = 'modal';
    const title = document.createElement('h3');
    title.textContent = opts.title ?? (opts.input ? 'Input' : 'Confirm');
    modal.appendChild(title);
    const p = document.createElement('p');
    p.textContent = opts.placeholder ?? '';
    modal.appendChild(p);
    let input: HTMLInputElement | null = null;
    if (opts.input) {
      input = document.createElement('input');
      input.value = opts.defaultValue ?? '';
      input.spellcheck = false;
      modal.appendChild(input);
    }
    const row = document.createElement('div');
    row.className = 'row';
    const cancel = document.createElement('button');
    cancel.className = 'secondary';
    cancel.textContent = 'cancel';
    const ok = document.createElement('button');
    ok.textContent = opts.confirmLabel ?? 'ok';
    if (opts.danger) ok.className = 'danger';
    row.append(cancel, ok);
    modal.appendChild(row);
    backdrop.appendChild(modal);
    root.appendChild(backdrop);

    const done = (v: string | null) => {
      backdrop.remove();
      resolve(v);
    };
    cancel.onclick = () => done(null);
    backdrop.onclick = (e) => { if (e.target === backdrop) done(null); };
    ok.onclick = () => done(opts.input ? (input?.value ?? '') : 'yes');
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { done(null); document.removeEventListener('keydown', onKey, true); }
      if (e.key === 'Enter' && (!input || document.activeElement === input)) {
        done(opts.input ? (input?.value ?? '') : 'yes');
        document.removeEventListener('keydown', onKey, true);
      }
    };
    document.addEventListener('keydown', onKey, true);
    if (input) {
      input.focus();
      input.select();
    } else {
      ok.focus();
    }
  });
}

/** Styled confirm. Resolves true on accept, false on cancel/backdrop/Esc. */
export function ddmConfirm(message: string, opts: Omit<DialogOpts, 'input'> = {}): Promise<boolean> {
  return open({ ...opts, placeholder: message }).then((v) => v !== null);
}

/** Styled prompt. Resolves the input string, or null on cancel. */
export function ddmPrompt(message: string, defaultValue = '', opts: Omit<DialogOpts, 'input' | 'defaultValue'> = {}): Promise<string | null> {
  return open({ ...opts, input: true, placeholder: message, defaultValue });
}
