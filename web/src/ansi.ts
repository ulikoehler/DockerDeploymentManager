/**
 * Minimal ANSI SGR → HTML renderer for log/exec output.
 * Handles the common subset: colors (30-37, 90-97, 38;5;n, 38;2;r;g;b),
 * bold/dim/italic/underline, reset. Everything else is stripped so raw
 * escape bytes never reach the DOM. All text is HTML-escaped — only the
 * spans we generate carry styling, so the result is safe for unsafeHTML.
 */

const FG: Record<number, string> = {
  30: '#6b7280', 31: '#f87171', 32: '#4ade80', 33: '#fbbf24',
  34: '#60a5fa', 35: '#c084fc', 36: '#22d3ee', 37: '#e5e7eb',
  90: '#6b7280', 91: '#fca5a5', 92: '#86efac', 93: '#fde68a',
  94: '#93c5fd', 95: '#d8b4fe', 96: '#67e8f9', 97: '#ffffff',
};

interface Style {
  color?: string;
  bg?: string;
  bold?: boolean;
  dim?: boolean;
  italic?: boolean;
  underline?: boolean;
}

function xterm256(n: number): string {
  if (n < 16) return FG[n] ?? '';
  if (n < 232) {
    const i = n - 16;
    const r = Math.floor(i / 36), g = Math.floor((i % 36) / 6), b = i % 6;
    const c = (v: number) => (v === 0 ? 0 : 55 + v * 40);
    return `rgb(${c(r)},${c(g)},${c(b)})`;
  }
  const g = 8 + (n - 232) * 10;
  return `rgb(${g},${g},${g})`;
}

function parseSgr(params: number[]): Style {
  const s: Style = {};
  for (let i = 0; i < params.length; i++) {
    const p = params[i];
    if (p === 0) continue; // reset handled by caller
    else if (p === 1) s.bold = true;
    else if (p === 2) s.dim = true;
    else if (p === 3) s.italic = true;
    else if (p === 4) s.underline = true;
    else if (p === 22) { s.bold = false; s.dim = false; }
    else if (p === 23) s.italic = false;
    else if (p === 24) s.underline = false;
    else if ((p >= 30 && p <= 37) || (p >= 90 && p <= 97)) s.color = FG[p];
    else if ((p >= 40 && p <= 47) || (p >= 100 && p <= 107)) {
      s.bg = FG[p >= 100 ? p - 60 : p];
    } else if (p === 39) s.color = undefined;
    else if (p === 49) s.bg = undefined;
    else if (p === 38 || p === 48) {
      const isFg = p === 38;
      const mode = params[i + 1];
      if (mode === 5 && params[i + 2] !== undefined) {
        const c = xterm256(params[i + 2]);
        if (isFg) s.color = c; else s.bg = c;
        i += 2;
      } else if (mode === 2 && params[i + 4] !== undefined) {
        const c = `rgb(${params[i + 2]},${params[i + 3]},${params[i + 4]})`;
        if (isFg) s.color = c; else s.bg = c;
        i += 4;
      }
    }
  }
  return s;
}

function cssText(s: Style): string {
  const parts: string[] = [];
  if (s.color) parts.push(`color:${s.color}`);
  if (s.bg) parts.push(`background:${s.bg}`);
  if (s.bold) parts.push('font-weight:700');
  if (s.dim) parts.push('opacity:.65');
  if (s.italic) parts.push('font-style:italic');
  if (s.underline) parts.push('text-decoration:underline');
  return parts.join(';');
}

const esc = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/**
 * Render a string that may contain ANSI escape sequences into HTML with
 * inline-styled spans. Non-SGR escapes are dropped. Safe for unsafeHTML.
 */
export function ansiToHtml(input: string): string {
  // Drop non-CSI sequences first: OSC (titles/links), charset selects,
  // and stray ESC introducers — none carry style state we render.
  input = input
    .replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g, '')
    .replace(/\u001b[()][0-9A-B]/g, '')
    .replace(/\u001b[=>]/g, '');
  // CSI sequences: ESC [ params intermediates final-byte
  const re = /\u001b\[([0-9;?]*)([ -/]*)([@-~])/g;
  let out = '';
  let last = 0;
  let m: RegExpExecArray | null;
  let cur: Style = {};
  let openCss = '';
  const flushText = (text: string) => {
    if (!text) return;
    out += openCss ? `<span style="${openCss}">${esc(text)}</span>` : esc(text);
  };
  const syncSpan = () => {
    const css = cssText(cur);
    if (css === openCss) return;
    if (openCss) out += '</span>';
    openCss = css;
    if (openCss) out += `<span style="${openCss}">`;
  };
  while ((m = re.exec(input)) !== null) {
    flushText(input.slice(last, m.index));
    last = m.index + m[0].length;
    // Close any open span before mutating state so partial styles can't
    // leak across the boundary — syncSpan re-opens with the merged style.
    if (openCss) { out += '</span>'; openCss = ''; }
    if (m[3] === 'm') {
      const raw = m[1] === '' || m[1] === '?' ? [] : m[1].split(';').map((p) => parseInt(p, 10) || 0);
      if (raw.length === 0 || raw.includes(0)) {
        cur = parseSgr(raw.filter((p) => p !== 0));
      } else {
        cur = { ...cur, ...parseSgr(raw) };
      }
      syncSpan();
    }
    // non-SGR CSI (cursor moves, erases) is dropped, style state persists
    syncSpan();
  }
  flushText(input.slice(last));
  if (openCss) out += '</span>';
  return out;
}

/**
 * Render a unified diff with line-level coloring (git diffs are fetched
 * with --no-color). Safe for unsafeHTML.
 */
export function diffToHtml(diff: string): string {
  return diff
    .split('\n')
    .map((line) => {
      let style = '';
      if (line.startsWith('+++') || line.startsWith('---')) style = 'color:#8b949e';
      else if (line.startsWith('@@')) style = 'color:#79c0ff;font-weight:700';
      else if (line.startsWith('+')) style = 'color:#7ee787;background:rgba(46,160,67,.15)';
      else if (line.startsWith('-')) style = 'color:#ffa198;background:rgba(248,81,73,.15)';
      else if (line.startsWith('diff ') || line.startsWith('index ') || line.startsWith('new file') || line.startsWith('deleted file') || line.startsWith('similarity') || line.startsWith('rename')) style = 'color:#8b949e';
      const e = esc(line);
      return style ? `<span style="${style}">${e}</span>` : e;
    })
    .join('\n');
}
