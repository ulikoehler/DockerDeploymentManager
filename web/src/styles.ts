import { css } from 'lit';

/**
 * Liquid-glass design tokens shared by every component.
 * Surfaces are translucent + blurred over the body's aurora mesh;
 * everything glass lives here so components stay consistent.
 */
export const sharedStyles = css`
  :host {
    display: block;
    font-family: "Inter", system-ui, -apple-system, "Segoe UI", sans-serif;
    color: #e8edf4;
    --glass-bg: rgba(18, 24, 34, 0.55);
    --glass-bg-deep: rgba(9, 13, 20, 0.55);
    --glass-border: rgba(255, 255, 255, 0.09);
    --glass-hi: rgba(255, 255, 255, 0.07);
    --accent-1: #6390ff;
    --accent-2: #8b5cf6;
    --ring: rgba(124, 156, 255, 0.32);
    --link: #9db8ff;
    --text-dim: #98a3b5;
  }
  * { box-sizing: border-box; }
  h1, h2, h3 { font-weight: 650; margin: 0.4em 0; letter-spacing: -0.01em; }
  a { color: var(--link); }
  ::selection { background: rgba(124, 156, 255, 0.35); }

  /* — controls — */
  button {
    background: linear-gradient(135deg, rgba(99, 144, 255, 0.92), rgba(139, 92, 246, 0.92));
    color: #fff;
    border: 1px solid rgba(255, 255, 255, 0.16);
    border-radius: 10px;
    padding: 0.45em 1em;
    cursor: pointer;
    font-size: 0.85em;
    font-weight: 550;
    font-family: inherit;
    box-shadow:
      0 4px 16px rgba(88, 116, 246, 0.28),
      inset 0 1px 0 rgba(255, 255, 255, 0.18);
    transition: transform 0.12s ease, box-shadow 0.15s ease, filter 0.15s ease;
    -webkit-backdrop-filter: blur(8px);
    backdrop-filter: blur(8px);
  }
  button:hover {
    filter: brightness(1.12);
    transform: translateY(-1px);
    box-shadow:
      0 7px 22px rgba(88, 116, 246, 0.4),
      inset 0 1px 0 rgba(255, 255, 255, 0.22);
  }
  button:active { transform: translateY(0) scale(0.98); }
  button.danger {
    background: linear-gradient(135deg, rgba(239, 68, 68, 0.9), rgba(190, 24, 62, 0.9));
    box-shadow:
      0 4px 16px rgba(239, 68, 68, 0.25),
      inset 0 1px 0 rgba(255, 255, 255, 0.16);
  }
  button.danger:hover { filter: brightness(1.12); box-shadow: 0 7px 22px rgba(239, 68, 68, 0.4); }
  button.secondary {
    background: rgba(255, 255, 255, 0.07);
    border-color: rgba(255, 255, 255, 0.12);
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.07);
  }
  button.secondary:hover { background: rgba(255, 255, 255, 0.13); filter: none; }
  button.small { padding: 0.2em 0.7em; font-size: 0.78em; border-radius: 8px; }
  button:disabled { opacity: 0.45; cursor: not-allowed; transform: none; }
  button:focus-visible,
  input:focus-visible,
  select:focus-visible,
  textarea:focus-visible {
    outline: 2px solid var(--accent-1);
    outline-offset: 1px;
  }

  input, select, textarea {
    background: rgba(9, 13, 20, 0.55);
    color: #e8edf4;
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 10px;
    padding: 0.45em 0.7em;
    font-size: 0.9em;
    font-family: inherit;
    transition: border-color 0.15s ease, box-shadow 0.15s ease, background 0.15s ease;
    box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.25);
  }
  input::placeholder, textarea::placeholder { color: #6b7484; }
  input:focus, select:focus, textarea:focus {
    outline: none;
    border-color: var(--accent-1);
    box-shadow: 0 0 0 3px var(--ring), inset 0 1px 3px rgba(0, 0, 0, 0.25);
    background: rgba(9, 13, 20, 0.7);
  }
  textarea { font-family: ui-monospace, "SF Mono", monospace; }
  select {
    -webkit-appearance: none;
    appearance: none;
    padding-right: 1.8em;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%2398a3b5' fill='none' stroke-width='1.5' stroke-linecap='round'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 0.6em center;
  }
  option { background: #141a24; color: #e8edf4; }
  fieldset {
    border: 1px solid var(--glass-border);
    border-radius: 12px;
    margin: 0.6em 0;
  }
  legend { color: var(--text-dim); font-size: 0.85em; padding: 0 0.4em; }

  /* — surfaces — */
  .card {
    background: var(--glass-bg);
    -webkit-backdrop-filter: blur(24px) saturate(160%);
    backdrop-filter: blur(24px) saturate(160%);
    border: 1px solid var(--glass-border);
    border-radius: 18px;
    box-shadow:
      0 12px 40px rgba(0, 0, 0, 0.38),
      inset 0 1px 0 var(--glass-hi);
    padding: 1.1em 1.25em;
    margin: 0.7em 0;
  }
  .row { display: flex; gap: 0.5em; align-items: center; flex-wrap: wrap; }
  .toolbar { display: flex; gap: 0.5em; flex-wrap: wrap; margin: 0.5em 0; }

  table { border-collapse: collapse; width: 100%; }
  th, td {
    text-align: left;
    padding: 0.45em 0.65em;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  }
  th {
    color: var(--text-dim);
    font-size: 0.72em;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.07em;
  }
  tbody tr { transition: background 0.12s ease; }
  tbody tr:hover { background: rgba(255, 255, 255, 0.04); }
  tr:last-child td { border-bottom: 0; }

  /* — badges / text — */
  .badge {
    display: inline-block;
    padding: 0.14em 0.65em;
    border-radius: 999px;
    font-size: 0.72em;
    font-weight: 600;
    border: 1px solid transparent;
    -webkit-backdrop-filter: blur(6px);
    backdrop-filter: blur(6px);
  }
  .badge.ok   { background: rgba(34, 197, 94, 0.16);  color: #86efac; border-color: rgba(134, 239, 172, 0.28); }
  .badge.warn { background: rgba(245, 158, 11, 0.16); color: #fde68a; border-color: rgba(253, 230, 138, 0.28); }
  .badge.err  { background: rgba(239, 68, 68, 0.18);  color: #fca5a5; border-color: rgba(252, 165, 165, 0.3); }
  .badge.muted{ background: rgba(255, 255, 255, 0.07); color: #9ca3af; border-color: rgba(255, 255, 255, 0.1); }
  .muted { color: var(--text-dim); font-size: 0.85em; }
  .error { color: #fca5a5; }
  .ok-text { color: #6ee7a0; }
  code {
    background: rgba(255, 255, 255, 0.07);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 6px;
    padding: 0.1em 0.4em;
    font-size: 0.88em;
    font-family: ui-monospace, "SF Mono", monospace;
  }

  pre {
    background: var(--glass-bg-deep);
    -webkit-backdrop-filter: blur(14px);
    backdrop-filter: blur(14px);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 12px;
    padding: 0.8em 0.9em;
    overflow: auto;
    font-size: 0.8em;
    line-height: 1.5;
    font-family: ui-monospace, "SF Mono", monospace;
    max-height: 60vh;
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.05);
  }
  .log-view { white-space: pre-wrap; word-break: break-all; }
  .log-stderr { color: #fca5a5; }

  hr { border: 0; border-top: 1px solid rgba(255, 255, 255, 0.07); margin: 1em 0; }
`;
