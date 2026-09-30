import { css } from 'lit';

export const sharedStyles = css`
  :host {
    display: block;
    font-family: system-ui, -apple-system, sans-serif;
    color: #d7dde4;
  }
  * { box-sizing: border-box; }
  h1, h2, h3 { font-weight: 600; margin: 0.4em 0; }
  button {
    background: #2563eb; color: #fff; border: 0; border-radius: 6px;
    padding: 0.4em 0.9em; cursor: pointer; font-size: 0.85em;
  }
  button:hover { background: #1d4ed8; }
  button.danger { background: #b91c1c; }
  button.danger:hover { background: #991b1b; }
  button.secondary { background: #374151; }
  button.secondary:hover { background: #4b5563; }
  button.small { padding: 0.15em 0.6em; font-size: 0.78em; }
  button:disabled { opacity: 0.45; cursor: not-allowed; }
  input, select, textarea {
    background: #1a1f27; color: #d7dde4; border: 1px solid #374151;
    border-radius: 6px; padding: 0.4em 0.6em; font-size: 0.9em;
    font-family: inherit;
  }
  textarea { font-family: ui-monospace, monospace; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: 0.35em 0.6em; border-bottom: 1px solid #232a35; }
  th { color: #9aa4b2; font-size: 0.8em; text-transform: uppercase; }
  .card {
    background: #161b23; border: 1px solid #232a35; border-radius: 8px;
    padding: 1em; margin: 0.6em 0;
  }
  .row { display: flex; gap: 0.5em; align-items: center; flex-wrap: wrap; }
  .badge {
    display: inline-block; padding: 0.1em 0.55em; border-radius: 999px;
    font-size: 0.72em; font-weight: 600;
  }
  .badge.ok { background: #14532d; color: #86efac; }
  .badge.warn { background: #713f12; color: #fde68a; }
  .badge.err { background: #7f1d1d; color: #fca5a5; }
  .badge.muted { background: #1f2937; color: #9ca3af; }
  .muted { color: #8b95a5; font-size: 0.85em; }
  .error { color: #f87171; }
  .ok-text { color: #4ade80; }
  pre {
    background: #0b0e13; border-radius: 6px; padding: 0.7em;
    overflow: auto; font-size: 0.8em; line-height: 1.45;
    font-family: ui-monospace, monospace; max-height: 60vh;
  }
  .log-view { white-space: pre-wrap; word-break: break-all; }
  .log-stderr { color: #fca5a5; }
  .toolbar { display: flex; gap: 0.5em; flex-wrap: wrap; margin: 0.5em 0; }
`;
