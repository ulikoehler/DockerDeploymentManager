import { LitElement, html } from 'lit';
import { customElement } from 'lit/decorators.js';
import { sharedStyles } from '../styles';

interface Ep { method: string; path: string; desc: string }

const GROUPS: { title: string; eps: Ep[] }[] = [
  {
    title: 'Auth & session',
    eps: [
      { method: 'POST', path: '/api/auth/login', desc: 'username+password → JWT (also sets nothing; token in body)' },
      { method: 'GET', path: '/api/auth/me', desc: 'current user, roles, features' },
      { method: 'POST', path: '/api/auth/token', desc: 'mint a scoped, expiring agent token' },
      { method: 'GET', path: '/api/auth/tokens', desc: 'list minted tokens (user/scope/expiry/state)' },
      { method: 'DELETE', path: '/api/auth/tokens/:jti', desc: 'revoke a minted token' },
      { method: 'POST', path: '/api/auth/logout-all', desc: 'revoke all of the caller\'s tokens' },
      { method: 'POST', path: '/api/auth/ws-ticket', desc: 'single-use WebSocket ticket (prefer over ?token=)' },
      { method: 'GET/POST', path: '/api/setup', desc: 'first-admin bootstrap — open only while zero users exist' },
    ],
  },
  {
    title: 'Services',
    eps: [
      { method: 'GET/POST', path: '/api/services', desc: 'list / create (compose YAML, template, or git)' },
      { method: 'GET/PUT/DELETE', path: '/api/services/:name', desc: 'detail / delete (?down=true)' },
      { method: 'PUT', path: '/api/services/:name/meta', desc: 'update meta.yaml (operator) — agent validates monitoring/backup sub-configs' },
      { method: 'GET/PUT', path: '/api/services/:name/compose', desc: 'compose file — server validates YAML + policy before save' },
      { method: 'POST', path: '/api/services/:name/actions', desc: '{action: up|down|restart|pull|update|enable|disable} → execution_id' },
      { method: 'GET', path: '/api/services/:name/logs', desc: 'log snapshot (?tail=&grep=)' },
      { method: 'POST', path: '/api/services/:name/exec', desc: 'docker exec into a service container' },
      { method: 'POST', path: '/api/containers/:id/exec', desc: 'docker exec into any container' },
      { method: 'GET', path: '/api/services/:name/unit', desc: 'systemd unit content' },
      { method: 'GET', path: '/api/services/:name/unit/check', desc: 'unit drift report' },
      { method: 'POST', path: '/api/services/:name/unit/regenerate', desc: 'rewrite unit from template' },
    ],
  },
  {
    title: 'Files',
    eps: [
      { method: 'GET', path: '/api/services/:name/files?path=', desc: 'list dir or read file (kind: dir|file|binary)' },
      { method: 'PUT', path: '/api/services/:name/files', desc: 'write file {path, content}' },
      { method: 'GET', path: '/api/services/:name/files/download?path=', desc: 'binary-safe download' },
      { method: 'PUT', path: '/api/services/:name/files/upload?path=', desc: 'binary-safe upload (raw body)' },
      { method: 'POST', path: '/api/services/:name/files/mkdir', desc: '{path}' },
      { method: 'POST', path: '/api/services/:name/files/rename', desc: '{from, to}' },
      { method: 'DELETE', path: '/api/services/:name/files?path=', desc: 'delete file/dir' },
      { method: 'ANY', path: '/dav/:service/*', desc: 'WebDAV — Bearer JWT or Basic user:token; needs mount_files feature' },
    ],
  },
  {
    title: 'Backup',
    eps: [
      { method: 'GET/PUT', path: '/api/services/:name/backup', desc: 'per-service backup config (paths/excludes/scheduled)' },
      { method: 'GET', path: '/api/services/:name/backup/check', desc: 'diagnostics: password/script/repo/timer/last run/issues' },
      { method: 'POST', path: '/api/services/:name/backup/provision', desc: 'init repo, password sidecar, systemd timer' },
      { method: 'POST', path: '/api/services/:name/backup/run', desc: 'run backup now → execution_id' },
      { method: 'GET', path: '/api/services/:name/backup/snapshots', desc: 'restic snapshots' },
      { method: 'POST', path: '/api/services/:name/backup/forget', desc: 'restic forget --prune → execution_id' },
      { method: 'POST', path: '/api/services/:name/backup/restore', desc: '{snapshot, target} → execution_id' },
      { method: 'GET/PUT', path: '/api/backup/global', desc: 'admin: enabled, scheduler, on_calendar, excludes, retention (whitelisted)' },
    ],
  },
  {
    title: 'Monitoring & alerts',
    eps: [
      { method: 'GET/PUT', path: '/api/services/:name/monitoring', desc: 'health check + log alerts config' },
      { method: 'POST', path: '/api/services/:name/monitoring/test', desc: 'run check now' },
      { method: 'GET', path: '/api/monitoring/status', desc: 'all services monitor state' },
      { method: 'GET', path: '/api/monitoring/status/:service', desc: 'one service' },
      { method: 'GET', path: '/api/monitoring/events?service=&limit=', desc: 'alert/event history' },
      { method: 'GET/POST', path: '/api/monitoring/notifiers', desc: 'notifier list / create' },
      { method: 'PUT/DELETE', path: '/api/monitoring/notifiers/:id', desc: 'update (secrets merge: "***"=keep) / delete' },
      { method: 'POST', path: '/api/monitoring/notifiers/:id/test', desc: 'send test notification' },
    ],
  },
  {
    title: 'Git',
    eps: [
      { method: 'GET', path: '/api/services/:name/git/repos', desc: 'configured repos' },
      { method: 'GET', path: '/api/services/:name/git/status', desc: 'dirty/branch per repo' },
      { method: 'GET', path: '/api/services/:name/git/log', desc: 'recent log' },
      { method: 'GET', path: '/api/services/:name/git/branches', desc: 'branches' },
      { method: 'GET', path: '/api/services/:name/git/diff', desc: 'unified diff — worktree vs HEAD, or ?base=<ref> for <base>..HEAD' },
      { method: 'POST', path: '/api/services/:name/git/clone', desc: '{url, path?} → execution_id' },
      { method: 'POST', path: '/api/services/:name/git/action', desc: '{repo, action: fetch|pull|checkout}' },
    ],
  },
  {
    title: 'Commands, users, misc',
    eps: [
      { method: 'GET', path: '/api/commands', desc: 'command sections (role-filtered)' },
      { method: 'POST', path: '/api/commands/:section/:item', desc: '{params} → execution_id' },
      { method: 'GET/POST', path: '/api/commands/sections', desc: 'admin: raw sections / {op:add|update|delete}' },
      { method: 'GET/POST/PUT/DELETE', path: '/api/users[/:name]', desc: 'user CRUD (admin)' },
      { method: 'GET', path: '/api/users/:name/effective', desc: 'effective per-service access preview' },
      { method: 'PUT', path: '/api/users/:name/password', desc: 'set password (self needs current_password)' },
      { method: 'PUT', path: '/api/users/:name/access', desc: 'access rules [{effect,service,pattern}]' },
      { method: 'GET', path: '/api/executions[/:id]', desc: 'execution history / detail (owner-scoped, persisted)' },
      { method: 'POST', path: '/api/executions/:id/cancel', desc: 'cancel a running execution (owner/admin; scoped → in-scope services only)' },
      { method: 'GET', path: '/api/audit', desc: 'audit log, newest first (admin)' },
      { method: 'GET', path: '/api/config', desc: 'effective config (secrets redacted)' },
      { method: 'GET', path: '/api/config/status', desc: 'config reload status' },
      { method: 'GET', path: '/api/policy', desc: 'caller\'s effective compose policy' },
      { method: 'GET', path: '/api/templates', desc: 'service templates' },
      { method: 'GET', path: '/api/gitops/status', desc: 'gitops sync state (admin)' },
      { method: 'GET/PUT', path: '/api/gitops/config', desc: 'gitops config — secrets return "***"' },
      { method: 'POST', path: '/api/gitops/sync|push', desc: 'trigger sync / push-back (admin)' },
      { method: 'POST', path: '/api/gitops/webhook', desc: 'inbound webhook (signature-verified)' },
      { method: 'GET', path: '/api/webdav/status', desc: 'webdav enabled/max upload' },
      { method: 'GET', path: '/api/systemd/groups', desc: 'systemd unit groups' },
      { method: 'GET', path: '/api/systemd/units/:unit/logs', desc: 'host unit logs' },
      { method: 'GET', path: '/api/health', desc: 'liveness — unauthenticated' },
    ],
  },
  {
    title: 'WebSockets',
    eps: [
      { method: 'WS', path: '/ws/execute?id=', desc: 'attach to a running execution (replay + live)' },
      { method: 'WS', path: '/ws/executions/:id', desc: 'same, by execution id' },
      { method: 'WS', path: '/ws/services/:name/logs', desc: 'live container logs (follow/grep)' },
      { method: 'WS', path: '/ws/events', desc: 'global monitor/alert event stream' },
    ],
  },
];

@customElement('ddm-api-docs')
export class DdmApiDocs extends LitElement {
  static styles = [sharedStyles];

  render() {
    return html`
      <h2>API reference</h2>
      <p class="muted">all endpoints live under the same origin as this UI. authenticate with
        <code>Authorization: Bearer &lt;jwt&gt;</code> — mint scoped tokens on the
        <a href="#/token">Tokens</a> page. responses are wrapped in
        <code>{"success":true,"data":…}</code>; errors as <code>{"success":false,"error":"…"}</code>.
        scoped tokens can only narrow permissions, never widen them.</p>
      ${GROUPS.map(
        (g) => html`<div class="card">
          <h3>${g.title}</h3>
          <table><tbody>
            ${g.eps.map(
              (e) => html`<tr>
                <td style="width:7em"><code>${e.method}</code></td>
                <td><code>${e.path}</code></td>
                <td class="muted">${e.desc}</td>
              </tr>`,
            )}
          </tbody></table>
        </div>`,
      )}
    `;
  }
}
