/* Live log view for the "Local Agent" panel (templates/local_agent.html).
 *
 * No WebSocket/SSE in this app (see static/js/attack-map.js's own
 * comment on that) — this follows the same self-scheduling fetch/poll
 * pattern AttackMap._poll uses: GET, append what's new, setTimeout the
 * next request. The endpoint (GET /api/web/local-agent/log?since=N)
 * is cursor-based, so a normal poll only ever downloads new lines.
 *
 * The panel that hosts this element gets replaced wholesale by htmx
 * every 5s (templates/local_agent.html's outer hx-trigger), but
 * #local-agent-term itself carries hx-preserve so htmx leaves this
 * exact node alone. That means this script only needs to bind once,
 * at page load, no MutationObserver or re-binding on every swap.
 */
(function () {
  'use strict';

  var POLL_MS = 2000;
  var MAX_ROWS = 300;

  var TAG_CLASS = {
    ready: 'bh-term-tag-accent',
    mode: 'bh-term-tag-accent',
    summary: 'bh-term-tag-accent',
    seen: 'bh-term-tag-text',
    would: 'bh-term-tag-danger',
    block: 'bh-term-tag-danger',
    warn: 'bh-term-tag-warning'
  };

  function span(className, text) {
    var el = document.createElement('span');
    el.className = className;
    el.textContent = text;
    return el;
  }

  function init(root) {
    var body = document.getElementById('local-agent-term-body');
    if (!body) return;

    var url = root.getAttribute('data-log-url');
    var cursor = 0;
    var atBottom = true;

    body.addEventListener('scroll', function () {
      atBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 24;
    });

    function appendLine(line) {
      var placeholder = body.querySelector('.bh-term-placeholder');
      if (placeholder) placeholder.parentNode.removeChild(placeholder);

      var time = line.time ? new Date(line.time) : null;
      var timeStr = time && !isNaN(time) ? time.toTimeString().slice(0, 8) : '';
      var tagClass = 'bh-term-tag ' + (TAG_CLASS[line.tag] || 'bh-term-tag-dim');

      var row = document.createElement('div');
      row.className = 'bh-term-row';
      row.appendChild(span('bh-term-time', timeStr));
      row.appendChild(document.createTextNode(' '));
      row.appendChild(span(tagClass, line.tag || ''));
      row.appendChild(document.createTextNode(' '));
      row.appendChild(span('bh-term-msg', line.message || ''));
      body.appendChild(row);

      while (body.children.length > MAX_ROWS) {
        body.removeChild(body.firstChild);
      }
    }

    function poll() {
      var pollUrl = url + (url.indexOf('?') >= 0 ? '&' : '?') + 'since=' + cursor;
      fetch(pollUrl, { credentials: 'same-origin' })
        .then(function (r) { if (!r.ok) throw new Error('bad status ' + r.status); return r.json(); })
        .then(function (resp) {
          var lines = resp.lines || [];
          lines.forEach(appendLine);
          if (typeof resp.cursor === 'number') cursor = resp.cursor;
          if (lines.length && atBottom) body.scrollTop = body.scrollHeight;
        })
        .catch(function () { /* transient network/auth hiccup, retry next tick */ })
        .then(function () { setTimeout(poll, POLL_MS); });
    }

    poll();
  }

  document.addEventListener('DOMContentLoaded', function () {
    var root = document.getElementById('local-agent-term');
    if (root) init(root);
  });
})();
