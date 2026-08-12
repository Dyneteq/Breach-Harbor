// BREACH::HARBOR — animated attack map.
//
// Hand-rolled canvas component: this app ships no frontend build step (see
// static/js/main.js), so there's no React/chart-lib dependency to reach
// for. Two render modes share one coordinate system:
//
//   - "dots" (default): a precomputed land dot-matrix,
//     static/vendor/world-dots.json ([lat, lon] pairs). Zero extra
//     script/data load.
//   - "vector": real country borders, drawn with d3-geo + topojson-client
//     over static/vendor/world-110m.json. Those vendor files are only
//     injected into the page the first time a user switches to this mode.
//
// Both modes plot points with the same plain equirectangular projection
// (see project() below) — the canvas is always kept at a 2:1 width:height
// ratio, which makes that projection mathematically identical to what
// d3.geoEquirectangular() produces at the matching scale/translate, so
// vector-mode borders and the dot grid / attack arcs stay in alignment.
// See static/vendor/README.md for how world-dots.json was generated.
//
// Two more things this component owns beyond the canvas itself:
//   - An optional sidebar feed list (opts.feedListEl) mirroring every
//     spawned arc as a text row — same event, same moment, so the two
//     panels are always in sync (see _pushFeedRow).
//   - Idle replay: real attack traffic is bursty, and a map that goes
//     dark for minutes between incidents reads as broken, not idle. Once
//     nothing new has landed for IDLE_THRESHOLD_MS, _maybeReplay cycles
//     back through the last MAX_HISTORY real events one at a time,
//     visually dimmed and marked "replay" in the feed, so the map stays
//     alive without ever fabricating new data or piling up arcs.
//   - Preload, then show: the first fetch response can carry a whole
//     backlog of pre-existing incidents. They're placed on the map/feed
//     instantly, all at once (_placeInstant), not trickled in one by one
//     with a flight-arc animation each — that made first paint look
//     stuck/loading for seconds. The animated arc is reserved for
//     incidents that arrive after that point, live (see _handleEvents).
(function () {
  'use strict';

  var MODE_KEY = 'bh-attack-map-mode';
  var VENDOR = '/static/vendor/';
  var PALETTE = {
    dot: 'rgba(148, 188, 227, 0.45)',
    land: 'rgba(47, 127, 224, 0.10)',
    border: 'rgba(148, 188, 227, 0.35)',
    arc: 'rgba(148, 188, 227, 0.55)',
    pulse: '#e05a4f',
    source: '#e05a4f',
    dest: '#2f7fe0',
  };

  // Idle replay: when nothing new has come in for IDLE_THRESHOLD_MS, cycle
  // back through the last MAX_HISTORY real events (one at a time, at most
  // every REPLAY_INTERVAL_MS) instead of leaving the map sitting empty.
  // REPLAY_INTERVAL_MS is well above an arc's own ~2.6s lifetime, so at
  // steady state there's at most one replay arc alive — the map stays
  // "alive" without arcs ever piling up. Replayed arcs are visually dimmed
  // (see PALETTE / _draw's replay fade) and marked in the feed list so
  // replayed history is never mistaken for a brand-new attack.
  var IDLE_THRESHOLD_MS = 6000;
  var REPLAY_INTERVAL_MS = 3500;
  var MAX_HISTORY = 25;
  var MAX_FEED_ROWS = 20;

  function escapeHTML(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  var dotsPromise = null;
  var vectorPromise = null;

  function loadJSON(url) {
    return fetch(url).then(function (r) {
      if (!r.ok) throw new Error('fetch failed: ' + url);
      return r.json();
    });
  }

  function loadScript(src) {
    return new Promise(function (resolve, reject) {
      var el = document.createElement('script');
      el.src = src;
      el.onload = function () { resolve(); };
      el.onerror = function () { reject(new Error('script failed: ' + src)); };
      document.head.appendChild(el);
    });
  }

  function getDots() {
    if (!dotsPromise) dotsPromise = loadJSON(VENDOR + 'world-dots.json');
    return dotsPromise;
  }

  // getVectorLand lazy-loads d3-array -> d3-geo -> topojson-client (order
  // matters: both d3 packages attach to the same window.d3 object, and
  // d3-geo's UMD wrapper expects d3-array's exports to already be there)
  // plus the topology itself, then resolves to the parsed land GeoJSON.
  function getVectorLand() {
    if (!vectorPromise) {
      vectorPromise = loadScript(VENDOR + 'd3-array.min.js')
        .then(function () { return loadScript(VENDOR + 'd3-geo.min.js'); })
        .then(function () { return loadScript(VENDOR + 'topojson-client.min.js'); })
        .then(function () { return loadJSON(VENDOR + 'world-110m.json'); })
        .then(function (topology) {
          return window.topojson.feature(topology, topology.objects.land);
        });
    }
    return vectorPromise;
  }

  // project maps [lat, lon] to canvas pixels under a plain equirectangular
  // projection. Only valid while the canvas is exactly 2:1 (width = 2 *
  // height) — see the file header.
  function project(lat, lon, width, height) {
    return [
      (lon + 180) / 360 * width,
      (90 - lat) / 180 * height,
    ];
  }

  function bezier(p0, p1, p2, t) {
    var u = 1 - t;
    return u * u * p0 + 2 * u * t * p1 + t * t * p2;
  }

  function debounce(fn, ms) {
    var timer;
    return function () {
      clearTimeout(timer);
      var args = arguments;
      timer = setTimeout(function () { fn.apply(null, args); }, ms);
    };
  }

  function sizeCanvas(canvas, width, height) {
    var ratio = window.devicePixelRatio || 1;
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    canvas.style.width = width + 'px';
    canvas.style.height = height + 'px';
    var ctx = canvas.getContext('2d');
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    return ctx;
  }

  function AttackMap(root, opts) {
    this.root = root;
    this.feedUrl = opts.feedUrl;
    this.feedListEl = opts.feedListEl || null;
    this.pollIntervalMs = opts.pollIntervalMs || 6000;
    this.mode = localStorage.getItem(MODE_KEY) === 'vector' ? 'vector' : 'dots';
    this.seen = new Set();
    this.firstLoad = true;
    this.arcs = [];
    this.destMarkers = new Map(); // collector name -> {x, y}
    this.history = []; // bounded ring buffer of real events, for idle replay
    this.historyIdx = 0;
    this.lastRealEventAt = performance.now();
    this.lastReplayAt = 0;
    this.width = 0;
    this.height = 0;
    this.timer = null;
    this.replayTimer = null;
    this.raf = null;

    this._build();
    this._resize();
    this._renderBackground();
    this._loop();
    this._poll();

    var self = this;
    this.replayTimer = setInterval(function () { self._maybeReplay(); }, 1000);

    this._onResize = debounce(function () { self._resize(); self._renderBackground(); }, 200);
    window.addEventListener('resize', this._onResize);
  }

  AttackMap.prototype._build = function () {
    this.root.classList.add('attack-map');
    this.root.innerHTML =
      '<div class="attack-map-toolbar">' +
        '<div class="attack-map-toggle btn-group btn-group-sm" role="group">' +
          '<button type="button" class="btn btn-outline-secondary" data-mode="dots">&#9679; DOTS</button>' +
          '<button type="button" class="btn btn-outline-secondary" data-mode="vector">&#9634; MAP</button>' +
        '</div>' +
        '<div class="attack-map-legend">&nbsp;</div>' +
      '</div>' +
      '<div class="attack-map-canvas-wrap">' +
        '<canvas class="attack-map-bg"></canvas>' +
        '<canvas class="attack-map-fg"></canvas>' +
        '<div class="attack-map-empty">Loading recent activity&hellip;</div>' +
      '</div>';

    this.bg = this.root.querySelector('.attack-map-bg');
    this.fg = this.root.querySelector('.attack-map-fg');
    this.legend = this.root.querySelector('.attack-map-legend');
    this.empty = this.root.querySelector('.attack-map-empty');
    this.wrap = this.root.querySelector('.attack-map-canvas-wrap');

    var self = this;
    var buttons = this.root.querySelectorAll('.attack-map-toggle button');
    buttons.forEach(function (btn) {
      btn.classList.toggle('active', btn.dataset.mode === self.mode);
      btn.addEventListener('click', function () {
        if (btn.dataset.mode === self.mode) return;
        self.mode = btn.dataset.mode;
        localStorage.setItem(MODE_KEY, self.mode);
        buttons.forEach(function (b) { b.classList.toggle('active', b === btn); });
        self._renderBackground();
      });
    });
  };

  AttackMap.prototype._resize = function () {
    var width = Math.round(this.wrap.clientWidth || this.root.clientWidth || 320);
    var height = Math.round(width / 2);
    this.width = width;
    this.height = height;
    this.wrap.style.height = height + 'px';
    this.bgCtx = sizeCanvas(this.bg, width, height);
    this.fgCtx = sizeCanvas(this.fg, width, height);
  };

  AttackMap.prototype._renderBackground = function () {
    var self = this;
    this.bgCtx.clearRect(0, 0, this.width, this.height);

    if (this.mode === 'vector') {
      this.wrap.classList.add('attack-map-loading');
      getVectorLand().then(function (land) {
        self.wrap.classList.remove('attack-map-loading');
        if (self.mode !== 'vector') return; // switched away while loading
        self._drawLand(land);
      }).catch(function () {
        // Vendor assets missing/offline — fall back to dots instead of a
        // blank map.
        self.wrap.classList.remove('attack-map-loading');
        self.mode = 'dots';
        self.root.querySelectorAll('.attack-map-toggle button').forEach(function (b) {
          b.classList.toggle('active', b.dataset.mode === 'dots');
        });
        self._renderBackground();
      });
      return;
    }

    getDots().then(function (dots) {
      if (self.mode !== 'dots') return;
      self._drawDots(dots);
    });
  };

  AttackMap.prototype._drawDots = function (dots) {
    // Circles, not 1.4px squares: at typical dashboard widths the old
    // squares were nearly sub-pixel and the land mass barely read as a
    // map at all. This radius/opacity is the smallest that still holds up
    // at the map's narrower 75%-width column.
    var ctx = this.bgCtx, w = this.width, h = this.height;
    ctx.fillStyle = PALETTE.dot;
    for (var i = 0; i < dots.length; i++) {
      var p = project(dots[i][0], dots[i][1], w, h);
      ctx.beginPath();
      ctx.arc(p[0], p[1], 1.7, 0, Math.PI * 2);
      ctx.fill();
    }
  };

  AttackMap.prototype._drawLand = function (land) {
    var ctx = this.bgCtx, w = this.width, h = this.height;
    var projection = window.d3.geoEquirectangular()
      .scale(w / (2 * Math.PI))
      .translate([w / 2, h / 2]);
    var path = window.d3.geoPath(projection, ctx);
    ctx.beginPath();
    path(land);
    ctx.fillStyle = PALETTE.land;
    ctx.fill();
    ctx.strokeStyle = PALETTE.border;
    ctx.lineWidth = 0.6;
    ctx.stroke();
  };

  AttackMap.prototype._poll = function () {
    var self = this;
    var url = this.feedUrl + (this.feedUrl.indexOf('?') >= 0 ? '&' : '?') + 'limit=40';
    fetch(url, { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('bad status ' + r.status); return r.json(); })
      .then(function (body) { self._handleEvents(body.events || []); })
      .catch(function () { /* transient network/auth hiccup — retry next tick */ })
      .then(function () {
        self.timer = setTimeout(function () { self._poll(); }, self.pollIntervalMs);
      });
  };

  AttackMap.prototype._handleEvents = function (events) {
    var self = this;
    // Oldest first: on the live path, arcs still spawn in chronological
    // order; for the preload path (see below) it just means the legend
    // ends up showing the most recent one, same as before.
    events = events.slice().reverse();
    var fresh = events.filter(function (e) { return !self.seen.has(e.incident_id); });
    fresh.forEach(function (e) { self.seen.add(e.incident_id); });

    if (this.firstLoad) {
      // Preload, then show: this first response can carry a whole backlog
      // (up to the feed's ?limit=40) of pre-existing incidents. Animating
      // each one in with a flight arc, one at a time, made the page look
      // stuck/loading for seconds. Instead: place every marker and feed
      // row instantly, all at once, the moment the data's actually ready.
      // Only incidents that arrive from here on get the animated arc —
      // that's what the arc is for, showing something *new* happening.
      this.firstLoad = false;
      if (!fresh.length) {
        this.empty.textContent = 'No attack data plotted yet';
        return;
      }
      this.lastRealEventAt = performance.now();
      this.empty.style.display = 'none';
      fresh.forEach(function (e) {
        self._pushHistory(e);
        self._placeInstant(e);
      });
      return;
    }

    if (!fresh.length) return;
    this.lastRealEventAt = performance.now();
    this.empty.style.display = 'none';
    fresh.forEach(function (e) {
      self._pushHistory(e);
      self._spawnArc(e, false);
    });
  };

  // _placeInstant is the preload path's "show" step: the destination
  // marker and feed row land immediately, no flight animation — see
  // _handleEvents' firstLoad branch for why.
  AttackMap.prototype._placeInstant = function (e) {
    var d = project(e.dest_lat, e.dest_lon, this.width, this.height);
    this.destMarkers.set(e.collector_name, { x: d[0], y: d[1] });

    var where = e.source_city ? (e.source_city + ', ' + e.source_country) : (e.source_country || e.source_ip);
    this.legend.textContent = (e.incident_type || 'incident').toUpperCase() + ' — ' + where + ' → ' + e.collector_name;

    this._pushFeedRow(e, false);
  };

  // _pushHistory keeps a small, bounded ring buffer of real events for
  // _maybeReplay to cycle through — bounded so a long-running tab never
  // grows this without limit.
  AttackMap.prototype._pushHistory = function (e) {
    this.history.push(e);
    if (this.history.length > MAX_HISTORY) this.history.shift();
  };

  // _maybeReplay keeps the map (and feed) visibly alive through quiet
  // periods by replaying one already-seen event at a time — see
  // IDLE_THRESHOLD_MS/REPLAY_INTERVAL_MS's doc comment for why this can
  // never pile up. A no-op with an empty history (nothing has ever come
  // in yet) or while real events are still arriving.
  AttackMap.prototype._maybeReplay = function () {
    if (!this.history.length) return;
    var now = performance.now();
    if (now - this.lastRealEventAt < IDLE_THRESHOLD_MS) return;
    if (now - this.lastReplayAt < REPLAY_INTERVAL_MS) return;
    this.lastReplayAt = now;
    var e = this.history[this.historyIdx % this.history.length];
    this.historyIdx++;
    this._spawnArc(e, true);
  };

  AttackMap.prototype._spawnArc = function (e, isReplay) {
    var s = project(e.source_lat, e.source_lon, this.width, this.height);
    var d = project(e.dest_lat, e.dest_lon, this.width, this.height);
    this.arcs.push({
      sx: s[0], sy: s[1], dx: d[0], dy: d[1],
      start: performance.now(), duration: 2600,
      replay: !!isReplay,
    });
    this.destMarkers.set(e.collector_name, { x: d[0], y: d[1] });

    var where = e.source_city ? (e.source_city + ', ' + e.source_country) : (e.source_country || e.source_ip);
    var label = (e.incident_type || 'incident').toUpperCase() + ' — ' + where + ' → ' + e.collector_name;
    this.legend.textContent = isReplay ? label + ' (replay)' : label;

    this._pushFeedRow(e, isReplay);
  };

  // _pushFeedRow mirrors every spawned arc (real or replayed) into the
  // sidebar list, if the caller gave us one — same dedup/history source as
  // the canvas, so the two panels are always showing the same events.
  AttackMap.prototype._pushFeedRow = function (e, isReplay) {
    if (!this.feedListEl) return;
    var emptyEl = this.feedListEl.querySelector('.attack-feed-empty');
    if (emptyEl) emptyEl.remove();

    var where = e.source_city ? (e.source_city + ', ' + e.source_country) : (e.source_country || e.source_ip);
    var row = document.createElement('div');
    row.className = 'attack-feed-row' + (isReplay ? ' is-replay' : '');
    row.innerHTML =
      '<div class="attack-feed-row-top">' +
        '<span class="attack-feed-time">' + escapeHTML(new Date().toLocaleTimeString([], { hour12: false })) + '</span>' +
        '<span class="attack-feed-type">' + escapeHTML(e.incident_type || 'incident') + (isReplay ? ' &middot; replay' : '') + '</span>' +
      '</div>' +
      '<div class="attack-feed-route">' + escapeHTML(where) + ' &rarr; ' + escapeHTML(e.collector_name || '') + '</div>';
    this.feedListEl.insertBefore(row, this.feedListEl.firstChild);

    while (this.feedListEl.children.length > MAX_FEED_ROWS) {
      this.feedListEl.removeChild(this.feedListEl.lastChild);
    }
  };

  AttackMap.prototype._loop = function () {
    var self = this;
    this.raf = requestAnimationFrame(function () { self._loop(); });
    this._draw();
  };

  AttackMap.prototype._draw = function () {
    var ctx = this.fgCtx, w = this.width, h = this.height;
    ctx.clearRect(0, 0, w, h);
    var now = performance.now();

    ctx.fillStyle = PALETTE.dest;
    this.destMarkers.forEach(function (m) {
      ctx.fillRect(m.x - 2, m.y - 2, 4, 4);
    });

    this.arcs = this.arcs.filter(function (arc) {
      var t = (now - arc.start) / arc.duration;
      if (t >= 1) return false;

      // Control point offset perpendicular to the source->dest line
      // (scaled to distance, capped) so arcs bow outward instead of
      // cutting straight across the map.
      var mx = (arc.sx + arc.dx) / 2, my = (arc.sy + arc.dy) / 2;
      var dx = arc.dx - arc.sx, dy = arc.dy - arc.sy;
      var dist = Math.sqrt(dx * dx + dy * dy) || 1;
      var cx = mx - (dy / dist) * Math.min(dist * 0.25, 60);
      var cy = my + (dx / dist) * Math.min(dist * 0.25, 60);

      var fade = t < 0.15 ? t / 0.15 : (1 - (t - 0.15) / 0.85);
      fade = Math.max(fade, 0);
      // Replayed history reads as clearly secondary to a live event, never
      // mistaken for a brand-new attack (the feed list marks it too).
      if (arc.replay) fade *= 0.5;

      // Expanding "radar ping" ring at the source point, first 40% of life.
      if (t < 0.4) {
        var ringT = t / 0.4;
        ctx.strokeStyle = PALETTE.source;
        ctx.globalAlpha = (1 - ringT) * 0.8;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(arc.sx, arc.sy, 2 + ringT * 10, 0, Math.PI * 2);
        ctx.stroke();
      }

      ctx.strokeStyle = PALETTE.arc;
      ctx.globalAlpha = fade * 0.8;
      ctx.lineWidth = 1.1;
      ctx.beginPath();
      ctx.moveTo(arc.sx, arc.sy);
      ctx.quadraticCurveTo(cx, cy, arc.dx, arc.dy);
      ctx.stroke();

      // Pulse dot travels along the same curve for the first ~70% of the
      // arc's life; the trail then fades on its own via `fade`.
      var pt = Math.min(t / 0.7, 1);
      ctx.fillStyle = PALETTE.pulse;
      ctx.globalAlpha = fade;
      ctx.beginPath();
      ctx.arc(bezier(arc.sx, cx, arc.dx, pt), bezier(arc.sy, cy, arc.dy, pt), 2.4, 0, Math.PI * 2);
      ctx.fill();

      ctx.globalAlpha = 1;
      return true;
    });
  };

  AttackMap.prototype.destroy = function () {
    if (this.raf) cancelAnimationFrame(this.raf);
    if (this.timer) clearTimeout(this.timer);
    if (this.replayTimer) clearInterval(this.replayTimer);
    window.removeEventListener('resize', this._onResize);
  };

  window.BreachHarbor = window.BreachHarbor || {};
  window.BreachHarbor.AttackMap = {
    init: function (root, opts) {
      if (!root) return null;
      return new AttackMap(root, opts || {});
    },
  };
})();
