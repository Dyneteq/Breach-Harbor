# Vendored assets

Used by `static/js/attack-map.js` for the animated attack map on the
dashboard and IP address detail pages. Vendored (not CDN-loaded) so the map
keeps working without a third-party script/data dependency at runtime.

## `world-dots.json`

Precomputed list of `[lat, lon]` points for the dot-matrix map mode (the
default). Generated once, offline, from the same 110m world topology as
`world-110m.json` below, by gridding lat/lon space at ~1.8°x2.0° steps and
keeping points that fall on land (`d3.geoContains`). Storing raw lat/lon
(not pre-projected pixel coordinates) lets the frontend project dots with
the same equirectangular math it uses for incident/collector markers, at
whatever canvas size the card renders at.

To regenerate: `npm install d3-geo topojson-client`, then run a script that
loads `world-110m.json`, builds `topojson.feature(topology, topology.objects.land)`,
and for each grid point keeps it if `d3.geoContains(land, [lon, lat])`.

## `d3-array.min.js`, `d3-geo.min.js`, `topojson-client.min.js`, `world-110m.json`

Power the "Real Map" toggle (actual vector country borders instead of dots).
Only injected into the page on first switch to that mode, not loaded eagerly.

- `d3-array` v3, `d3-geo` v3 — Mike Bostock, ISC license. `d3-array` must
  load before `d3-geo` (both attach to the same `window.d3` object; `d3-geo`
  extends what `d3-array` created).
- `topojson-client` v3 — Mike Bostock, ISC license. Attaches to `window.topojson`.
- `world-110m.json` — [world-atlas](https://github.com/topojson/world-atlas)
  (Natural Earth 1:110m data via `us-atlas`/`world-atlas`), ISC license.

Fetched from `cdn.jsdelivr.net/npm/{d3-array,d3-geo,topojson-client}@<major>`
and `cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json`.
