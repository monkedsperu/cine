/**
 * Cine simulado — imita la API del cine que usa el bot, para probar vigías y jobs sin tocar el cine real.
 * =========================================================================================================
 * Node.js built-in only (v18+).
 *
 * Endpoints del cine (los mismos que llama server.js):
 *   GET  /                                   home (pone una cookie)
 *   GET  /api/v1-web/bootstrap-data
 *   GET  /api/v1-web/cache/cinemascache
 *   GET  /api/v1-web/cache/moviescache
 *   GET  /api/v1-web/cache/sessioncache
 *   GET  /api/v1-web/seatplan/cinema/:c/session/:s
 *   GET  /api/v1-web/gettickets/cinema/:c/session/:s/usersessionid/:uid
 *   POST /api/v1-web/add-tickets              { encInfo } cifrado AES-256-CBC → { encResponse }
 *
 * Panel de control: /mock  (API en /mock/api/*)
 *
 * La "PELÍCULA DE PRUEBA" empieza como próximo estreno, sin funciones. El botón Habilitar publica sus
 * funciones en los cines elegidos, por etapas configurables como en el cine real: primero aparecen en la
 * cartelera (moviescache), luego su detalle con la hora (sessioncache), y luego el mapa de la sala y las
 * entradas. Las reservas (add-tickets) retienen las butacas por userSessionId durante holdSec segundos.
 *
 * Uso suelto: node mock/mock-cine.js   (MOCK_PORT, por defecto 5200). Con el bot: node mock/run.js
 */

'use strict';

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const MOCK_PORT  = parseInt(process.env.MOCK_PORT) || 5200;
const MOCK_HOST  = process.env.MOCK_HOST || '127.0.0.1';
const STATE_FILE = process.env.MOCK_STATE || path.join(__dirname, '..', 'data-mock', 'mock-state.json');
const AES_KEY    = Buffer.from('23531153594256443940269346428302', 'utf8');   // la misma que server.js

const TEST_MOVIE = { id: 'HO00099001', title: 'PELICULA DE PRUEBA', genre: 'Acción', rating: '+14', runTime: 128 };
const NOW_MOVIE  = { id: 'HO00099002', title: 'PELICULA EN CARTELERA', genre: 'Comedia', rating: 'APT', runTime: 105 };

const CINEMAS = [
  { id: '0000000022', name: 'CP Salaverry',      slug: 'cp-salaverry' },
  { id: '0000000005', name: 'CP Alcazar',        slug: 'cp-alcazar' },
  { id: '0000000013', name: 'CP San Miguel',     slug: 'cp-san-miguel' },
  { id: '0000000031', name: 'CP Primavera',      slug: 'cp-primavera' },
  { id: '0000000044', name: 'CP Santa Clara',    slug: 'cp-santa-clara' },
];
const cinemaName = id => CINEMAS.find(c => c.id === id)?.name || id;

const TICKETS = [
  { TicketTypeCode: '0003', Description: 'General 2D OL',      PriceInCents: 2190 },
  { TicketTypeCode: '0010', Description: 'Niños 2D OL',        PriceInCents: 1790 },
  { TicketTypeCode: '0020', Description: 'Mayores 60 2D OL',   PriceInCents: 1790 },
  { TicketTypeCode: '0050', Description: 'Promo Online 2D',    PriceInCents: 1590 },
];

// ─── SALA ─────────────────────────────────────────────────────────────────────
// Como la envía el cine: vista desde atrás. Rows[0] = última fila (L), Rows[11] = primera (A);
// ColumnIndex 0 = extremo derecho visto desde la pantalla. Bloques 4 | pasillo | 12 | pasillo | 4.
const ROW_NAMES = 'LKJIHGFEDCBA'.split('');
const COLS      = 22;
const AISLES    = new Set([4, 17]);

function seatId(ci) {   // número de butaca: 1 a la izquierda vista desde la pantalla (columna más alta)
  let n = 0;
  for (let c = COLS - 1; c >= ci; c--) if (!AISLES.has(c)) n++;
  return String(n);
}
const isWheelchair = (ri, ci) => ri === ROW_NAMES.length - 1 && (ci === 0 || ci === COLS - 1);
const seatLabel    = (ri, ci) => `${ROW_NAMES[ri]}${seatId(ci)}`;

// ─── ESTADO ───────────────────────────────────────────────────────────────────

const DEFAULT_CFG = {
  holdSec:          480,   // cuánto retiene el cine las butacas de una orden tras cada add-tickets
  reportExpiry:     false, // incluir la hora de vencimiento en la respuesta de add-tickets
  failRate:         0,     // % de add-tickets que responden 502 (como el "VSS" del cine)
  maxPerOrder:      10,    // máximo de entradas que acepta una orden (add-tickets)
  renewMode:        'extends', // reenviar butacas que la orden ya tiene: 'extends' renueva la retención, 'rejects' la rechaza
  detailDelaySec:   15,    // al habilitar: segundos hasta que sessioncache publica la hora
  seatplanDelaySec: 0,     // … hasta que la sala tiene mapa de asientos
  ticketsDelaySec:  0,     // … hasta que hay entradas a la venta
  soldPct:          0,     // % de butacas que nacen vendidas en las funciones de la película de prueba
  times:            '14:20, 16:50, 19:10, 20:30, 22:00',   // horarios de cada día al habilitar
  days:             4,     // días de funciones desde el estreno
  cinemaOffsetMin:  10,    // desfase de horario entre cines (min), para que no todos tengan las mismas horas
  crowdOn:          false, // público comprando: cada crowdEverySec se venden 1–crowdMax butacas en una función al azar
  crowdEverySec:    8,
  crowdMax:         4,
};

let S = load();

function freshState() {
  return {
    cfg: { ...DEFAULT_CFG },
    test: { enabled: false, enabledAt: null, cinemas: [CINEMAS[0].id], openingDate: dayOffset(2) },
    sessions: {},   // key "cinemaId-sessionId" → función
    orders:   {},   // userSessionId → { uid, key, seats: ['ri-ci'], createdAt, updatedAt, expiresAt, adds }
    nextSessionId: 90001,
  };
}

function load() {
  try {
    const s = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    s.cfg = { ...DEFAULT_CFG, ...s.cfg };
    return s;
  } catch { return freshState(); }
}

let saveTimer = null;
function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try {
      fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
      fs.writeFileSync(STATE_FILE + '.tmp', JSON.stringify(S));
      fs.renameSync(STATE_FILE + '.tmp', STATE_FILE);
    } catch (e) { console.error('[mock] no se pudo guardar el estado:', e.message); }
  }, 300);
}

const reqLog = [];   // últimas llamadas a la API del cine (no se guarda)
function log(msg, type = 'info') {
  reqLog.unshift({ at: Date.now(), msg, type });
  if (reqLog.length > 200) reqLog.pop();
}
const stats = { requests: 0, byEndpoint: {} };

// ─── FECHAS (hora de Lima, sin zona como las da el cine) ─────────────────────

function dayOffset(n) {
  return new Date(Date.now() + n * 86400000).toLocaleDateString('en-CA', { timeZone: 'America/Lima' });
}
const limaMs = iso => new Date(iso + '-05:00').getTime();

// ─── FUNCIONES ────────────────────────────────────────────────────────────────

function addSession({ movieId, cinemaId, day, time, screenName, delays = {}, soldPct = 0 }) {
  const sessionId = String(S.nextSessionId++);
  const key = `${cinemaId}-${sessionId}`;
  const now = Date.now();
  S.sessions[key] = {
    key, sessionId, cinemaId, movieId, screenName: screenName || 'SALA 1',
    showtime: `${day}T${time}:00`, formats: '2D', languages: ['DOB'],
    publishedAt: now,
    detailAt:   now + (delays.detail   || 0) * 1000,
    seatplanAt: now + (delays.seatplan || 0) * 1000,
    ticketsAt:  now + (delays.tickets  || 0) * 1000,
    seats: {},   // 'ri-ci' → { kind: 'sold' | 'hold', uid?, at }
  };
  if (soldPct > 0) fillRandom(S.sessions[key], soldPct);
  return S.sessions[key];
}

function allSeatKeys() {
  const out = [];
  for (let ri = 0; ri < ROW_NAMES.length; ri++)
    for (let ci = 0; ci < COLS; ci++) if (!AISLES.has(ci) && !isWheelchair(ri, ci)) out.push(`${ri}-${ci}`);
  return out;
}

function fillRandom(sess, pct) {
  for (const k of allSeatKeys()) if (!sess.seats[k] && Math.random() * 100 < pct) sess.seats[k] = { kind: 'sold', at: Date.now() };
}

// Película en cartelera: hoy y 2 días más en todos los cines, para que el panel normal tenga algo
function ensureNowShowing() {
  const today = dayOffset(0);
  for (const key of Object.keys(S.sessions)) {
    const s = S.sessions[key];
    if (s.movieId === NOW_MOVIE.id && s.showtime.slice(0, 10) < today) deleteSession(key);
  }
  for (let d = 0; d < 3; d++) {
    const day = dayOffset(d);
    for (const [i, c] of CINEMAS.entries()) {
      if (Object.values(S.sessions).some(s => s.movieId === NOW_MOVIE.id && s.cinemaId === c.id && s.showtime.startsWith(day))) continue;
      for (const t of ['15:30', '18:00', '21:15']) {
        addSession({ movieId: NOW_MOVIE.id, cinemaId: c.id, day, time: t, screenName: `SALA ${(i % 6) + 2}`, soldPct: 25 });
      }
    }
  }
  save();
}

function deleteSession(key) {
  delete S.sessions[key];
  for (const [uid, o] of Object.entries(S.orders)) if (o.key === key) delete S.orders[uid];
}

// Horarios configurados: "11:00, 20:30" → ['11:00', '20:30'] (válidos, ordenados, sin repetir)
function parseTimes(txt) {
  const list = String(txt || '').split(/[,;\s]+/).map(t => t.trim()).filter(t => /^([01]?\d|2[0-3]):[0-5]\d$/.test(t))
    .map(t => t.padStart(5, '0'));
  return [...new Set(list)].sort();
}

// Al habilitar: S.cfg.days días desde el estreno, con los horarios de S.cfg.times en cada cine elegido
function enableTestMovie(cinemaIds) {
  disableTestMovie(false);
  const c = S.cfg;
  const delays = { detail: c.detailDelaySec, seatplan: c.seatplanDelaySec, tickets: c.ticketsDelaySec };
  const start = new Date(S.test.openingDate + 'T12:00:00-05:00').getTime();
  let n = 0;
  for (const [ci, cinemaId] of cinemaIds.entries()) {
    for (let d = 0; d < c.days; d++) {
      const day = new Date(start + d * 86400000).toLocaleDateString('en-CA', { timeZone: 'America/Lima' });
      for (const [ti, t] of (parseTimes(c.times).length ? parseTimes(c.times) : ['20:00']).entries()) {
        // Desfase por cine para que no todos tengan las mismas horas
        const [h, m] = t.split(':').map(Number);
        const mins = Math.min(23 * 60 + 59, h * 60 + m + ci * c.cinemaOffsetMin);
        const time = `${String(Math.floor(mins / 60)).padStart(2, '0')}:${String(mins % 60).padStart(2, '0')}`;
        addSession({ movieId: TEST_MOVIE.id, cinemaId, day, time, screenName: `SALA ${(ti % 4) + 1}`, delays, soldPct: c.soldPct });
        n++;
      }
    }
  }
  S.test.enabled = true;
  S.test.enabledAt = Date.now();
  S.test.cinemas = cinemaIds;
  log(`🎬 Película de prueba HABILITADA: ${n} funciones en ${cinemaIds.map(cinemaName).join(', ')} (detalle en ${delays.detail}s, mapa en ${delays.seatplan}s, entradas en ${delays.tickets}s)`, 'success');
  save();
}

function disableTestMovie(logIt = true) {
  for (const key of Object.keys(S.sessions)) if (S.sessions[key].movieId === TEST_MOVIE.id) deleteSession(key);
  S.test.enabled = false;
  S.test.enabledAt = null;
  if (logIt) log('Película de prueba vuelta a "próximamente" (funciones y retenciones borradas)', 'warn');
  save();
}

// ─── RETENCIONES ──────────────────────────────────────────────────────────────

function releaseOrder(uid, why) {
  const o = S.orders[uid];
  if (!o) return;
  const sess = S.sessions[o.key];
  if (sess) for (const k of o.seats) if (sess.seats[k]?.uid === uid) delete sess.seats[k];
  delete S.orders[uid];
  log(`Retención liberada (${why}): ${o.seats.map(k => seatLabel(...k.split('-').map(Number))).join(', ')} · orden ${uid.slice(0, 8)}`, 'warn');
}

function sweep() {
  const now = Date.now();
  let changed = false;
  for (const [uid, o] of Object.entries(S.orders)) if (o.expiresAt <= now) { releaseOrder(uid, 'venció'); changed = true; }
  if (changed) save();
}
setInterval(sweep, 1000).unref();

// Público comprando: vende algunas butacas juntas en una función al azar de la película de prueba
let crowdTimer = null;
function crowdTick() {
  clearTimeout(crowdTimer);
  if (S.cfg.crowdOn) {
    const now = Date.now();
    const list = Object.values(S.sessions).filter(s => s.movieId === TEST_MOVIE.id && s.seatplanAt <= now && s.ticketsAt <= now);
    const sess = list[Math.floor(Math.random() * list.length)];
    if (sess) {
      const want = 1 + Math.floor(Math.random() * Math.max(1, S.cfg.crowdMax));
      // Prefiere el centro de la sala, como la gente
      const free = allSeatKeys().filter(k => !sess.seats[k]).map(k => {
        const [ri, ci] = k.split('-').map(Number);
        return { k, ri, ci, score: Math.abs(ci - COLS / 2) / COLS + Math.abs(ri - 4) / 12 + Math.random() * 0.5 };
      }).sort((a, b) => a.score - b.score);
      const first = free[0];
      if (first) {
        const row = free.filter(x => x.ri === first.ri).sort((a, b) => Math.abs(a.ci - first.ci) - Math.abs(b.ci - first.ci)).slice(0, want);
        for (const x of row) sess.seats[x.k] = { kind: 'sold', at: now };
        log(`👥 Público compró ${row.map(x => seatLabel(x.ri, x.ci)).join(', ')} en ${cinemaName(sess.cinemaId)} ${sess.showtime.slice(5, 16).replace('T', ' ')}`);
        save();
      }
    }
  }
  crowdTimer = setTimeout(crowdTick, Math.max(1, S.cfg.crowdEverySec) * 1000);
  crowdTimer.unref();
}

// ─── RESPUESTAS DEL CINE ──────────────────────────────────────────────────────

function moviesCache() {
  const now = Date.now();
  const build = (m, extra) => {
    const byCinema = {};
    for (const s of Object.values(S.sessions)) {
      if (s.movieId !== m.id || s.publishedAt > now) continue;
      const day = s.showtime.slice(0, 10) + 'T00:00:00';
      const c = byCinema[s.cinemaId] = byCinema[s.cinemaId] || {};
      (c[day] = c[day] || []).push(s);
    }
    return {
      id: m.id, title: m.title, genre: m.genre, ratingDescription: m.rating, runTime: m.runTime,
      posterUrl: '', restricted: false, isNewRelease: false, ...extra,
      cinemas: Object.entries(byCinema).map(([cinemaId, days]) => ({
        cinemaId,
        dates: Object.entries(days).sort().map(([date, list]) => ({
          date, formats: '2D',
          sessions: list.sort((a, b) => a.showtime.localeCompare(b.showtime)).map(s => s.key),
        })),
      })),
    };
  };
  return {
    movies: [
      build(NOW_MOVIE, { OpeningDate: dayOffset(-7) + 'T00:00:00', isPreSale: false, isComingSoon: false }),
      build(TEST_MOVIE, { OpeningDate: S.test.openingDate + 'T00:00:00', isPreSale: S.test.enabled, isComingSoon: !S.test.enabled }),
    ],
    idMoviesBookingRestricted: [],
  };
}

function sessionCache() {
  const now = Date.now();
  return {
    sessions: Object.values(S.sessions).filter(s => s.detailAt <= now).map(s => ({
      id: s.key, sessionId: s.sessionId, cinemaId: s.cinemaId, movieId: s.movieId,
      showtime: s.showtime, screenName: s.screenName, formats: s.formats, languages: s.languages,
    })),
  };
}

function seatPlan(sess) {
  if (!sess || sess.seatplanAt > Date.now()) return { SeatLayoutData: null };
  const rows = ROW_NAMES.map((name, ri) => ({
    PhysicalName: name,
    Seats: [...Array(COLS).keys()].filter(ci => !AISLES.has(ci)).map(ci => {
      const occ = sess.seats[`${ri}-${ci}`];
      return {
        Id: seatId(ci), Position: { AreaNumber: 1, RowIndex: ri, ColumnIndex: ci },
        Status: occ ? (occ.kind === 'hold' ? 5 : 1) : 0,
        SeatStyle: isWheelchair(ri, ci) ? 3 : 0,
      };
    }),
  }));
  return { SeatLayoutData: { Areas: [{ AreaCategoryCode: '0000000001', AreaNumber: 1, Description: 'GENERAL',
    ColumnCount: COLS, RowCount: ROW_NAMES.length, Rows: rows }] } };
}

function encrypt(data) {
  const iv = crypto.randomBytes(16);
  const c  = crypto.createCipheriv('aes-256-cbc', AES_KEY, iv);
  return Buffer.concat([iv, c.update(JSON.stringify(data), 'utf8'), c.final()]).toString('base64');
}
function decrypt(b64) {
  const buf = Buffer.from(b64, 'base64');
  const d   = crypto.createDecipheriv('aes-256-cbc', AES_KEY, buf.subarray(0, 16));
  return JSON.parse(Buffer.concat([d.update(buf.subarray(16)), d.final()]).toString('utf8'));
}

// add-tickets: las entradas se acumulan en la orden del userSessionId; cada reserva renueva el vencimiento
function addTickets(p) {
  const now  = Date.now();
  const key  = `${p.CinemaId}-${p.SessionId}`;
  const sess = S.sessions[key];
  const where = sess ? `${cinemaName(sess.cinemaId)} ${sess.showtime.slice(5, 16).replace('T', ' ')}` : key;
  const fail = (Result, ErrorDescription) => { log(`add-tickets RECHAZADO (${ErrorDescription}) · ${where}`, 'error'); return { Result, ErrorDescription }; };
  if (!sess || sess.seatplanAt > now || sess.ticketsAt > now) return fail(1, 'Sesión no disponible para venta');
  const tt = (p.TicketTypes || [])[0];
  const ticket = TICKETS.find(t => t.TicketTypeCode === tt?.TicketTypeCode);
  if (!ticket) return fail(3, 'Tipo de entrada inválido');
  const uid = String(p.UserSessionId || '');
  if (!uid) return fail(4, 'Falta UserSessionId');

  const wanted = (p.SelectedSeats || []).map(s => `${s.RowIndex}-${s.ColumnIndex}`);
  if (!wanted.length || (tt.Qty && tt.Qty !== wanted.length)) return fail(5, 'Cantidad de entradas y butacas no coincide');
  const already = S.orders[uid]?.key === key ? S.orders[uid].seats.filter(k => !wanted.includes(k)).length : 0;
  if (already + wanted.length > S.cfg.maxPerOrder) return fail(7, `Máximo ${S.cfg.maxPerOrder} entradas por compra`);
  for (const k of wanted) {
    const [ri, ci] = k.split('-').map(Number);
    if (ri < 0 || ri >= ROW_NAMES.length || ci < 0 || ci >= COLS || AISLES.has(ci)) return fail(6, `Butaca inexistente ${k}`);
    const occ = sess.seats[k];
    if (occ && !(occ.kind === 'hold' && occ.uid === uid)) return fail(2, `Butaca ${seatLabel(ri, ci)} no disponible`);
    if (occ && S.cfg.renewMode === 'rejects') return fail(2, `Butaca ${seatLabel(ri, ci)} ya está en la orden`);
  }

  // Orden del uid en otra función: se descarta (el cine abre una orden por función)
  let o = S.orders[uid];
  if (o && o.key !== key) { releaseOrder(uid, 'orden cambiada de función'); o = null; }
  if (!o) o = S.orders[uid] = { uid, key, seats: [], createdAt: now, adds: 0, ticketCode: ticket.TicketTypeCode };
  for (const k of wanted) {
    if (!o.seats.includes(k)) o.seats.push(k);
    sess.seats[k] = { kind: 'hold', uid, at: now };
  }
  o.adds++;
  o.updatedAt = now;
  o.expiresAt = now + S.cfg.holdSec * 1000;
  save();

  const labels = o.seats.map(k => seatLabel(...k.split('-').map(Number)));
  log(`✅ add-tickets OK · ${where} · ${wanted.map(k => seatLabel(...k.split('-').map(Number))).join(', ')} · orden ${uid.slice(0, 8)} (${labels.length} butacas, reserva nº ${o.adds})`, 'success');
  const order = {
    UserSessionId: uid, CinemaId: p.CinemaId, TotalValueCents: ticket.PriceInCents * labels.length,
    Sessions: [{ CinemaId: p.CinemaId, SessionId: p.SessionId, Tickets: labels.map(l => ({ SeatData: l, TicketTypeCode: ticket.TicketTypeCode, PriceCents: ticket.PriceInCents })) }],
  };
  if (S.cfg.reportExpiry) order.ExpiryDateUtc = new Date(o.expiresAt).toISOString();
  return { Result: 0, Order: order };
}

// ─── PANEL DE CONTROL ─────────────────────────────────────────────────────────

function panelState() {
  const now = Date.now();
  const sessions = Object.values(S.sessions).filter(s => s.movieId === TEST_MOVIE.id).map(s => sessionSummary(s, now))
    .sort((a, b) => a.cinemaName.localeCompare(b.cinemaName) || a.showtime.localeCompare(b.showtime));
  const orders = Object.values(S.orders).map(o => {
    const s = S.sessions[o.key];
    return { uid: o.uid, key: o.key, where: s ? `${cinemaName(s.cinemaId)} ${s.showtime.slice(5, 16).replace('T', ' ')} · ${s.movieId === TEST_MOVIE.id ? 'prueba' : 'cartelera'}` : o.key,
             seats: o.seats.map(k => seatLabel(...k.split('-').map(Number))), adds: o.adds, createdAt: o.createdAt, expiresAt: o.expiresAt };
  }).sort((a, b) => a.expiresAt - b.expiresAt);
  return { now, cfg: S.cfg, test: S.test, movie: TEST_MOVIE, cinemas: CINEMAS, sessions, orders, log: reqLog.slice(0, 120), stats,
           botUrl: `http://localhost:${process.env.MOCK_BOT_PORT || 5101}` };
}

function sessionSummary(s, now) {
  let sold = 0, held = 0;
  for (const v of Object.values(s.seats)) v.kind === 'hold' ? held++ : sold++;
  const total = allSeatKeys().length;
  return {
    key: s.key, sessionId: s.sessionId, cinemaId: s.cinemaId, cinemaName: cinemaName(s.cinemaId),
    showtime: s.showtime, screenName: s.screenName,
    detailIn: Math.max(0, s.detailAt - now), seatplanIn: Math.max(0, s.seatplanAt - now), ticketsIn: Math.max(0, s.ticketsAt - now),
    total, sold, held, free: total - sold - held,
  };
}

function seatView(s) {
  const rows = ROW_NAMES.map((name, ri) => ({
    name,
    seats: [...Array(COLS).keys()].map(ci => {
      if (AISLES.has(ci)) return null;
      const occ = s.seats[`${ri}-${ci}`];
      return { ri, ci, label: seatLabel(ri, ci), wc: isWheelchair(ri, ci), kind: occ?.kind || 'free', uid: occ?.uid || null };
    }),
  }));
  return { key: s.key, cols: COLS, rows, summary: sessionSummary(s, Date.now()) };
}

function readBody(req) {
  return new Promise((res, rej) => {
    let d = '';
    req.on('data', c => { d += c; if (d.length > 1e6) req.destroy(); });
    req.on('end', () => { try { res(d ? JSON.parse(d) : {}); } catch { res({}); } });
    req.on('error', rej);
  });
}

function json(res, status, data, headers = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store', ...headers });
  res.end(body);
}

const num = (v, d, min, max) => { const n = Number(v); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : d; };

async function handlePanel(req, res, pathname, method) {
  if (method === 'GET' && (pathname === '/mock' || pathname === '/mock/')) {
    const html = fs.readFileSync(path.join(__dirname, 'panel.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(html);
  }
  if (method === 'GET' && pathname === '/mock/api/state') return json(res, 200, panelState());

  const sm = pathname.match(/^\/mock\/api\/session\/([0-9]+-[0-9]+)$/);
  if (method === 'GET' && sm) {
    const s = S.sessions[sm[1]];
    return s ? json(res, 200, seatView(s)) : json(res, 404, { error: 'Función no encontrada' });
  }
  if (method !== 'POST') return json(res, 404, { error: 'No encontrado' });
  const b = await readBody(req);

  if (pathname === '/mock/api/enable') {
    const ids = (Array.isArray(b.cinemas) ? b.cinemas : []).filter(id => CINEMAS.some(c => c.id === id));
    if (!ids.length) return json(res, 400, { error: 'Elige al menos un cine' });
    enableTestMovie(ids);
    return json(res, 200, { ok: true });
  }
  if (pathname === '/mock/api/disable') { disableTestMovie(); return json(res, 200, { ok: true }); }

  if (pathname === '/mock/api/config') {
    const c = S.cfg;
    if ('holdSec' in b)          c.holdSec          = num(b.holdSec, c.holdSec, 10, 3600);
    if ('reportExpiry' in b)     c.reportExpiry     = !!b.reportExpiry;
    if ('failRate' in b)         c.failRate         = num(b.failRate, c.failRate, 0, 100);
    if ('maxPerOrder' in b)      c.maxPerOrder      = num(b.maxPerOrder, c.maxPerOrder, 1, 100);
    if ('renewMode' in b)        c.renewMode        = b.renewMode === 'rejects' ? 'rejects' : 'extends';
    if ('detailDelaySec' in b)   c.detailDelaySec   = num(b.detailDelaySec, c.detailDelaySec, 0, 3600);
    if ('seatplanDelaySec' in b) c.seatplanDelaySec = num(b.seatplanDelaySec, c.seatplanDelaySec, 0, 3600);
    if ('ticketsDelaySec' in b)  c.ticketsDelaySec  = num(b.ticketsDelaySec, c.ticketsDelaySec, 0, 3600);
    if ('soldPct' in b)          c.soldPct          = num(b.soldPct, c.soldPct, 0, 95);
    if ('times' in b)            c.times            = parseTimes(b.times).join(', ') || c.times;
    if ('days' in b)             c.days             = num(b.days, c.days, 1, 14);
    if ('cinemaOffsetMin' in b)  c.cinemaOffsetMin  = num(b.cinemaOffsetMin, c.cinemaOffsetMin, 0, 120);
    if ('crowdEverySec' in b)    c.crowdEverySec    = num(b.crowdEverySec, c.crowdEverySec, 1, 600);
    if ('crowdMax' in b)         c.crowdMax         = num(b.crowdMax, c.crowdMax, 1, 10);
    if ('crowdOn' in b && c.crowdOn !== !!b.crowdOn) {
      c.crowdOn = !!b.crowdOn;
      log(c.crowdOn ? `👥 Público comprando: cada ${c.crowdEverySec}s, hasta ${c.crowdMax} butacas` : '👥 Público detenido');
      crowdTick();
    }
    if (/^\d{4}-\d{2}-\d{2}$/.test(b.openingDate || '') && !S.test.enabled) S.test.openingDate = b.openingDate;
    save();
    return json(res, 200, { ok: true, cfg: c });
  }

  if (pathname === '/mock/api/add-session') {
    if (!S.test.enabled) return json(res, 400, { error: 'Primero habilita la película' });
    if (!CINEMAS.some(c => c.id === b.cinemaId) || !/^\d{4}-\d{2}-\d{2}$/.test(b.day || '') || !/^([01]\d|2[0-3]):[0-5]\d$/.test(b.time || ''))
      return json(res, 400, { error: 'Cine, fecha u hora inválidos' });
    const c = S.cfg;
    const s = addSession({ movieId: TEST_MOVIE.id, cinemaId: b.cinemaId, day: b.day, time: b.time, screenName: String(b.screenName || 'SALA 5').slice(0, 20),
      delays: { detail: c.detailDelaySec, seatplan: c.seatplanDelaySec, tickets: c.ticketsDelaySec }, soldPct: c.soldPct });
    log(`➕ Función nueva: ${cinemaName(s.cinemaId)} ${s.showtime.slice(5, 16).replace('T', ' ')} (${s.screenName})`, 'success');
    save();
    return json(res, 200, { ok: true, key: s.key });
  }

  const am = pathname.match(/^\/mock\/api\/session\/([0-9]+-[0-9]+)\/(seat|fill|clear|release|delete|publish-now)$/);
  if (am) {
    const s = S.sessions[am[1]];
    if (!s) return json(res, 404, { error: 'Función no encontrada' });
    const action = am[2];
    if (action === 'seat') {   // alterna una butaca: libre ↔ vendida a otra persona; retenida → libera esa orden
      const k = `${parseInt(b.ri)}-${parseInt(b.ci)}`;
      const occ = s.seats[k];
      const lbl = seatLabel(parseInt(b.ri), parseInt(b.ci));
      if (!occ) { s.seats[k] = { kind: 'sold', at: Date.now() }; log(`✋ ${lbl} vendida a otra persona (manual)`); }
      else if (occ.kind === 'sold') { delete s.seats[k]; log(`✋ ${lbl} liberada (manual)`); }
      else releaseOrder(occ.uid, 'manual');
    }
    if (action === 'fill')    { fillRandom(s, num(b.pct, 30, 1, 100)); log(`Función ${s.sessionId}: llenada al azar ~${num(b.pct, 30, 1, 100)}%`); }
    if (action === 'clear')   { for (const [k, v] of Object.entries(s.seats)) if (v.kind === 'sold') delete s.seats[k]; log(`Función ${s.sessionId}: ventas borradas`); }
    if (action === 'release') { for (const o of Object.values(S.orders)) if (o.key === s.key) releaseOrder(o.uid, 'manual'); }
    if (action === 'publish-now') { const n = Date.now(); s.detailAt = Math.min(s.detailAt, n); s.seatplanAt = Math.min(s.seatplanAt, n); s.ticketsAt = Math.min(s.ticketsAt, n); log(`Función ${s.sessionId}: publicada completa`); }
    if (action === 'delete')  { deleteSession(s.key); log(`🗑 Función ${s.sessionId} eliminada (${cinemaName(s.cinemaId)} ${s.showtime.slice(5, 16).replace('T', ' ')})`, 'warn'); }
    save();
    return json(res, 200, { ok: true });
  }

  const om = pathname.match(/^\/mock\/api\/order\/([A-Za-z0-9]+)\/release$/);
  if (om) { releaseOrder(om[1], 'manual'); save(); return json(res, 200, { ok: true }); }

  if (pathname === '/mock/api/reset') {
    const keepCfg = S.cfg;
    S = freshState();
    S.cfg = keepCfg;
    ensureNowShowing();
    log('Estado reiniciado', 'warn');
    return json(res, 200, { ok: true });
  }
  return json(res, 404, { error: 'No encontrado' });
}

// ─── SERVIDOR ─────────────────────────────────────────────────────────────────

function start(port = MOCK_PORT, host = MOCK_HOST) {
  ensureNowShowing();
  setInterval(ensureNowShowing, 3600 * 1000).unref();
  crowdTick();

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname, method = req.method;
    try {
      if (p.startsWith('/mock')) return await handlePanel(req, res, p, method);

      stats.requests++;
      const ep = p.replace(/\/(cinema|session|usersessionid)\/[^/]+/g, '/$1/:x');
      stats.byEndpoint[ep] = (stats.byEndpoint[ep] || 0) + 1;

      if (method === 'GET' && p === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': `mock_visit=${crypto.randomBytes(6).toString('hex')}; Path=/; HttpOnly` });
        return res.end('<p>Cine simulado. Panel de control: <a href="/mock">/mock</a></p>');
      }
      if (p === '/api/v1-web/bootstrap-data') return json(res, 200, { ok: true }, { 'Set-Cookie': 'mock_boot=1; Path=/' });
      if (p === '/api/v1-web/cache/cinemascache') return json(res, 200, CINEMAS.map(c => ({ ID: c.id, name: c.name, formattedCinemaName: c.slug })));
      if (p === '/api/v1-web/cache/moviescache')  return json(res, 200, moviesCache());
      if (p === '/api/v1-web/cache/sessioncache') return json(res, 200, sessionCache());

      let m = p.match(/^\/api\/v1-web\/seatplan\/cinema\/([^/]+)\/session\/([^/]+)$/);
      if (m && method === 'GET') return json(res, 200, seatPlan(S.sessions[`${m[1]}-${m[2]}`]));

      m = p.match(/^\/api\/v1-web\/gettickets\/cinema\/([^/]+)\/session\/([^/]+)\/usersessionid\/([^/]+)$/);
      if (m && method === 'GET') {
        const s = S.sessions[`${m[1]}-${m[2]}`];
        const ready = s && s.ticketsAt <= Date.now();
        return json(res, 200, { ResponseCode: 0, Tickets: ready ? TICKETS : [] });
      }

      if (p === '/api/v1-web/add-tickets' && method === 'POST') {
        const b = await readBody(req);
        let payload;
        try { payload = decrypt(b.encInfo); } catch { return json(res, 400, { error: 'encInfo inválido' }); }
        if (S.cfg.failRate > 0 && Math.random() * 100 < S.cfg.failRate) {
          log('💥 add-tickets: 502 simulado (VSS)', 'error');
          return json(res, 502, { encResponse: encrypt({ Result: 99, ErrorDescription: 'VSS: error de comunicación (simulado)' }) });
        }
        return json(res, 200, { encResponse: encrypt(addTickets(payload)) });
      }

      return json(res, 404, { error: 'No encontrado en el cine simulado' });
    } catch (e) {
      console.error('[mock]', e);
      return json(res, 500, { error: e.message });
    }
  });
  server.listen(port, host, () => console.log(`🎞  Cine simulado → http://${host}:${port}/mock`));
  return server;
}

module.exports = { start, MOCK_PORT };
if (require.main === module) start();
