/**
 * Cine Seat Reservation Bot — v3
 * ======================================
 * Node.js built-in only (v18+), sin dependencias npm.
 *
 * - Acceso con contraseña (.env: ADMIN_PASSWORD, APP_PASSWORDS)
 * - Varios jobs de reserva, cada uno con su función, asientos y horario
 * - Jobs, contraseñas creadas en el panel e histórico se guardan en ./data
 *
 * Uso: node server.js   →   http://localhost:5100
 */

'use strict';

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { URL } = require('url');

// ─── .ENV ─────────────────────────────────────────────────────────────────────
// Parser mínimo: KEY=valor por línea, # al inicio = comentario. Las variables ya
// definidas en el entorno tienen prioridad.

function loadEnv(file) {
  if (!fs.existsSync(file)) return;
  for (const raw of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 1) continue;
    const key = line.slice(0, eq).trim();
    let val   = line.slice(eq + 1).trim();
    if (/^(['"]).*\1$/.test(val)) val = val.slice(1, -1);
    if (!(key in process.env)) process.env[key] = val;
  }
}
loadEnv(path.join(__dirname, '.env'));

const PORT              = process.env.PORT || 5100;
const HOST              = process.env.HOST || '0.0.0.0';   // 127.0.0.1 = solo accesible desde la propia máquina (detrás de nginx)
const ADMIN_PASSWORD    = process.env.ADMIN_PASSWORD || '';
const ENV_APP_PASSWORDS = (process.env.APP_PASSWORDS || '').split(',').map(s => s.trim()).filter(Boolean);
const TRUST_PROXY       = process.env.TRUST_PROXY === '1';   // detrás de nginx: usar X-Forwarded-For
const BASE_URL          = (process.env.URL_CINE || '').replace(/\/+$/, '');       // sitio del cine (obligatorio)
const CDN_URL           = (process.env.URL_CINE_CDN || '').replace(/\/+$/, '');   // CDN de pósters (opcional)
const AES_KEY           = Buffer.from('23531153594256443940269346428302', 'utf8'); // 32 bytes → AES-256-CBC
const PUBLIC_DIR        = path.join(__dirname, 'public');
const DATA_DIR          = process.env.DATA_DIR || path.join(__dirname, 'data');

if (!ADMIN_PASSWORD) {
  console.error('❌ Falta ADMIN_PASSWORD en .env (ver .env.example)');
  process.exit(1);
}
if (!/^https?:\/\//.test(BASE_URL)) {
  console.error('❌ Falta URL_CINE en .env (ej. URL_CINE=https://www.sitio-del-cine.com, ver .env.example)');
  process.exit(1);
}

// ─── PERSISTENCIA ─────────────────────────────────────────────────────────────

function readData(name, fallback) {
  try { return JSON.parse(fs.readFileSync(path.join(DATA_DIR, name), 'utf8')); }
  catch { return fallback; }
}

function writeData(name, data) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const file = path.join(DATA_DIR, name);
  fs.writeFileSync(file + '.tmp', JSON.stringify(data, null, 1));
  fs.renameSync(file + '.tmp', file);
}

// ─── CIFRADO / DESCIFRADO ─────────────────────────────────────────────────────

function encrypt(data) {
  const json   = JSON.stringify(data);
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, iv);
  const enc    = Buffer.concat([cipher.update(json, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, enc]).toString('base64');
}

function decrypt(base64) {
  const buf   = Buffer.from(base64, 'base64');
  const iv    = buf.slice(0, 16);
  const ct    = buf.slice(16);
  const dec   = crypto.createDecipheriv('aes-256-cbc', AES_KEY, iv);
  const plain = Buffer.concat([dec.update(ct), dec.final()]);
  return JSON.parse(plain.toString('utf8'));
}

function genSessionId() { return crypto.randomBytes(16).toString('hex'); }

// ─── AUTENTICACIÓN DEL PANEL ──────────────────────────────────────────────────
// Admin: ADMIN_PASSWORD. Usuarios: APP_PASSWORDS del .env + las creadas en el panel,
// menos las revocadas desde el panel (data/auth.json).

const auth = readData('auth.json', { created: [], revoked: [] });
const saveAuth = () => writeData('auth.json', auth);

function appPasswords() {
  const list = [];
  const seen = new Set();
  for (const p of ENV_APP_PASSWORDS) {
    if (auth.revoked.includes(p) || seen.has(p)) continue;
    seen.add(p);
    list.push({ password: p, label: '', source: 'env', createdAt: null });
  }
  for (const c of auth.created) {
    if (seen.has(c.password)) continue;
    seen.add(c.password);
    list.push({ ...c, source: 'panel' });
  }
  return list;
}

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function checkPassword(pw) {
  if (!pw) return null;
  if (safeEqual(pw, ADMIN_PASSWORD)) return { role: 'admin', password: null };
  const match = appPasswords().find(p => safeEqual(pw, p.password));
  return match ? { role: 'user', password: match.password } : null;
}

const SESSION_TTL = 7 * 24 * 3600 * 1000;
const sessions    = new Map();   // token → { role, password, expires }

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) out[part.slice(0, eq).trim()] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return out;
}

function getSession(req) {
  const token = parseCookies(req).cpb_session;
  const s = token && sessions.get(token);
  if (!s) return null;
  // Expirada, o su contraseña fue eliminada → fuera
  if (s.expires < Date.now() || (s.role === 'user' && !appPasswords().some(p => p.password === s.password))) {
    sessions.delete(token);
    return null;
  }
  return s;
}

function sessionCookie(req, token, maxAgeSec) {
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  return `cpb_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${secure}`;
}

// Límite de intentos de login: 10 fallos cada 15 min por IP
const loginFails = new Map();
function clientIp(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return req.headers['x-forwarded-for'].split(',')[0].trim();
  return req.socket.remoteAddress;
}
function loginBlocked(ip) {
  const f = loginFails.get(ip);
  if (!f) return false;
  if (Date.now() - f.first > 15 * 60 * 1000) { loginFails.delete(ip); return false; }
  return f.n >= 10;
}
function loginFailed(ip) {
  const f = loginFails.get(ip);
  if (!f || Date.now() - f.first > 15 * 60 * 1000) loginFails.set(ip, { n: 1, first: Date.now() });
  else f.n++;
}

// ─── COOKIE JAR (cine) ──────────────────────────────────────────────────

class CookieJar {
  constructor() { this._jar = {}; }

  ingest(setCookieArray) {
    if (!setCookieArray) return;
    for (const raw of setCookieArray) {
      const pair = raw.split(';')[0].trim();
      const eq   = pair.indexOf('=');
      if (eq < 0) continue;
      const name  = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (name) this._jar[name] = value;
    }
  }

  header() {
    return Object.entries(this._jar).map(([k, v]) => `${k}=${v}`).join('; ');
  }

  set(name, value) { this._jar[name] = value; }
  replace(obj)     { this._jar = { ...obj }; }
  get(name)        { return this._jar[name]; }
  size()           { return Object.keys(this._jar).length; }
  dump()           { return { ...this._jar }; }
}

const jar = new CookieJar();
let sessionReady = false;

// ─── FETCH A CINE ───────────────────────────────────────────────────────

const BASE_HEADERS = {
  'Accept':          'application/json, text/plain, */*',
  'Accept-Language': 'es-PE,es;q=0.9,en;q=0.8',
  'Accept-Encoding': 'gzip, deflate, br',
  'User-Agent':      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Sec-Fetch-Dest':  'empty',
  'Sec-Fetch-Mode':  'cors',
  'Sec-Fetch-Site':  'same-origin',
  'Sec-Ch-Ua':       '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
  'Sec-Ch-Ua-Mobile':'?0',
  'Sec-Ch-Ua-Platform': '"Windows"',
};

async function cpFetch(url, opts = {}) {
  const cookie = jar.header();
  const headers = {
    ...BASE_HEADERS,
    'Origin':  BASE_URL,
    'Referer': BASE_URL + '/',
    ...(opts.headers || {}),
    ...(cookie ? { 'Cookie': cookie } : {}),
  };

  const res = await fetch(url, { ...opts, headers });

  const raw = res.headers.getSetCookie ? res.headers.getSetCookie()
            : [res.headers.get('set-cookie')].filter(Boolean);
  jar.ingest(raw);

  return res;
}

// Si la sesión expiró (403), la renueva y reintenta una vez
async function cpFetchRetry(url, opts = {}) {
  let res = await cpFetch(url, opts);
  if (res.status === 403) {
    addLog('403 recibido, renovando sesión...', 'warn');
    await initSession(true);
    res = await cpFetch(url, opts);
  }
  return res;
}

async function cpGet(endpoint) {
  const res = await cpFetchRetry(BASE_URL + endpoint);
  if (!res.ok) throw new Error(`HTTP ${res.status} en GET ${endpoint}`);
  return res.json();
}

// gettickets responde {ResponseCode, Tickets:[...]}; devolvemos solo el array
async function getTickets(cinemaId, sessionId, uid) {
  const data = await cpGet(`/api/v1-web/gettickets/cinema/${cinemaId}/session/${sessionId}/usersessionid/${uid}`);
  return Array.isArray(data) ? data : (data.Tickets || []);
}

async function cpPost(endpoint, payload) {
  const encInfo = encrypt(payload);
  const res = await cpFetchRetry(BASE_URL + endpoint, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ encInfo }),
  });
  if (!res.ok) {
    // Incluir la respuesta del servidor en el error (descifrada si viene cifrada)
    let detail = await res.text().catch(() => '');
    try { const j = JSON.parse(detail); detail = JSON.stringify(j.encResponse ? decrypt(j.encResponse) : j); } catch {}
    const err = new Error(`HTTP ${res.status} en POST ${endpoint}: ${detail.slice(0, 500)}`);
    err.status = res.status;
    throw err;
  }
  const json = await res.json();
  return json.encResponse ? decrypt(json.encResponse) : json;
}

// ─── PÓSTERS ──────────────────────────────────────────────────────────────────
// El CDN del cine no deja que el navegador cargue las imágenes desde otro sitio
// (Chrome las bloquea con ERR_BLOCKED_BY_ORB), así que se sirven a través del bot.

const posterCache = new Map();   // id → { type, buf }

function posterPath(movie) {
  const id = String(movie.posterUrl || '').match(/FilmPosterGraphic\/(HO\d+)/)?.[1] || (/^HO\d+$/.test(movie.id) ? movie.id : null);
  return id ? `/bot/poster?id=${id}` : '';
}

async function getPoster(id) {
  if (!CDN_URL) return null;   // sin URL_CINE_CDN no hay pósters
  if (posterCache.has(id)) return posterCache.get(id);
  const r = await fetch(`${CDN_URL}/CDN/media/entity/get/FilmPosterGraphic/${id}?referenceScheme=HeadOffice&allowPlaceHolder=true&width=160`,
    { headers: { 'User-Agent': BASE_HEADERS['User-Agent'] } });
  const type = r.headers.get('content-type') || '';
  if (!r.ok || !type.startsWith('image/')) return null;
  const img = { type, buf: Buffer.from(await r.arrayBuffer()) };
  if (posterCache.size >= 300) posterCache.delete(posterCache.keys().next().value);
  posterCache.set(id, img);
  return img;
}

// ─── INICIALIZACIÓN DE SESIÓN ─────────────────────────────────────────────────

async function getCinemas() {
  const data = await cpGet('/api/v1-web/cache/cinemascache');
  const cinemas = Array.isArray(data) ? data : (data.cinemas || data);
  return cinemas.map(c => ({
    id:   c.ID   || c.id || c.cinemaId || c.Id,
    name: c.name || c.Name || c.description || c.Description,
    slug: c.formattedCinemaName || c.slug || c.Slug || '',
  })).filter(c => c.id && c.name)
     .sort((a, b) => a.name.localeCompare(b.name));
}

async function initSession(force = false) {
  if (sessionReady && !force) return true;
  try {
    addLog('Inicializando sesión con el cine...');
    const home = await cpFetch(BASE_URL + '/');
    addLog(`  Homepage: ${home.status}`);
    const boot = await cpFetch(BASE_URL + '/api/v1-web/bootstrap-data', {
      headers: { 'Content-Type': 'application/json' },
    });
    addLog(`  Bootstrap: ${boot.status} | cookies: ${jar.size()}`);
    if (!jar.get('userSessionId')) jar.set('userSessionId', genSessionId());
    sessionReady = true;
    addLog('✅ Sesión lista');
    return true;
  } catch (e) {
    addLog(`❌ Error iniciando sesión: ${e.message}`, 'error');
    return false;
  }
}

async function ensureSession() {
  if (!sessionReady) await initSession();
}

// ─── LOG ──────────────────────────────────────────────────────────────────────

const logs = [];

function addLog(msg, type = 'info', job = null) {
  const entry = { time: new Date().toISOString(), msg, type, jobId: job?.id || null, jobName: job?.name || null };
  logs.unshift(entry);
  if (logs.length > 300) logs.pop();
  const tag = type === 'error' ? '❌' : type === 'success' ? '✅' : type === 'warn' ? '⚠️' : '·';
  console.log(`${tag} ${job ? `[${job.name}] ` : ''}${msg}`);
}

// ─── JOBS ─────────────────────────────────────────────────────────────────────

const DEFAULTS = {
  intervalMs:  600000,   // sin mediciones: revisión objetivo tras reservar
  retryMinMs:  10000,    // reintentos rápidos (tras un fallo, o pasada la retención máxima observada)
  retryMaxMs:  20000,
  baselineMs:  60000,    // revisión complementaria mientras dura la retención (0 = desactivada)
  windowMinMs: 30000,    // ritmo dentro de la ventana probable de liberación
  windowMaxMs: 60000,
  ticketCode:  '0050',
};

// Campos de configuración que el panel puede fijar
const CONFIG_KEYS = ['name', 'cinemaId', 'cinemaName', 'movieId', 'movieTitle', 'posterUrl', 'sessionId',
  'showtime', 'screenName', 'day', 'ticketCode', 'ticketDesc', 'targetSeats',
  'intervalMs', 'retryMinMs', 'retryMaxMs', 'baselineMs', 'windowMinMs', 'windowMaxMs', 'endAt', 'adaptive'];

// Estado persistido además de la configuración
const STATE_KEYS = ['id', 'createdAt', 'userSessionId', 'running', 'attempts', 'successes', 'lastResult', 'history',
  'heldSeats', 'lastReservedAt', 'cycle', 'holdSamples', 'holdHint', 'seatState',
  'uidReservations', 'orderExpiryInfo', 'expiryChecked', 'paused', 'alert', 'watcherId'];

const HOLD_MAX_MS     = 60 * 60 * 1000;  // pasado esto, butacas ocupadas ya no se asumen como retención propia
const HOLD_SAMPLES    = 5;               // mediciones de retención que se recuerdan por job

const jobs = new Map();

function newJob(cfg = {}) {
  const job = {
    id:           crypto.randomBytes(5).toString('hex'),
    createdAt:    new Date().toISOString(),
    userSessionId: genSessionId(),   // uno por job: cada job tiene su propia orden en el cine
    name:         'Job',
    cinemaId: null, cinemaName: '', movieId: null, movieTitle: '', posterUrl: '',
    sessionId: null, showtime: null, screenName: '', day: null,
    ticketCode: DEFAULTS.ticketCode, ticketDesc: '', targetSeats: [],
    intervalMs: DEFAULTS.intervalMs, retryMinMs: DEFAULTS.retryMinMs, retryMaxMs: DEFAULTS.retryMaxMs,
    baselineMs: DEFAULTS.baselineMs, windowMinMs: DEFAULTS.windowMinMs, windowMaxMs: DEFAULTS.windowMaxMs,
    endAt: null, adaptive: true,
    running: false, mode: 'normal', nextAt: null, busy: false,
    attempts: 0, successes: 0, lastResult: null, history: [],
    heldSeats:      [],     // etiquetas reservadas en la última reserva exitosa (retención propia)
    lastReservedAt: null,   // ms de esa reserva
    cycle:          null,   // vuelta actual: { reservedAt, newOrder, orderSeq, expiresAt, sawOccupied, lastOccupiedAt, measured, phase }
    holdSamples:    [],     // mediciones reales de la retención: { ms, loMs, hiMs, at, newOrder, orderSeq }
    holdHint:       null,   // estimación de un solo uso (ms): la retención duró menos de esto
    uidReservations: 0,     // reservas hechas con el userSessionId actual (0 → la próxima abre una orden nueva)
    paused:         false,  // en pausa: sigue revisando pero no reserva; avisa cuando las butacas están libres
    alert:          null,   // aviso vigente: { seats, taken, at, lastSeenAt, ack }
    watcherId:      null,   // vigía de preestreno que creó el job
    orderExpiryInfo: null,  // campos de vencimiento encontrados en la última respuesta de reserva
    expiryChecked:  false,  // ya se registró en consola si la respuesta trae vencimiento
    seatState:      {},     // etiqueta → 'held' | 'free' | 'taken' en la última comprobación
    timer: null, endTimer: null,
  };
  applyConfig(job, cfg);
  return job;
}

function resetHold(job) {
  job.heldSeats = []; job.lastReservedAt = null; job.cycle = null; job.seatState = {};
}

function applyConfig(job, b) {
  const prevSession = job.sessionId;
  const prevSeats   = JSON.stringify(job.targetSeats);
  for (const k of CONFIG_KEYS) if (k in b) job[k] = b[k];
  job.name       = String(job.name || '').trim().slice(0, 60) || job.movieTitle || 'Job';
  job.intervalMs = Math.max(5000, parseInt(job.intervalMs) || DEFAULTS.intervalMs);
  job.retryMinMs = Math.max(5000, parseInt(job.retryMinMs) || DEFAULTS.retryMinMs);
  job.retryMaxMs = Math.max(job.retryMinMs, parseInt(job.retryMaxMs) || job.retryMinMs);
  job.endAt      = job.endAt ? (new Date(job.endAt).getTime() || null) : null;
  job.targetSeats = Array.isArray(job.targetSeats) ? job.targetSeats : [];
  job.adaptive   = job.adaptive !== false;
  const bl = parseInt(job.baselineMs);
  job.baselineMs  = bl === 0 ? 0 : Math.max(10000, bl || DEFAULTS.baselineMs);
  job.windowMinMs = Math.max(5000, parseInt(job.windowMinMs) || DEFAULTS.windowMinMs);
  job.windowMaxMs = Math.max(job.windowMinMs, parseInt(job.windowMaxMs) || job.windowMinMs);
  // Otra función → la retención aprendida ya no aplica; otros asientos → la retención actual tampoco.
  // En ambos casos, orden nueva (otro userSessionId): el cine acumula las entradas en la orden del
  // userSessionId, así que con el mismo id las butacas nuevas se sumarían a las de la reserva anterior.
  const seatsChanged = JSON.stringify(job.targetSeats) !== prevSeats;
  if (job.sessionId !== prevSession || seatsChanged) {
    const hadHold = job.heldSeats?.length > 0;
    if (job.sessionId !== prevSession) { job.holdSamples = []; job.holdHint = null; }
    resetHold(job);
    newOrder(job);
    if (hadHold) addLog('Butacas o función cambiadas: se usará una orden nueva; la retención anterior se liberará sola', 'info', job);
  }
  if (job.running) armEndTimer(job);
}

// Orden nueva en el cine: otro userSessionId (las entradas se acumulan por userSessionId)
function newOrder(job) {
  job.userSessionId   = genSessionId();
  job.uidReservations = 0;
}

// Mediciones relevantes para una vuelta: las del mismo contexto (orden nueva o no) si hay al menos 2,
// si no todas. Así, si la primera reserva de una orden dura distinto que las siguientes, se separan.
function relevantSamples(job, isNewOrder) {
  const all  = job.holdSamples || [];
  const same = all.filter(x => x.newOrder === isNewOrder);
  return isNewOrder != null && same.length >= 2 ? same : all;
}

// Retención aprendida (para mostrar): la menor de las mediciones relevantes
function learnedHold(job, isNewOrder = null) {
  const s = relevantSamples(job, isNewOrder);
  return s.length ? Math.min(...s.map(x => x.ms)) : null;
}

// Plan de revisiones mientras dura la retención (tiempos en ms desde la reserva):
//  - 'expiry':   el cine informó el vencimiento → revisar justo antes (vencimiento − 20 s)
//  - 'range':    hay mediciones → puntos a ½, ⅔ y ¾ del mínimo; ventana probable [mín − 20 s, máx]
//                revisando cada windowMin–windowMax; pasado el máximo, reintentos rápidos
//  - 'interval': sin datos → revisar al cumplirse el intervalo y después reintentos rápidos
// En todos los casos, antes de la ventana se revisa además cada baselineMs (complementaria).
function holdSchedule(job, cycle) {
  const base = { baselineMs: job.baselineMs };
  if (cycle?.expiresAt) {
    return { ...base, mode: 'expiry', target: Math.max(5000, cycle.expiresAt - cycle.reservedAt - 20000) };
  }
  const isNew   = cycle ? cycle.newOrder : job.uidReservations === 0;
  const samples = relevantSamples(job, isNew);
  let lo = samples.length ? Math.min(...samples.map(x => x.ms)) : null;
  const hi = samples.length ? Math.max(...samples.map(x => x.ms)) : null;
  if (job.holdHint && (lo == null || job.holdHint < lo)) lo = job.holdHint;   // estimación de un solo uso
  if (!job.adaptive || lo == null) return { ...base, mode: 'interval', target: job.intervalMs };
  const windowStart = Math.max(5000, lo - 20000);
  return {
    ...base, mode: 'range', minMs: lo, maxMs: Math.max(hi || lo, lo),
    points: [lo / 2, lo * 2 / 3, lo * 3 / 4].map(Math.round).filter(p => p >= 5000 && p < windowStart),
    windowStart, windowEnd: Math.max(hi || lo, lo),
  };
}

const randBetween = (a, b) => a + Math.floor(Math.random() * (b - a + 1));

// Espera hasta la próxima revisión de una vuelta en retención; registra en consola los cambios de fase
function holdDelay(job) {
  const c   = job.cycle;
  const sch = holdSchedule(job, c);
  const e   = Date.now() - c.reservedAt;
  const baseline = sch.baselineMs > 0 ? Math.round(sch.baselineMs * (0.9 + Math.random() * 0.2)) : Infinity;
  const fmt = ms => (ms / 60000).toFixed(1);
  let phase, d;
  if (sch.mode === 'range') {
    if (e < sch.windowStart - 500) {
      phase = 'before';
      const next = sch.points.find(p => p > e + 500);
      d = Math.min(next != null ? next - e : Infinity, baseline, sch.windowStart - e);
    } else if (e < sch.windowEnd) {
      phase = 'window';
      d = Math.min(randBetween(job.windowMinMs, job.windowMaxMs), baseline);
    } else {
      phase = 'after';
      d = randomRetry(job);
    }
  } else {
    if (e < sch.target - 500) { phase = 'before'; d = Math.min(baseline, sch.target - e); }
    else                      { phase = 'after';  d = randomRetry(job); }
  }
  if (phase !== c.phase && c.phase) {
    const range = `${job.retryMinMs / 1000}-${job.retryMaxMs / 1000}s`;
    if (phase === 'window') addLog(`Ventana probable de liberación (${fmt(sch.windowStart)}–${fmt(sch.windowEnd)} min): revisando cada ${job.windowMinMs / 1000}-${job.windowMaxMs / 1000}s`, 'info', job);
    if (phase === 'after')  addLog(sch.mode === 'range'
      ? `Superó la retención máxima observada (${fmt(sch.windowEnd)} min): reintentando cada ${range}`
      : `Sigue retenida tras la revisión objetivo: reintentando cada ${range}`, 'info', job);
  }
  c.phase = phase;
  return Math.max(1000, Math.round(d));
}

// Texto del plan para la consola
function scheduleText(job, sch) {
  const fmt = ms => (ms / 60000).toFixed(1);
  const base = sch.baselineMs > 0 ? `revisión complementaria cada ${sch.baselineMs / 1000}s; ` : '';
  const fast = `${job.retryMinMs / 1000}-${job.retryMaxMs / 1000}s`;
  if (sch.mode === 'expiry') return `${base}vencimiento informado por el cine: revisión a los ${fmt(sch.target)} min; luego cada ${fast}`;
  if (sch.mode === 'interval') return `${base}revisión a los ${fmt(sch.target)} min (sin mediciones aún); luego cada ${fast}`;
  return `${base}${sch.points.length ? `puntos a los ${sch.points.map(fmt).join(', ')} min; ` : ''}`
    + `ventana probable ${fmt(sch.windowStart)}–${fmt(sch.windowEnd)} min cada ${job.windowMinMs / 1000}-${job.windowMaxMs / 1000}s; luego cada ${fast}`;
}

// Busca en la respuesta de la reserva campos de vencimiento (nombre con expir/timeout/…).
// Devuelve los campos encontrados y, si alguno es una fecha u otro valor usable, la hora de vencimiento.
function findExpiry(obj) {
  const fields = [];
  let expiresAt = null;
  const now = Date.now();
  const walk = (o, p, depth) => {
    if (!o || typeof o !== 'object' || depth > 6) return;
    for (const [k, v] of Object.entries(o)) {
      const path = p ? `${p}.${k}` : k;
      if (v && typeof v === 'object') { walk(v, path, depth + 1); continue; }
      if (!/expir|timeout|time.?left|remaining|until|vence/i.test(k) || v == null || v === '') continue;
      fields.push(`${path}=${String(v).slice(0, 40)}`);
      if (expiresAt) continue;
      if (typeof v === 'string' && isNaN(Number(v))) {
        const t = Date.parse(v);
        if (t > now && t < now + 3 * 3600 * 1000) expiresAt = t;
      } else if (/second|seg/i.test(k) && Number(v) >= 30 && Number(v) <= 7200) expiresAt = now + Number(v) * 1000;
      else if (/minute|min/i.test(k) && Number(v) >= 1 && Number(v) <= 180) expiresAt = now + Number(v) * 60000;
    }
  };
  walk(obj, '', 0);
  return { fields: fields.slice(0, 8), expiresAt };
}

function publicJob(job, historyLimit = 100) {
  const out = {};
  for (const k of [...CONFIG_KEYS, ...STATE_KEYS, 'mode', 'nextAt', 'busy']) out[k] = job[k];
  out.history = job.history.slice(0, historyLimit);
  const active = job.cycle && !job.cycle.measured && job.heldSeats?.length ? job.cycle : null;
  out.learnedHoldMs = learnedHold(job);
  out.schedule      = holdSchedule(job, active);   // vuelta en curso, o la que empezará tras la próxima reserva
  out.scheduleActive = !!active;
  return out;
}

// Guardado con debounce para no escribir el archivo en cada intento seguido
let saveTimer = null;
function saveJobs() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    const data = [...jobs.values()].map(j => {
      const o = {};
      for (const k of [...CONFIG_KEYS, ...STATE_KEYS]) o[k] = j[k];
      o.history = j.history.slice(0, 200);
      return o;
    });
    try { writeData('jobs.json', data); } catch (e) { console.error('No se pudo guardar jobs.json:', e.message); }
  }, 500);
}

function randomRetry(job) {
  return job.retryMinMs + Math.floor(Math.random() * (job.retryMaxMs - job.retryMinMs + 1));
}

// Un intento: GET de disponibilidad y, si corresponde, POST add-tickets con las butacas libres.
// - Si las butacas de la última reserva siguen ocupadas, es la retención del propio job: se espera.
// - Cuando se liberan, se mide cuánto duró la retención (para la espera adaptativa).
// - Si otra persona tomó algunas butacas, se reservan las que siguen libres (reserva parcial).
async function attemptReserve(job, dryRun = false, notifyOnly = false) {
  const { cinemaId, sessionId, targetSeats } = job;
  if (!cinemaId || !sessionId || !targetSeats.length) {
    addLog('Configuración incompleta', 'warn', job);
    return { success: false, error: 'Configuración incompleta' };
  }

  await ensureSession();
  job.attempts++;
  let holdInfo = {};   // { holdMs, holdLoMs, holdHiMs } si en este intento se midió la retención

  try {
    // 1. Disponibilidad (solo lectura)
    const plan = await cpGet(`/api/v1-web/seatplan/cinema/${cinemaId}/session/${sessionId}`);
    const area = plan.SeatLayoutData?.Areas?.[0];
    if (!area) throw new Error('Sin datos de sala');

    const rows = area.Rows || [];
    const now  = Date.now();
    const st   = {};   // etiqueta → 'free' | 'occupied' | 'missing'
    for (const t of targetSeats) {
      const seat = (rows[t.rowIndex]?.Seats || []).find(s => s.Position?.ColumnIndex === t.columnIndex);
      st[t.label] = !seat ? 'missing' : seat.Status === 0 ? 'free' : 'occupied';
    }

    // 2. ¿Sigue activa la retención de nuestra última reserva?
    const held = (job.heldSeats || []).filter(l => l in st);
    const holdActive = held.length > 0 && job.lastReservedAt && now - job.lastReservedAt < HOLD_MAX_MS
                    && held.every(l => st[l] === 'occupied');
    if (holdActive) {
      if (job.cycle) { job.cycle.sawOccupied = true; job.cycle.lastOccupiedAt = now; }
      job.seatState = Object.fromEntries(targetSeats.map(t =>
        [t.label, held.includes(t.label) ? 'held' : st[t.label] === 'free' ? 'free' : 'taken']));
      // Sin log por cada revisión: la consola solo avisa al entrar en retención y al liberarse
      const msg = `Retención activa: ${held.join(', ')} siguen reservados por este job (${((now - job.lastReservedAt) / 60000).toFixed(1)} min)`;
      return { success: false, holdActive: true, error: msg };
    }

    // 3. La retención parece terminada: medir cuánto duró. La medición y el olvido de las butacas
    // propias solo se aplican si se confirma (ver commitRelease): a veces el mapa muestra libre por un
    // momento una butaca que sigue retenida, y el cine rechaza la reserva.
    const snapshot = held.length ? {
      heldSeats: job.heldSeats, lastReservedAt: job.lastReservedAt, cycle: job.cycle && { ...job.cycle },
      holdSamples: job.holdSamples, holdHint: job.holdHint,
    } : null;
    const pendingLogs = [];
    const c = job.cycle;
    if (c && c.reservedAt && !c.measured) {
      c.measured = true;
      const elapsed = now - c.reservedAt;
      const min = ms => `${(ms / 60000).toFixed(1)} min`;
      if (c.sawOccupied) {
        // Medición real: se liberó entre la última revisión en que seguía ocupada y esta
        const lo = c.lastOccupiedAt - c.reservedAt;
        const ms = Math.round((lo + elapsed) / 2);
        holdInfo = { holdMs: ms, holdLoMs: lo, holdHiMs: elapsed, holdNewOrder: !!c.newOrder, holdOrderSeq: c.orderSeq || null };
        job.holdSamples = [...(job.holdSamples || []),
          { ms, loMs: lo, hiMs: elapsed, at: now, newOrder: !!c.newOrder, orderSeq: c.orderSeq || null }].slice(-HOLD_SAMPLES);
        job.holdHint = null;
        const ctx = c.newOrder ? 'orden nueva' : `misma orden, reserva nº ${c.orderSeq}`;
        pendingLogs.push(`Retención liberada tras ~${min(ms)} (entre ${min(lo)} y ${min(elapsed)}; ${ctx})`);
        if (c.expiresAt) pendingLogs.push(`Vencimiento informado por el cine: ${min(c.expiresAt - c.reservedAt)}; liberación medida: ~${min(ms)}`);
      } else {
        // Ya estaba libre en la primera revisión: solo se sabe que duró menos. No es una medición;
        // se usa como estimación para la próxima vuelta, que revisará antes y la medirá bien.
        job.holdHint = elapsed;
        pendingLogs.push(`Las butacas ya estaban libres en la primera revisión (${min(elapsed)}): la retención duró menos. La próxima vuelta revisará antes para medirla`);
      }
    }
    job.heldSeats = [];
    const commitRelease = () => { for (const m of pendingLogs) addLog(m, 'info', job); };
    // El cine rechazó la reserva de butacas que eran nuestras: la retención sigue, se deshace todo
    const rollback = (why) => {
      if (!snapshot || !free.some(t => snapshot.heldSeats.includes(t.label))) return false;
      Object.assign(job, snapshot);
      holdInfo = {};
      job.seatState = Object.fromEntries(targetSeats.map(t =>
        [t.label, snapshot.heldSeats.includes(t.label) ? 'held' : st[t.label] === 'free' ? 'free' : 'taken']));
      addLog(`El mapa mostraba libre ${labels(free.filter(t => snapshot.heldSeats.includes(t.label))).join(', ')} pero el cine rechazó la reserva (${why}): se asume que la retención de este job sigue activa`, 'warn', job);
      return true;
    };

    // 4. Qué butacas se pueden reservar ahora
    const free  = targetSeats.filter(t => st[t.label] === 'free');
    const taken = targetSeats.filter(t => st[t.label] !== 'free');
    job.seatState = Object.fromEntries(targetSeats.map(t => [t.label, st[t.label] === 'free' ? 'free' : 'taken']));
    const takenTxt = taken.map(t => `${t.label}(${st[t.label] === 'missing' ? 'no existe' : 'ocupado'})`).join(', ');
    const labels   = arr => arr.map(t => t.label);

    if (!free.length) {
      commitRelease();
      if (job.alert) {
        job.alert = null;
        addLog('Las butacas del aviso ya no están libres (reservadas por ti u otra persona)', 'info', job);
      }
      const msg = `No disponibles: ${takenTxt}`;
      addLog(msg, 'warn', job);
      return { success: false, error: msg, taken: labels(taken), ...holdInfo };
    }
    if (taken.length) addLog(`${takenTxt} ya no ${taken.length > 1 ? 'están disponibles' : 'está disponible'}; se continúa con ${labels(free).join(', ')}`, 'warn', job);
    else              addLog(`Asientos disponibles ✓ ${labels(free).join(',')}`, 'info', job);

    // En pausa: no se reserva, solo se avisa (el panel muestra el aviso para reservar desde otro dispositivo)
    if (notifyOnly) {
      commitRelease();
      const seats = labels(free);
      if (!job.alert || job.alert.seats.join() !== seats.join()) {
        job.alert = { seats, taken: labels(taken), at: now, lastSeenAt: now, ack: false };
        addLog(`🔔 BUTACAS LIBRES: ${seats.join(', ')}${taken.length ? ` (no disponibles: ${labels(taken).join(', ')})` : ''}. En pausa: el bot no las reserva`, 'success', job);
      } else job.alert.lastSeenAt = now;
      return { success: false, notify: true, seats, taken: labels(taken),
               error: `Libres: ${seats.join(', ')} · en pausa, solo aviso`, ...holdInfo };
    }

    if (dryRun) {
      commitRelease();
      addLog(`[TEST] Se reservarían: ${labels(free).join(', ')}`, 'success', job);
      return { success: true, dryRun: true, partial: taken.length > 0, seats: labels(free), taken: labels(taken), ...holdInfo };
    }

    // 5. Tipos de ticket y reserva. Si el cine responde 5xx (p. ej. 502 "VSS"),
    // se renuevan la sesión y el userSessionId del job, y se reintenta una vez al momento.
    let result;
    try {
      result = await addTickets(job, area, free);
    } catch (e) {
      if (!(e.status >= 500)) { if (rollback(e.message.slice(0, 80))) return { success: false, error: `Rechazada: ${e.message} · la retención propia sigue activa` }; throw e; }
      addLog(`${e.message}`, 'error', job);
      addLog('Error del servidor del cine: renovando sesión y userSessionId, y reintentando...', 'warn', job);
      newOrder(job);
      await initSession(true);
      try { result = await addTickets(job, area, free); }
      catch (e2) { if (rollback(e2.message.slice(0, 80))) return { success: false, error: `Rechazada: ${e2.message} · la retención propia sigue activa` }; throw e2; }
    }

    if (result.Result === 0 && result.Order) {
      commitRelease();
      const orderSeats = (result.Order.Sessions || []).flatMap(s => (s.Tickets || []).map(t => t.SeatData)).filter(Boolean);
      const reserved   = orderSeats.join(', ') || labels(free).join(', ');
      const total      = (result.Order.TotalValueCents / 100).toFixed(2);
      if (orderSeats.length > free.length) {
        addLog(`La orden tiene ${orderSeats.length} butacas (${reserved}) pero se pidieron ${free.length}: incluye butacas de una reserva anterior`, 'warn', job);
      }
      job.successes++;
      job.heldSeats      = labels(free);
      job.lastReservedAt = Date.now();
      const isNewOrder   = (job.uidReservations || 0) === 0;
      job.uidReservations = (job.uidReservations || 0) + 1;
      const exp = findExpiry(result);
      job.orderExpiryInfo = exp.fields.length ? { fields: exp.fields, at: job.lastReservedAt, usable: !!exp.expiresAt } : null;
      if (!job.expiryChecked || exp.fields.length) {
        addLog(exp.fields.length
          ? `Respuesta de la reserva con datos de vencimiento: ${exp.fields.join(', ')}${exp.expiresAt ? '' : ' (no se pudo interpretar como hora)'}`
          : 'La respuesta de la reserva no trae hora de vencimiento: se usa la retención medida', 'info', job);
        job.expiryChecked = true;
      }
      job.cycle = { reservedAt: job.lastReservedAt, newOrder: isNewOrder, orderSeq: job.uidReservations,
                    expiresAt: exp.expiresAt, sawOccupied: false, lastOccupiedAt: null, measured: false, phase: null };
      for (const t of free) job.seatState[t.label] = 'held';
      addLog(taken.length
        ? `✅ RESERVA PARCIAL: ${reserved} | S/.${total} · no disponibles: ${labels(taken).join(', ')}`
        : `✅ RESERVADO: ${reserved} | S/.${total}`, 'success', job);
      return { success: true, partial: taken.length > 0, seats: reserved, total, taken: labels(taken), ...holdInfo };
    }
    if (rollback(`Result=${result.Result}`)) return { success: false, error: `Rechazada (Result=${result.Result}): la retención propia sigue activa` };
    throw new Error(`Result=${result.Result}`);

  } catch (err) {
    addLog(`Error: ${err.message}`, 'error', job);
    return { success: false, error: err.message, ...holdInfo };
  }
}

// Confirma el tipo de entrada con el userSessionId del job y envía add-tickets para las butacas dadas
async function addTickets(job, area, seats) {
  const { cinemaId, sessionId, ticketCode } = job;
  const targetSeats = seats;
  const tickets = await getTickets(cinemaId, sessionId, job.userSessionId);
  if (!tickets.find(t => t.TicketTypeCode === ticketCode)) {
    throw new Error(`TicketTypeCode ${ticketCode} no disponible`);
  }

  const payload = {
    UserSessionId: job.userSessionId,
    CinemaId:      cinemaId,
    SessionId:     sessionId,
    // Un solo tipo con Qty = nº de asientos, como lo envía la web
    TicketTypes:   [{ TicketTypeCode: ticketCode, LoyaltyRecognitionId: null, Qty: targetSeats.length }],
    SelectedSeats: targetSeats.map(s => ({
      AreaCategoryCode: area.AreaCategoryCode,
      special:          false,
      AreaNumber:       s.areaNumber || 1,
      RowIndex:         s.rowIndex,
      ColumnIndex:      s.columnIndex,
    })),
    ReturnOrder:                  true,
    ReturnSeatData:               false,
    ProcessOrderValue:            true,
    UserSelectedSeatingSupported: true,
    SkipAutoAllocation:           true,
    RemoveTickets:                false,
    RemoveTicketsQty:             0,
    RemoveTicketsIds:             null,
  };

  return cpPost('/api/v1-web/add-tickets', payload);
}

// Ejecuta un intento y lo registra en el histórico. source: 'auto' | 'manual' | 'test'
async function doReserve(job, dryRun, source) {
  if (job.busy) return { success: false, skipped: true, error: 'Ya hay un intento en curso para este job' };
  job.busy = true;
  let r;
  try { r = await attemptReserve(job, dryRun, job.paused && source === 'auto'); }
  finally { job.busy = false; }

  job.lastResult = { ...r, timestamp: new Date().toISOString() };
  job.history.unshift({
    time:     new Date().toISOString(),
    source,
    success:  !!r.success,
    dryRun:   !!r.dryRun,
    // reserved | partial | hold (retención propia activa) | free (en pausa: libres, solo aviso) | failed | test
    kind:     r.dryRun ? 'test' : r.success ? (r.partial ? 'partial' : 'reserved') : r.holdActive ? 'hold' : r.notify ? 'free' : 'failed',
    msg:      r.success
      ? (r.dryRun ? `Disponibles: ${[].concat(r.seats).join(', ')}` : `Reservado ${r.seats} · S/.${r.total}`)
        + (r.taken?.length ? ` · no disponibles: ${r.taken.join(', ')}` : '')
      : r.error,
    taken:    r.taken || [],
    holdMs:   r.holdMs || null,   // retención medida si se liberó en este intento (con su rango)
    holdLoMs: r.holdLoMs ?? null,
    holdHiMs: r.holdHiMs ?? null,
    holdNewOrder: r.holdNewOrder ?? null,
    holdOrderSeq: r.holdOrderSeq ?? null,
    nextInMs: null,
  });
  if (job.history.length > 500) job.history.pop();
  saveJobs();
  return r;
}

// Mientras dura la retención de una reserva: revisiones según holdSchedule/holdDelay.
// Tras un fallo (o sin retención que vigilar): reintentos aleatorios entre retryMin y retryMax.
async function runTick(job) {
  if (!job.running) return;
  job.nextAt = null;
  const r = await doReserve(job, false, 'auto');
  if (!job.running) return;

  const range = `${job.retryMinMs / 1000}-${job.retryMaxMs / 1000}s`;
  const c     = job.cycle;
  const inHold = (r.success || r.holdActive) && c && !c.measured;
  if (r.success && c) c.phase = null;
  const delay = inHold ? holdDelay(job) : randomRetry(job);

  if (!r.skipped) {
    const mode = r.success ? 'normal' : r.holdActive ? 'hold' : r.notify ? 'notify' : 'retry';
    if (mode !== job.mode) {
      if (mode === 'retry') addLog(`Reserva fallida; reintentando cada ${range}`, 'warn', job);
      if (mode === 'normal' && job.mode === 'retry') addLog('Reserva recuperada', 'info', job);
    }
    if (r.success && c) addLog(`Plan (${c.newOrder ? 'orden nueva' : `misma orden, reserva nº ${c.orderSeq}`}): ${scheduleText(job, holdSchedule(job, c))}`, 'info', job);
    job.mode = mode;
    job.history[0].nextInMs = delay;
  }
  job.nextAt = Date.now() + delay;
  job.timer  = setTimeout(() => runTick(job), delay);
  saveJobs();
}

function startJob(job, resumed = false) {
  if (job.running && !resumed) return { ok: true };
  if (job.endAt && Date.now() >= job.endAt) {
    job.running = false;
    return { ok: false, error: 'La hora de fin ya pasó' };
  }
  if (!job.cinemaId || !job.sessionId || !job.targetSeats.length) {
    return { ok: false, error: 'El job no tiene función o asientos' };
  }
  job.running = true;
  job.mode    = 'normal';
  if (!resumed) { job.attempts = 0; job.successes = 0; }
  const fin = job.endAt ? ` hasta las ${new Date(job.endAt).toLocaleTimeString('es-PE', { timeZone: 'America/Lima' })}` : '';
  addLog(`${resumed ? 'Job reanudado' : 'Job iniciado'}${fin}. Tras reservar: ${scheduleText(job, holdSchedule(job, null))}`, 'info', job);
  armEndTimer(job);
  runTick(job);   // primer intento inmediato
  saveJobs();
  return { ok: true };
}

// Pausa: el job sigue revisando pero ya no reserva; avisa cuando ve las butacas libres.
// La retención vigente (si la hay) no se cancela: vence sola.
function setPaused(job, paused) {
  if (!!job.paused === !!paused) return;
  job.paused = !!paused;
  if (paused) {
    addLog(`⏸ En pausa: el bot ya no reserva, solo avisará cuando las butacas estén libres${job.heldSeats?.length ? ' (la retención actual vencerá sola)' : ''}`, 'warn', job);
  } else {
    job.alert = null;
    addLog('▶ Pausa quitada: el bot vuelve a reservar', 'info', job);
    if (job.running && !job.busy) { clearTimeout(job.timer); runTick(job); }   // intentar ya
  }
  saveJobs();
}

// setTimeout no admite más de ~24.8 días (2^31-1 ms): con más, se dispara al instante.
// Para funciones lejanas (preventas de meses) se espera por tramos y se vuelve a armar.
const MAX_TIMEOUT_MS = 2 ** 31 - 1;

function armEndTimer(job) {
  clearTimeout(job.endTimer); job.endTimer = null;
  if (!job.running || !job.endAt) return;
  const left = job.endAt - Date.now();
  if (left > MAX_TIMEOUT_MS) {
    job.endTimer = setTimeout(() => armEndTimer(job), MAX_TIMEOUT_MS);
    return;
  }
  job.endTimer = setTimeout(() => {
    addLog('Hora de fin alcanzada', 'info', job);
    stopJob(job);
  }, Math.max(0, left));
}

function stopJob(job) {
  job.running = false;
  clearTimeout(job.timer);    job.timer = null;
  clearTimeout(job.endTimer); job.endTimer = null;
  job.nextAt = null;
  job.mode   = 'normal';
  job.alert  = null;
  addLog('Job detenido', 'info', job);
  saveJobs();
}

// Cargar jobs guardados y reanudar los que estaban corriendo
for (const saved of readData('jobs.json', [])) {
  const job = newJob(saved);
  for (const k of STATE_KEYS) if (k in saved) job[k] = saved[k];
  job.history     = Array.isArray(job.history) ? job.history : [];
  job.heldSeats   = Array.isArray(job.heldSeats) ? job.heldSeats : [];
  // Solo mediciones reales en formato objeto; los números de versiones anteriores mezclaban estimaciones
  job.holdSamples = (Array.isArray(job.holdSamples) ? job.holdSamples : []).filter(x => x && typeof x === 'object' && x.ms > 0);
  job.seatState   = job.seatState || {};
  job.uidReservations = job.uidReservations || 0;
  jobs.set(job.id, job);
}

function jobAlerts() {
  return [...jobs.values()].filter(j => j.running && j.paused && j.alert && !j.alert.ack).map(j => ({
    jobId: j.id, name: j.name, cinemaName: j.cinemaName, movieTitle: j.movieTitle, showtime: j.showtime,
    screenName: j.screenName, seats: j.alert.seats, taken: j.alert.taken, at: j.alert.at, lastSeenAt: j.alert.lastSeenAt,
  }));
}

// ─── VIGÍAS DE PREESTRENO ─────────────────────────────────────────────────────
// Consultan la cartelera cada pollMin–pollMax. Cuando la película tiene funciones en los cines
// elegidos, eligen asientos centrales juntos en cada función y crean (e inician) un job de reserva.
// Cada función se procesa una sola vez; si falla (sala sin publicar, sin asientos) se reintenta más tarde.

// sessionsPerCinema: cuántas funciones reservar por cine (las de los primeros días, una por día);
// prefFrom–prefTo: horario preferido dentro de cada día (si no hay, la función más cercana a ese rango)
const WATCH_DEFAULTS = { pollMinMs: 3000, pollMaxMs: 5000, seatCount: 5, ticketCode: DEFAULTS.ticketCode,
                         sessionsPerCinema: 3, prefFrom: '20:00', prefTo: '21:00' };
const WATCH_MAX_SESSIONS = 3;       // máximo de funciones reservadas por cine
const WATCH_NODETAIL_MS = 120000;   // tiempo que se espera el detalle (hora) de una función nueva antes de elegir sin él
const WATCH_RETRY_MS = 30000;   // reintento de una función que no se pudo procesar
const WATCHER_KEYS   = ['id', 'createdAt', 'name', 'movieId', 'movieTitle', 'posterUrl', 'cinemas', 'pollMinMs', 'pollMaxMs',
  'seatCount', 'ticketCode', 'sessionsPerCinema', 'prefFrom', 'prefTo',
  'running', 'handled', 'considered', 'chosen', 'checks', 'lastCheckAt', 'lastError', 'foundAt', 'movieSeenAt', 'events'];
const watchers = new Map();

function applyWatcherConfig(w, b) {
  if ('cinemas' in b) {
    const list = (Array.isArray(b.cinemas) ? b.cinemas : [])
      .filter(c => c && /^[0-9A-Za-z]{1,20}$/.test(String(c.id)))
      .map(c => ({ id: String(c.id), name: String(c.name || c.id).slice(0, 60) }));
    if (!list.length) return 'Elige al menos un cine';
    w.cinemas = list;
  }
  if ('pollMinMs' in b || 'pollMaxMs' in b) {
    w.pollMinMs = Math.max(2000, parseInt(b.pollMinMs) || WATCH_DEFAULTS.pollMinMs);
    w.pollMaxMs = Math.max(w.pollMinMs, parseInt(b.pollMaxMs) || w.pollMinMs);
  }
  if ('seatCount' in b)  w.seatCount  = Math.min(10, Math.max(1, parseInt(b.seatCount) || WATCH_DEFAULTS.seatCount));
  if ('ticketCode' in b) w.ticketCode = String(b.ticketCode || '').trim().slice(0, 20) || WATCH_DEFAULTS.ticketCode;
  if ('sessionsPerCinema' in b) w.sessionsPerCinema = Math.min(WATCH_MAX_SESSIONS, Math.max(1, parseInt(b.sessionsPerCinema) || WATCH_DEFAULTS.sessionsPerCinema));
  const hhmm = (v, d) => /^([01]\d|2[0-3]):[0-5]\d$/.test(String(v || '')) ? String(v) : d;
  if ('prefFrom' in b) w.prefFrom = hhmm(b.prefFrom, WATCH_DEFAULTS.prefFrom);
  if ('prefTo' in b)   w.prefTo   = hhmm(b.prefTo, WATCH_DEFAULTS.prefTo);
  if (w.prefTo < w.prefFrom) [w.prefFrom, w.prefTo] = [w.prefTo, w.prefFrom];
  return null;
}

function newWatcher(b) {
  const movieId = String(b.movieId || '').trim().toUpperCase();
  if (!/^[A-Z0-9]{4,20}$/.test(movieId)) return { error: 'ID de película inválido' };
  const w = {
    id: crypto.randomBytes(5).toString('hex'), createdAt: new Date().toISOString(),
    movieId, movieTitle: String(b.movieTitle || movieId).slice(0, 80), posterUrl: String(b.posterUrl || ''),
    cinemas: [], ...WATCH_DEFAULTS, running: false, handled: {}, considered: {}, chosen: {}, checks: 0, lastCheckAt: null, lastError: null,
    foundAt: null, movieSeenAt: null, events: [], timer: null, nextAt: null, busy: false,
  };
  const err = applyWatcherConfig(w, { cinemas: [], pollMinMs: WATCH_DEFAULTS.pollMinMs, pollMaxMs: WATCH_DEFAULTS.pollMaxMs, ...b });
  if (err) return { error: err };
  w.name = `Vigía ${w.movieTitle}`;
  return w;
}

function publicWatcher(w) {
  const o = {};
  for (const k of WATCHER_KEYS) o[k] = w[k];
  o.nextAt = w.nextAt;
  o.busy   = w.busy;
  o.status = w.status || null;
  // Funciones procesadas, con el estado actual de su job
  o.sessions = Object.entries(w.handled || {}).filter(([, h]) => h.status !== 'dropped').map(([key, h]) => {
    const j = h.jobId && jobs.get(h.jobId);
    return { key, ...h, job: j ? { id: j.id, name: j.name, running: j.running, paused: !!j.paused, mode: j.mode,
      successes: j.successes, alert: !!(j.alert && !j.alert.ack) } : null };
  }).sort((a, b) => String(a.cinemaName).localeCompare(String(b.cinemaName)) || String(a.showtime || a.key).localeCompare(String(b.showtime || b.key)));
  return o;
}

let saveWTimer = null;
function saveWatchers() {
  clearTimeout(saveWTimer);
  saveWTimer = setTimeout(() => {
    const data = [...watchers.values()].map(w => Object.fromEntries(WATCHER_KEYS.map(k => [k, w[k]])));
    try { writeData('watchers.json', data); } catch (e) { console.error('No se pudo guardar watchers.json:', e.message); }
  }, 1000);
}

function addWLog(w, msg, type = 'info') {
  addLog(msg, type, w);
  w.events.unshift({ time: new Date().toISOString(), msg, type });
  if (w.events.length > 60) w.events.pop();
}

function startWatcher(w, resumed = false) {
  if (w.running && !resumed) return;
  w.running = true;
  addWLog(w, `${resumed ? 'Vigía reanudado' : 'Vigía iniciado'}: consulta cada ${w.pollMinMs / 1000}–${w.pollMaxMs / 1000} s en ${w.cinemas.map(c => c.name).join(', ')}`);
  watcherTick(w);
  saveWatchers();
}

function stopWatcher(w, silent = false) {
  w.running = false;
  clearTimeout(w.timer); w.timer = null; w.nextAt = null;
  if (!silent) addWLog(w, 'Vigía detenido');
  saveWatchers();
}

async function watcherTick(w) {
  if (!w.running) return;
  clearTimeout(w.timer);
  w.nextAt = null;
  w.busy = true;
  let changed = false;
  try {
    changed = await watcherCheck(w);
    if (w.lastError) { addWLog(w, 'Consultas normalizadas'); w.lastError = null; changed = true; }
  } catch (e) {
    if (w.lastError !== e.message) { addWLog(w, `Error consultando la cartelera: ${e.message}`, 'error'); changed = true; }
    w.lastError = e.message;
  } finally { w.busy = false; }
  w.checks++;
  w.lastCheckAt = Date.now();
  if (changed || w.checks % 20 === 0) saveWatchers();
  if (!w.running) return;
  const delay = w.pollMinMs + Math.floor(Math.random() * (w.pollMaxMs - w.pollMinMs + 1));
  w.nextAt = Date.now() + delay;
  w.timer  = setTimeout(() => watcherTick(w), delay);
}

// Devuelve true si hubo novedades (para guardar)
async function watcherCheck(w) {
  await ensureSession();
  const mc = await cpGet('/api/v1-web/cache/moviescache');
  const movie = (mc.movies || []).find(m => String(m.id).toUpperCase() === w.movieId);
  if (!movie) return false;
  let changed = false;
  if (!w.movieSeenAt) {
    w.movieSeenAt = Date.now();
    w.movieTitle = movie.title || w.movieTitle;
    w.posterUrl  = posterPath(movie) || w.posterUrl;
    w.name = `Vigía ${w.movieTitle}`;
    changed = true;
  }

  const ids = new Set(w.cinemas.map(c => c.id));
  const found = [];
  let others = 0;   // funciones en cines no elegidos (solo informativo)
  for (const c of (movie.cinemas || [])) {
    const n = (c.dates || []).reduce((k, d) => k + (d.sessions || []).length, 0);
    if (!ids.has(c.cinemaId)) { others += n; continue; }
    for (const d of (c.dates || [])) for (const key of (d.sessions || [])) found.push({ cinemaId: c.cinemaId, key, date: d.date });
  }
  // Estado visible en la tarjeta del vigía (no se guarda)
  w.status = { inCatalog: true, selected: found.length, others, preSale: !!movie.isPreSale, comingSoon: !!movie.isComingSoon };
  if (changed) {
    // "Figura en el catálogo" no significa que tenga funciones: el catálogo incluye próximos estrenos
    addWLog(w, found.length ? 'La película figura en el catálogo del cine'
      : `La película figura en el catálogo del cine, pero aún sin funciones en los cines elegidos${others ? ` (sí en otros cines: ${others})` : ''}`);
  }
  const now = Date.now();
  if (!found.length) return changed;
  // Solo se vuelve a elegir si hay funciones nuevas (o esperando su hora) o reintentos pendientes;
  // así, con todo procesado, cada consulta es un solo GET de la cartelera.
  const retryDue = key => { const h = w.handled[key]; return h && h.status !== 'job' && now - h.at > WATCH_RETRY_MS; };
  const waiting  = key => typeof w.considered[key] === 'number' && w.considered[key] > 1 && now - w.considered[key] < WATCH_NODETAIL_MS;
  if (!found.some(f => !w.considered[f.key] || waiting(f.key) || retryDue(f.key))) return changed;

  if (!w.foundAt) {
    w.foundAt = now;
    const perCinema = w.cinemas.map(c => [c.name, found.filter(f => f.cinemaId === c.id).length]).filter(([, n]) => n);
    addWLog(w, `🎉 FUNCIONES DETECTADAS: ${perCinema.map(([n, k]) => `${n} (${k})`).join(', ')}`, 'success');
  }

  const sc = await cpGet('/api/v1-web/cache/sessioncache');
  const sessMap = {};
  for (const s of (sc.sessions || [])) sessMap[s.id] = s;

  // Por cine: elegir las funciones de los primeros días (ver chooseSessions)
  const pending = [];
  for (const c of w.cinemas) {
    const list = found.filter(f => f.cinemaId === c.id)
      .map(f => { const ss = sessMap[f.key]; return { f, s: ss, day: String(f.date).slice(0, 10), mins: ss?.showtime ? toMins(ss.showtime) : null, at: limaTime(ss?.showtime) }; })
      .filter(x => !(x.at && x.at < now))                          // ya empezó
      .filter(x => w.handled[x.f.key]?.status !== 'noseats');      // agotada: se elige otra
    if (!list.length) continue;
    const picks = chooseSessions(list, w.sessionsPerCinema, toMins('T' + w.prefFrom), toMins('T' + w.prefTo));
    const sig = picks.map(x => x.f.key).join(',');
    const whenOf = x => x.s?.showtime ? shortWhen(x.s.showtime) : `${shortWhen(x.day + 'T').slice(0, 5)} (hora desconocida)`;
    if (w.chosen[c.id] !== sig) {
      w.chosen[c.id] = sig;
      const days = new Set(list.map(x => x.day)).size;
      addWLog(w, `${c.name}: ${list.length} funciones en ${days} día${days > 1 ? 's' : ''}; se eligen ${picks.map(x => `${whenOf(x)} (${x.why})`).join(', ')}`);
      // Las funciones que quedaron fuera de la selección: se detiene y elimina su job
      const keep = new Set(picks.map(x => x.f.key));
      for (const [key, h] of Object.entries(w.handled)) {
        if (h.cinemaId !== c.id || keep.has(key) || h.status !== 'job') continue;
        const j = jobs.get(h.jobId);
        if (j) {
          stopJob(j);
          jobs.delete(j.id);
          addLog('Job eliminado por el vigía: la función ya no está entre las elegidas', 'info', j);
          saveJobs();
        }
        w.handled[key] = { ...h, status: 'dropped', jobId: null, msg: 'ya no está entre las elegidas', at: now };
        addWLog(w, `${c.name} ${h.showtime ? shortWhen(h.showtime) : key}: ya no está entre las elegidas; job eliminado`, 'warn');
      }
    }
    for (const x of picks) { const h = w.handled[x.f.key]; if (!h || retryDue(x.f.key)) pending.push(x); }
  }
  // Funciones ya vistas con su hora; las que aún no tienen detalle se esperan un rato antes de darlas por vistas
  for (const f of found) w.considered[f.key] = sessMap[f.key] ? 1 : (w.considered[f.key] || now);
  await Promise.all(pending.map(x => watcherSession(w, movie, x.f, x.s)));
  return true;
}

// "2026-10-20T20:30:00" → minutos desde medianoche (hora de la función, tal como la da el cine)
const toMins = iso => { const t = String(iso).split('T')[1] || ''; return (+t.slice(0, 2)) * 60 + (+t.slice(3, 5)); };

// Elige hasta n funciones (máx. 3) de un cine, en este orden:
//   1. la primera función disponible, a cualquier hora;
//   2. la primera que empieza en el horario preferido (8–9 pm por defecto), aunque sea otro día;
//   3. otra en el horario preferido pero de un día distinto a las ya elegidas (más opciones de fecha);
//   si alguna no existe, se completa con la siguiente función más próxima.
function chooseSessions(list, n, fromMin, toMin) {
  const inWin  = x => x.mins != null && x.mins >= fromMin && x.mins <= toMin;
  const when   = x => x.s?.showtime || `${x.day}T99:99`;   // sin hora: al final de su día
  const sorted = [...list].sort((a, b) => when(a).localeCompare(when(b)));
  const picks  = [];
  const take = (x, why) => { if (x && picks.length < n && !picks.includes(x)) picks.push(Object.assign(x, { why })); };
  const label = `${fmtHM(fromMin)}–${fmtHM(toMin)}`;
  take(sorted[0], 'primera');
  take(sorted.find(x => inWin(x) && !picks.includes(x)), label);
  take(sorted.find(x => inWin(x) && !picks.includes(x) && !picks.some(p => p.day === x.day)), `${label}, otro día`);
  for (const x of sorted) take(x, 'siguiente');
  return picks;
}
const fmtHM = m => `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`;

// Las horas del cine vienen sin zona ("2026-10-12T20:10:00"): son hora de Lima
const limaTime  = iso => !iso ? null : new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + '-05:00').getTime() || null;
const shortWhen = iso => iso ? `${iso.slice(8, 10)}/${iso.slice(5, 7)} ${iso.slice(11, 16)}` : '';

async function watcherSession(w, movie, f, s) {
  const cinemaName = w.cinemas.find(c => c.id === f.cinemaId)?.name || f.cinemaId;
  const sessionId  = String(s?.sessionId || f.key.split('-').pop());
  const when = s?.showtime ? shortWhen(s.showtime) : shortWhen(String(f.date)).slice(0, 5);
  const base = { cinemaId: f.cinemaId, cinemaName, sessionId, showtime: s?.showtime || null, screenName: s?.screenName || '', at: Date.now() };
  const fail = (status, msg) => {
    const prev = w.handled[f.key];
    w.handled[f.key] = { ...base, status, msg };
    if (prev?.msg !== msg) addWLog(w, `${cinemaName} ${when}: ${msg}`, 'warn');
  };
  try {
    const plan = await cpGet(`/api/v1-web/seatplan/cinema/${f.cinemaId}/session/${sessionId}`);
    const area = plan.SeatLayoutData?.Areas?.[0];
    if (!area) return fail('error', 'la sala aún no tiene mapa de asientos; se reintentará');
    const pick = pickCentralSeats(area, w.seatCount);
    if (!pick) return fail('noseats', 'no hay asientos libres juntos; se reintentará');

    const name = `${cinemaName} · ${when} · ${movie.title || w.movieTitle}`.slice(0, 60);
    const showAt = limaTime(s?.showtime);
    const job = newJob({
      name, cinemaId: f.cinemaId, cinemaName, movieId: w.movieId, movieTitle: movie.title || w.movieTitle,
      posterUrl: posterPath(movie) || w.posterUrl, sessionId, showtime: s?.showtime || null, screenName: s?.screenName || '',
      day: String(f.date).slice(0, 10), ticketCode: w.ticketCode, targetSeats: pick.seats,
      endAt: showAt ? showAt + 20 * 60000 : null,
    });
    // Tipo de entrada: el configurado; si esta función no lo tiene, una "General"; si no, la primera
    const tickets = await getTickets(f.cinemaId, sessionId, job.userSessionId);
    if (!tickets.length) return fail('error', 'la función aún no tiene entradas a la venta; se reintentará');
    const t = tickets.find(x => x.TicketTypeCode === w.ticketCode)
           || tickets.find(x => /general/i.test(x.Description || '')) || tickets[0];
    job.ticketCode = t.TicketTypeCode;
    job.ticketDesc = t.Description || '';
    job.watcherId  = w.id;
    jobs.set(job.id, job);
    const labels = pick.seats.map(x => x.label).join(', ');
    w.handled[f.key] = { ...base, status: 'job', jobId: job.id, seats: pick.seats.map(x => x.label) };
    addWLog(w, `${cinemaName} ${when}: job creado con ${labels}${pick.seats.length < w.seatCount ? ` (solo ${pick.seats.length} juntos disponibles)` : ''} · ${job.ticketDesc || job.ticketCode}`, 'success');
    addLog(`Job creado por el vigía de preestreno (${labels})`, 'info', job);
    const r = startJob(job);
    if (!r.ok) addWLog(w, `${name}: no se pudo iniciar (${r.error})`, 'warn');
    saveJobs();
  } catch (e) {
    fail('error', `${e.message.slice(0, 120)}; se reintentará`);
  }
}

// Asientos centrales juntos: en cada fila se buscan tramos de butacas libres contiguas (un pasillo
// o una butaca ocupada corta el tramo). Cada ventana de n butacas se puntúa por su distancia al
// centro horizontal de la sala y a la fila ideal: algo por detrás de la mitad, al ~60 % de la
// profundidad contando desde la pantalla. Gana la de menor puntuación. Si no hay n juntas, se
// prueba con n-1, n-2… hasta 2.
function pickCentralSeats(area, n) {
  const rows = (area.Rows || []).map((r, ri) => ({ r, ri })).filter(x => (x.r.Seats || []).length);
  if (!rows.length) return null;
  const col  = s => s.Position?.ColumnIndex ?? 0;
  const cols = rows.flatMap(x => x.r.Seats.map(col));
  const cMin = Math.min(...cols), cMax = Math.max(...cols);
  const cMid = (cMin + cMax) / 2, half = Math.max(1, (cMax - cMin) / 2);
  const IDEAL_DEPTH = 0.6, W_H = 1, W_V = 0.8;
  const usable = s => s.Status === 0 && s.SeatStyle !== 3;

  for (let want = n; want >= Math.min(n, 2); want--) {
    let best = null;
    rows.forEach(({ r, ri }, k) => {
      // Rows[0] es la fila del fondo; la última con butacas es la más cercana a la pantalla
      const depth = rows.length > 1 ? (rows.length - 1 - k) / (rows.length - 1) : IDEAL_DEPTH;
      const seats = [...r.Seats].sort((a, b) => col(a) - col(b));
      let run = [];
      const flush = () => {
        for (let i = 0; i + want <= run.length; i++) {
          const win = run.slice(i, i + want);
          const center = (col(win[0]) + col(win[want - 1])) / 2;
          const score = W_H * Math.abs(center - cMid) / half + W_V * Math.abs(depth - IDEAL_DEPTH);
          if (!best || score < best.score) best = { score, ri, row: r, win };
        }
        run = [];
      };
      for (const s of seats) {
        const prev = run[run.length - 1];
        if (!usable(s)) { flush(); continue; }
        if (prev && col(s) !== col(prev) + 1) flush();
        run.push(s);
      }
      flush();
    });
    if (best) return {
      seats: best.win.map(s => ({ rowIndex: best.ri, columnIndex: col(s), areaNumber: area.AreaNumber || 1,
                                  label: `${best.row.PhysicalName}${s.Id || col(s)}` })),
    };
  }
  return null;
}

for (const saved of readData('watchers.json', [])) {
  const w = { ...saved, timer: null, nextAt: null, busy: false };
  w.handled = w.handled || {}; w.events = w.events || []; w.cinemas = w.cinemas || [];
  w.considered = w.considered || {}; w.chosen = w.chosen || {};
  for (const k of ['sessionsPerCinema', 'prefFrom', 'prefTo']) if (w[k] == null) w[k] = WATCH_DEFAULTS[k];
  w.sessionsPerCinema = Math.min(WATCH_MAX_SESSIONS, w.sessionsPerCinema);
  watchers.set(w.id, w);
}

// ─── HTTP ─────────────────────────────────────────────────────────────────────

const MIME = { '.html':'text/html; charset=utf-8', '.js':'application/javascript', '.css':'text/css', '.json':'application/json', '.ico':'image/x-icon', '.png':'image/png', '.svg':'image/svg+xml' };

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
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), ...headers });
  res.end(body);
}

function serveFile(res, rel) {
  const fp = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!fp.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(404); res.end('404'); return; }
  fs.readFile(fp, (err, data) => {
    if (err) { res.writeHead(404); res.end('404'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(fp)] || 'text/plain', 'Cache-Control': 'no-store' });
    res.end(data);
  });
}

function redirect(res, to) { res.writeHead(302, { Location: to }); res.end(); }

const JOB_ROUTE = /^\/bot\/jobs\/([a-f0-9]+)(?:\/(start|stop|test|reserve-once|delete|pause|resume|ack))?$/;
const WATCHER_ROUTE = /^\/bot\/watchers\/([a-f0-9]+)(?:\/(start|stop|delete))?$/;

http.createServer(async (req, res) => {
  const url      = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname;
  const method   = req.method;

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');

  try {

    // ══ Rutas públicas: login ═════════════════════════════════════════════════

    if (method === 'POST' && pathname === '/auth/login') {
      const ip = clientIp(req);
      if (loginBlocked(ip)) return json(res, 429, { error: 'Demasiados intentos. Espera 15 minutos.' });
      const { password } = await readBody(req);
      const who = checkPassword(password);
      if (!who) {
        loginFailed(ip);
        await new Promise(r => setTimeout(r, 400));
        return json(res, 401, { error: 'Contraseña incorrecta' });
      }
      loginFails.delete(ip);
      const token = crypto.randomBytes(32).toString('hex');
      sessions.set(token, { ...who, expires: Date.now() + SESSION_TTL });
      return json(res, 200, { ok: true, role: who.role }, { 'Set-Cookie': sessionCookie(req, token, SESSION_TTL / 1000) });
    }

    if (method === 'GET' && (pathname === '/login' || pathname === '/login.html')) {
      if (getSession(req)) return redirect(res, '/');
      return serveFile(res, 'login.html');
    }

    // ══ A partir de aquí se requiere sesión ═══════════════════════════════════

    const sess = getSession(req);
    if (!sess) {
      if (/^\/(bot|admin|auth)\//.test(pathname)) return json(res, 401, { error: 'No autenticado' });
      return redirect(res, '/login');
    }

    if (method === 'GET' && pathname === '/preestreno') return serveFile(res, 'preestreno.html');

    if (method === 'POST' && pathname === '/auth/logout') {
      sessions.delete(parseCookies(req).cpb_session);
      return json(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(req, '', 0) });
    }

    if (method === 'GET' && pathname === '/auth/me') {
      return json(res, 200, { role: sess.role });
    }

    // ── Admin: contraseñas hijas ─────────────────────────────────────────────
    if (pathname.startsWith('/admin/')) {
      if (sess.role !== 'admin') return json(res, 403, { error: 'Solo el administrador' });

      if (method === 'GET' && pathname === '/admin/passwords') {
        return json(res, 200, { passwords: appPasswords() });
      }

      if (method === 'POST' && pathname === '/admin/passwords') {
        const b = await readBody(req);
        const password = String(b.password || '').trim() || crypto.randomBytes(6).toString('base64url');
        const label    = String(b.label || '').trim().slice(0, 40);
        if (password.length < 4)          return json(res, 400, { error: 'Mínimo 4 caracteres' });
        if (password.includes(','))       return json(res, 400, { error: 'No puede contener comas' });
        if (safeEqual(password, ADMIN_PASSWORD) || appPasswords().some(p => p.password === password))
          return json(res, 400, { error: 'Esa contraseña ya existe' });
        auth.created.push({ password, label, createdAt: new Date().toISOString() });
        auth.revoked = auth.revoked.filter(p => p !== password);
        saveAuth();
        return json(res, 200, { ok: true, password, passwords: appPasswords() });
      }

      if (method === 'POST' && pathname === '/admin/passwords/delete') {
        const { password } = await readBody(req);
        auth.created = auth.created.filter(c => c.password !== password);
        // Las del .env no se pueden borrar del archivo: quedan revocadas
        if (ENV_APP_PASSWORDS.includes(password) && !auth.revoked.includes(password)) auth.revoked.push(password);
        saveAuth();
        return json(res, 200, { ok: true, passwords: appPasswords() });
      }

      return json(res, 404, { error: 'No encontrado' });
    }

    // ── Catálogo del cine ───────────────────────────────────────────────

    if (method === 'GET' && pathname === '/bot/cinemas') {
      await ensureSession();
      return json(res, 200, { cinemas: await getCinemas() });
    }

    if (method === 'GET' && pathname === '/bot/movies') {
      const cinemaId = url.searchParams.get('cinemaId');
      if (!cinemaId) return json(res, 400, { error: 'Falta cinemaId' });
      await ensureSession();

      const [moviesCache, sessionCache] = await Promise.all([
        cpGet('/api/v1-web/cache/moviescache'),
        cpGet('/api/v1-web/cache/sessioncache'),
      ]);

      const sessMap = {};
      for (const s of (sessionCache.sessions || [])) sessMap[s.id] = s;

      // Solo funciones de hoy hasta 3 días más (hora de Lima), formato YYYY-MM-DD
      const limaDay = (offset) => new Date(Date.now() + offset * 86400000)
        .toLocaleDateString('en-CA', { timeZone: 'America/Lima' });
      const fromDay = limaDay(0), toDay = limaDay(3);
      const inRange = (date) => { const d = String(date).slice(0, 10); return d >= fromDay && d <= toDay; };

      const movies = (moviesCache.movies || [])
        .filter(m => m.cinemas?.some(c => c.cinemaId === cinemaId))
        .map(m => {
          const cinema = m.cinemas.find(c => c.cinemaId === cinemaId);
          const sessions = [];
          for (const d of (cinema?.dates || []).filter(d => inRange(d.date)))
            for (const sid of (d.sessions || []))
              if (sessMap[sid]) sessions.push({ ...sessMap[sid], date: d.date });
          return { id: m.id, title: m.title, rating: m.ratingDescription, runtime: m.runTime, posterUrl: posterPath(m), sessions };
        })
        .filter(m => m.sessions.length > 0);

      return json(res, 200, { movies });
    }

    // ── Consultar preestreno: funciones de una película en todas las fechas ──
    // Sin movieId: resumen de toda la cartelera (para elegir). Con movieId: sus funciones por cine.
    if (method === 'GET' && pathname === '/bot/presale') {
      const movieId = (url.searchParams.get('movieId') || '').trim().toUpperCase();
      if (movieId && !/^[A-Z0-9]{4,20}$/.test(movieId)) return json(res, 400, { error: 'ID inválido' });
      await ensureSession();
      const moviesCache = await cpGet('/api/v1-web/cache/moviescache');
      const restrictedIds = moviesCache.idMoviesBookingRestricted || [];
      const info = m => ({
        id: m.id, title: m.title, posterUrl: posterPath(m), genre: m.genre, rating: m.ratingDescription, runtime: m.runTime,
        openingDate: m.OpeningDate, isPreSale: !!m.isPreSale, isComingSoon: !!m.isComingSoon, isNewRelease: !!m.isNewRelease,
        restricted: !!m.restricted, bookingRestricted: restrictedIds.includes(m.id),
        sessionCount: (m.cinemas || []).reduce((n, c) => n + (c.dates || []).reduce((k, d) => k + (d.sessions || []).length, 0), 0),
        cinemaCount: (m.cinemas || []).length,
      });

      if (!movieId) {
        return json(res, 200, { checkedAt: new Date().toISOString(), movies: (moviesCache.movies || []).map(info) });
      }

      const movie = (moviesCache.movies || []).find(m => String(m.id).toUpperCase() === movieId);
      if (!movie) return json(res, 200, { checkedAt: new Date().toISOString(), found: false, movieId });

      const [sessionCache, cinemas] = await Promise.all([cpGet('/api/v1-web/cache/sessioncache'), getCinemas()]);
      const sessMap = {};
      for (const s of (sessionCache.sessions || [])) sessMap[s.id] = s;
      const cinemaName = Object.fromEntries(cinemas.map(c => [c.id, c.name]));

      const list = (movie.cinemas || []).map(c => {
        const sessions = [];
        for (const d of (c.dates || []))
          for (const sid of (d.sessions || []))
            sessions.push({ ...(sessMap[sid] || { id: sid }), date: d.date, formats: d.formats, detail: !!sessMap[sid] });
        sessions.sort((a, b) => String(a.showtime || a.date).localeCompare(String(b.showtime || b.date)));
        return { cinemaId: c.cinemaId, name: cinemaName[c.cinemaId] || c.cinemaId, sessions };
      }).sort((a, b) => a.name.localeCompare(b.name));

      return json(res, 200, { checkedAt: new Date().toISOString(), found: true, movie: info(movie), cinemas: list });
    }

    if (method === 'GET' && pathname === '/bot/poster') {
      const id = url.searchParams.get('id') || '';
      if (!/^HO\d{5,12}$/.test(id)) return json(res, 400, { error: 'id inválido' });
      const img = await getPoster(id);
      if (!img) return json(res, 404, { error: 'Sin póster' });
      res.writeHead(200, { 'Content-Type': img.type, 'Content-Length': img.buf.length, 'Cache-Control': 'private, max-age=86400' });
      return res.end(img.buf);
    }

    if (method === 'GET' && pathname === '/bot/seatplan') {
      const cinemaId  = url.searchParams.get('cinemaId');
      const sessionId = url.searchParams.get('sessionId');
      if (!cinemaId || !sessionId) return json(res, 400, { error: 'Faltan parámetros' });
      await ensureSession();
      return json(res, 200, await cpGet(`/api/v1-web/seatplan/cinema/${cinemaId}/session/${sessionId}`));
    }

    if (method === 'GET' && pathname === '/bot/tickets') {
      const cinemaId  = url.searchParams.get('cinemaId');
      const sessionId = url.searchParams.get('sessionId');
      if (!cinemaId || !sessionId) return json(res, 400, { error: 'Faltan parámetros' });
      await ensureSession();
      const uid = jar.get('userSessionId') || genSessionId();
      return json(res, 200, await getTickets(cinemaId, sessionId, uid));
    }

    // ── Estado general ───────────────────────────────────────────────────────

    if (method === 'GET' && pathname === '/bot/status') {
      return json(res, 200, {
        role:         sess.role,
        sessionReady,
        cookieCount:  jar.size(),
        defaults:     DEFAULTS,
        log:          logs.slice(0, 80),
        jobs:         [...jobs.values()].map(j => publicJob(j)),
      });
    }

    // ── Jobs ─────────────────────────────────────────────────────────────────

    if (method === 'POST' && pathname === '/bot/jobs') {
      const b   = await readBody(req);
      const job = newJob(b);
      jobs.set(job.id, job);
      addLog('Job creado', 'info', job);
      saveJobs();
      const started = b.start ? startJob(job) : { ok: true };
      return json(res, 200, { ok: true, job: publicJob(job), started });
    }

    // Test sin guardar: comprueba disponibilidad con la configuración del editor
    if (method === 'POST' && pathname === '/bot/test') {
      const tmp = newJob({ ...(await readBody(req)), name: 'Test' });
      return json(res, 200, await attemptReserve(tmp, true));
    }

    if (method === 'POST' && pathname === '/bot/jobs/pause-all') {
      const { paused } = await readBody(req);
      for (const j of jobs.values()) if (j.running) setPaused(j, !!paused);
      return json(res, 200, { ok: true });
    }

    // Avisos vigentes (butacas libres en jobs en pausa), para cualquier página
    if (method === 'GET' && pathname === '/bot/alerts') {
      return json(res, 200, { alerts: jobAlerts() });
    }

    // ── Vigías de preestreno ──────────────────────────────────────────────
    if (method === 'GET' && pathname === '/bot/watchers') {
      return json(res, 200, { watchers: [...watchers.values()].map(publicWatcher) });
    }

    if (method === 'POST' && pathname === '/bot/watchers') {
      const b = await readBody(req);
      const w = newWatcher(b);
      if (w.error) return json(res, 400, { error: w.error });
      watchers.set(w.id, w);
      addWLog(w, `Vigía creado: ${w.cinemas.map(c => c.name).join(', ')}`);
      if (b.start !== false) startWatcher(w);
      saveWatchers();
      return json(res, 200, { ok: true, watcher: publicWatcher(w) });
    }

    const wm = pathname.match(WATCHER_ROUTE);
    if (wm && method === 'POST') {
      const w = watchers.get(wm[1]);
      if (!w) return json(res, 404, { error: 'Vigía no encontrado' });
      if (wm[2] === 'start')  { startWatcher(w); return json(res, 200, { ok: true }); }
      if (wm[2] === 'stop')   { stopWatcher(w);  return json(res, 200, { ok: true }); }
      if (wm[2] === 'delete') { stopWatcher(w, true); watchers.delete(w.id); saveWatchers(); return json(res, 200, { ok: true }); }
      const err = applyWatcherConfig(w, await readBody(req));
      if (err) return json(res, 400, { error: err });
      addWLog(w, `Configuración actualizada: ${w.cinemas.map(c => c.name).join(', ')}`);
      saveWatchers();
      return json(res, 200, { ok: true, watcher: publicWatcher(w) });
    }

    const m = pathname.match(JOB_ROUTE);
    if (m && method === 'POST') {
      const job = jobs.get(m[1]);
      if (!job) return json(res, 404, { error: 'Job no encontrado' });
      const action = m[2];

      if (!action) {                       // actualizar configuración
        applyConfig(job, await readBody(req));
        addLog('Configuración actualizada', 'info', job);
        saveJobs();
        return json(res, 200, { ok: true, job: publicJob(job) });
      }
      if (action === 'start') {
        const r = startJob(job);
        return json(res, r.ok ? 200 : 400, r);
      }
      if (action === 'stop') {
        stopJob(job);
        return json(res, 200, { ok: true });
      }
      if (action === 'pause')  { setPaused(job, true);  return json(res, 200, { ok: true }); }
      if (action === 'resume') { setPaused(job, false); return json(res, 200, { ok: true }); }
      if (action === 'ack') {                // descartar el aviso (vuelve a avisar si cambian las butacas libres)
        if (job.alert) { job.alert.ack = true; saveJobs(); }
        return json(res, 200, { ok: true });
      }
      if (action === 'test')         return json(res, 200, await doReserve(job, true, 'test'));
      if (action === 'reserve-once') return json(res, 200, await doReserve(job, false, 'manual'));
      if (action === 'delete') {
        stopJob(job);
        jobs.delete(job.id);
        addLog('Job eliminado', 'info', job);
        saveJobs();
        return json(res, 200, { ok: true });
      }
    }

    if (method === 'POST' && pathname === '/bot/history/clear') {
      const { jobId } = await readBody(req);
      for (const j of jobs.values()) if (!jobId || j.id === jobId) j.history = [];
      saveJobs();
      return json(res, 200, { ok: true });
    }

    // ── Cookies / tokens del cine (compartidos por todos los jobs) ──────

    if (method === 'GET' && pathname === '/bot/session') {
      return json(res, 200, { sessionReady, cookies: jar.dump() });
    }

    if (method === 'POST' && pathname === '/bot/session') {
      const b = await readBody(req);
      if (!b.cookies || typeof b.cookies !== 'object') return json(res, 400, { error: 'Falta cookies' });
      jar.replace(b.cookies);
      sessionReady = true;
      addLog(`Cookies actualizadas manualmente (${jar.size()})`);
      return json(res, 200, { ok: true, cookies: jar.dump() });
    }

    if (method === 'POST' && pathname === '/bot/reset-session') {
      sessionReady = false;
      await initSession(true);
      return json(res, 200, { ok: true, cookieCount: jar.size() });
    }

    // ── Archivos estáticos ───────────────────────────────────────────────────
    if (method !== 'GET') return json(res, 404, { error: 'No encontrado' });
    return serveFile(res, pathname === '/' ? 'index.html' : pathname.slice(1));

  } catch (err) {
    console.error(err);
    return json(res, 500, { error: err.message });
  }

}).listen(PORT, HOST, async () => {
  console.log(`\n🎬 Cine Bot → http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log(`   Node.js ${process.version} · ${appPasswords().length} contraseñas de usuario · ${jobs.size} jobs\n`);
  await initSession();
  for (const job of jobs.values()) if (job.running) startJob(job, true);
  for (const w of watchers.values()) if (w.running) startWatcher(w, true);
});
