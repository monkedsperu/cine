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

const DEFAULTS = { intervalMs: 600000, retryMinMs: 10000, retryMaxMs: 20000, ticketCode: '0050' };

// Campos de configuración que el panel puede fijar
const CONFIG_KEYS = ['name', 'cinemaId', 'cinemaName', 'movieId', 'movieTitle', 'posterUrl', 'sessionId',
  'showtime', 'screenName', 'day', 'ticketCode', 'ticketDesc', 'targetSeats',
  'intervalMs', 'retryMinMs', 'retryMaxMs', 'endAt', 'adaptive'];

// Estado persistido además de la configuración
const STATE_KEYS = ['id', 'createdAt', 'userSessionId', 'running', 'attempts', 'successes', 'lastResult', 'history',
  'heldSeats', 'lastReservedAt', 'cycle', 'holdSamples', 'holdHint', 'seatState'];

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
    endAt: null, adaptive: true,
    running: false, mode: 'normal', nextAt: null, busy: false,
    attempts: 0, successes: 0, lastResult: null, history: [],
    heldSeats:      [],     // etiquetas reservadas en la última reserva exitosa (retención propia)
    lastReservedAt: null,   // ms de esa reserva
    cycle:          null,   // vuelta actual: { reservedAt, plan, step, sawOccupied, lastOccupiedAt, measured, retrying }
    holdSamples:    [],     // mediciones reales de la retención: { ms, loMs, hiMs, at }
    holdHint:       null,   // estimación de un solo uso (ms): la retención duró menos de esto
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
  // Otra función → la retención aprendida ya no aplica; otros asientos → la retención actual tampoco.
  // En ambos casos, orden nueva (otro userSessionId): el cine acumula las entradas en la orden del
  // userSessionId, así que con el mismo id las butacas nuevas se sumarían a las de la reserva anterior.
  const seatsChanged = JSON.stringify(job.targetSeats) !== prevSeats;
  if (job.sessionId !== prevSession || seatsChanged) {
    const hadHold = job.heldSeats?.length > 0;
    if (job.sessionId !== prevSession) { job.holdSamples = []; job.holdHint = null; }
    resetHold(job);
    job.userSessionId = genSessionId();
    if (hadHold) addLog('Butacas o función cambiadas: se usará una orden nueva; la retención anterior se liberará sola', 'info', job);
  }
  if (job.running) armEndTimer(job);
}

// Retención aprendida: la menor de las últimas mediciones reales (más vale revisar antes que tarde)
function learnedHold(job) {
  return job.holdSamples?.length ? Math.min(...job.holdSamples.map(x => x.ms)) : null;
}

// Puntos de revisión tras reservar (ms desde la reserva). Con una retención H conocida o estimada:
// a la mitad, faltando un tercio, faltando un cuarto y faltando 20 s; después, reintentos aleatorios.
// Sin H (o sin espera adaptativa): una sola revisión al cumplirse el intervalo fijo.
function checkPlan(job) {
  const known = [learnedHold(job), job.holdHint].filter(Boolean);
  if (!job.adaptive || !known.length) return [job.intervalMs];
  const H = Math.min(...known);
  const plan = [];
  for (const p of [H / 2, H * 2 / 3, H * 3 / 4, H - 20000].map(Math.round)) {
    if (p >= 5000 && (!plan.length || p - plan[plan.length - 1] >= 5000)) plan.push(p);
  }
  return plan.length ? plan : [Math.max(5000, Math.round(H / 2))];
}

function publicJob(job, historyLimit = 100) {
  const out = {};
  for (const k of [...CONFIG_KEYS, ...STATE_KEYS, 'mode', 'nextAt', 'busy']) out[k] = job[k];
  out.history = job.history.slice(0, historyLimit);
  out.learnedHoldMs = learnedHold(job);
  out.nextPlanMs    = checkPlan(job);   // plan que se usará tras la próxima reserva
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
async function attemptReserve(job, dryRun = false) {
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

    // 3. La retención terminó: medir cuánto duró
    const c = job.cycle;
    if (c && c.reservedAt && !c.measured) {
      c.measured = true;
      const elapsed = now - c.reservedAt;
      const min = ms => `${(ms / 60000).toFixed(1)} min`;
      if (c.sawOccupied) {
        // Medición real: se liberó entre la última revisión en que seguía ocupada y esta
        const lo = c.lastOccupiedAt - c.reservedAt;
        const ms = Math.round((lo + elapsed) / 2);
        holdInfo = { holdMs: ms, holdLoMs: lo, holdHiMs: elapsed };
        job.holdSamples = [...(job.holdSamples || []), { ms, loMs: lo, hiMs: elapsed, at: now }].slice(-HOLD_SAMPLES);
        job.holdHint = null;
        addLog(`Retención liberada tras ~${min(ms)} (entre ${min(lo)} y ${min(elapsed)})`, 'info', job);
      } else {
        // Ya estaba libre en la primera revisión: solo se sabe que duró menos. No es una medición;
        // se usa como estimación para la próxima vuelta, que revisará antes y la medirá bien.
        job.holdHint = elapsed;
        addLog(`Las butacas ya estaban libres en la primera revisión (${min(elapsed)}): la retención duró menos. La próxima vuelta revisará antes para medirla`, 'info', job);
      }
    }
    job.heldSeats = [];

    // 4. Qué butacas se pueden reservar ahora
    const free  = targetSeats.filter(t => st[t.label] === 'free');
    const taken = targetSeats.filter(t => st[t.label] !== 'free');
    job.seatState = Object.fromEntries(targetSeats.map(t => [t.label, st[t.label] === 'free' ? 'free' : 'taken']));
    const takenTxt = taken.map(t => `${t.label}(${st[t.label] === 'missing' ? 'no existe' : 'ocupado'})`).join(', ');
    const labels   = arr => arr.map(t => t.label);

    if (!free.length) {
      const msg = `No disponibles: ${takenTxt}`;
      addLog(msg, 'warn', job);
      return { success: false, error: msg, taken: labels(taken), ...holdInfo };
    }
    if (taken.length) addLog(`${takenTxt} ya no ${taken.length > 1 ? 'están disponibles' : 'está disponible'}; se continúa con ${labels(free).join(', ')}`, 'warn', job);
    else              addLog(`Asientos disponibles ✓ ${labels(free).join(',')}`, 'info', job);

    if (dryRun) {
      addLog(`[TEST] Se reservarían: ${labels(free).join(', ')}`, 'success', job);
      return { success: true, dryRun: true, partial: taken.length > 0, seats: labels(free), taken: labels(taken), ...holdInfo };
    }

    // 5. Tipos de ticket y reserva. Si el cine responde 5xx (p. ej. 502 "VSS"),
    // se renuevan la sesión y el userSessionId del job, y se reintenta una vez al momento.
    let result;
    try {
      result = await addTickets(job, area, free);
    } catch (e) {
      if (!(e.status >= 500)) throw e;
      addLog(`${e.message}`, 'error', job);
      addLog('Error del servidor del cine: renovando sesión y userSessionId, y reintentando...', 'warn', job);
      job.userSessionId = genSessionId();
      await initSession(true);
      result = await addTickets(job, area, free);
    }

    if (result.Result === 0 && result.Order) {
      const orderSeats = (result.Order.Sessions || []).flatMap(s => (s.Tickets || []).map(t => t.SeatData)).filter(Boolean);
      const reserved   = orderSeats.join(', ') || labels(free).join(', ');
      const total      = (result.Order.TotalValueCents / 100).toFixed(2);
      if (orderSeats.length > free.length) {
        addLog(`La orden tiene ${orderSeats.length} butacas (${reserved}) pero se pidieron ${free.length}: incluye butacas de una reserva anterior`, 'warn', job);
      }
      job.successes++;
      job.heldSeats      = labels(free);
      job.lastReservedAt = Date.now();
      job.cycle          = { reservedAt: job.lastReservedAt, plan: checkPlan(job), step: 0,
                             sawOccupied: false, lastOccupiedAt: null, measured: false, retrying: false };
      for (const t of free) job.seatState[t.label] = 'held';
      addLog(taken.length
        ? `✅ RESERVA PARCIAL: ${reserved} | S/.${total} · no disponibles: ${labels(taken).join(', ')}`
        : `✅ RESERVADO: ${reserved} | S/.${total}`, 'success', job);
      return { success: true, partial: taken.length > 0, seats: reserved, total, taken: labels(taken), ...holdInfo };
    }
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
  try { r = await attemptReserve(job, dryRun); }
  finally { job.busy = false; }

  job.lastResult = { ...r, timestamp: new Date().toISOString() };
  job.history.unshift({
    time:     new Date().toISOString(),
    source,
    success:  !!r.success,
    dryRun:   !!r.dryRun,
    // reserved | partial | hold (retención propia activa) | failed | test
    kind:     r.dryRun ? 'test' : r.success ? (r.partial ? 'partial' : 'reserved') : r.holdActive ? 'hold' : 'failed',
    msg:      r.success
      ? (r.dryRun ? `Disponibles: ${[].concat(r.seats).join(', ')}` : `Reservado ${r.seats} · S/.${r.total}`)
        + (r.taken?.length ? ` · no disponibles: ${r.taken.join(', ')}` : '')
      : r.error,
    taken:    r.taken || [],
    holdMs:   r.holdMs || null,   // retención medida si se liberó en este intento (con su rango)
    holdLoMs: r.holdLoMs ?? null,
    holdHiMs: r.holdHiMs ?? null,
    nextInMs: null,
  });
  if (job.history.length > 500) job.history.pop();
  saveJobs();
  return r;
}

// Tras reservar: revisiones en los puntos del plan (checkPlan). Si la retención sigue activa al
// agotarse el plan, o si un intento falla: reintentos aleatorios entre retryMin y retryMax.
async function runTick(job) {
  if (!job.running) return;
  job.nextAt = null;
  const r = await doReserve(job, false, 'auto');
  if (!job.running) return;

  const range = `${job.retryMinMs / 1000}-${job.retryMaxMs / 1000}s`;
  const min   = ms => (ms / 60000).toFixed(1);
  const c     = job.cycle;
  let delay;
  if ((r.success || r.holdActive) && c?.plan && c.step < c.plan.length) {
    // Siguiente punto del plan, contado desde la reserva
    delay = Math.max(1000, c.reservedAt + c.plan[c.step] - Date.now());
    c.step++;
  } else {
    delay = randomRetry(job);
    if (r.holdActive && c && !c.retrying) {
      c.retrying = true;
      addLog(`Sigue retenida tras la última revisión programada; reintentando cada ${range} hasta que se libere`, 'info', job);
    }
  }

  if (!r.skipped) {
    const mode = r.success ? 'normal' : r.holdActive ? 'hold' : 'retry';
    if (mode !== job.mode) {
      if (mode === 'retry') addLog(`Reserva fallida; reintentando cada ${range}`, 'warn', job);
      if (mode === 'normal' && job.mode === 'retry') addLog('Reserva recuperada', 'info', job);
    }
    if (r.success && c?.plan) {
      const adaptivePlan = job.adaptive && (learnedHold(job) || job.holdHint);
      addLog(adaptivePlan
        ? `Revisiones programadas a los ${c.plan.map(min).join(', ')} min; si sigue retenida, cada ${range}`
        : `Próxima revisión en ${min(delay)} min (intervalo fijo)`, 'info', job);
    }
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
  const plan   = checkPlan(job);
  const espera = plan.length > 1 || (job.adaptive && (learnedHold(job) || job.holdHint))
    ? `revisiones a los ${plan.map(ms => (ms / 60000).toFixed(1)).join(', ')} min` : `revisión a los ${job.intervalMs / 1000}s`;
  addLog(`${resumed ? 'Job reanudado' : 'Job iniciado'}: ${espera} tras reservar, reintento ${job.retryMinMs / 1000}-${job.retryMaxMs / 1000}s si falla${fin}`, 'info', job);
  armEndTimer(job);
  runTick(job);   // primer intento inmediato
  saveJobs();
  return { ok: true };
}

function armEndTimer(job) {
  clearTimeout(job.endTimer); job.endTimer = null;
  if (!job.running || !job.endAt) return;
  job.endTimer = setTimeout(() => {
    addLog('Hora de fin alcanzada', 'info', job);
    stopJob(job);
  }, Math.max(0, job.endAt - Date.now()));
}

function stopJob(job) {
  job.running = false;
  clearTimeout(job.timer);    job.timer = null;
  clearTimeout(job.endTimer); job.endTimer = null;
  job.nextAt = null;
  job.mode   = 'normal';
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
  jobs.set(job.id, job);
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

const JOB_ROUTE = /^\/bot\/jobs\/([a-f0-9]+)(?:\/(start|stop|test|reserve-once|delete))?$/;

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
      const data = await cpGet('/api/v1-web/cache/cinemascache');
      const cinemas = Array.isArray(data) ? data : (data.cinemas || data);
      const list = cinemas.map(c => ({
        id:   c.ID   || c.id || c.cinemaId || c.Id,
        name: c.name || c.Name || c.description || c.Description,
        slug: c.formattedCinemaName || c.slug || c.Slug || '',
      })).filter(c => c.id && c.name)
         .sort((a, b) => a.name.localeCompare(b.name));
      return json(res, 200, { cinemas: list });
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
});
