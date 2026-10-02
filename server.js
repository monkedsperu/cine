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
const TG_TOKEN          = process.env.TELEGRAM_BOT_TOKEN || '';                  // avisos por Telegram (opcional)
const TG_CHAT           = process.env.TELEGRAM_CHAT_ID || '';
const CINE_RPS          = Math.max(1, parseFloat(process.env.CINE_RPS) || 15);      // peticiones por segundo al cine (máx.)
const CINE_CONCURRENCY  = Math.max(1, parseInt(process.env.CINE_CONCURRENCY) || 10); // peticiones simultáneas al cine (máx.)
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
// Admin: ADMIN_PASSWORD. Usuarios: APP_PASSWORDS del .env + las creadas en el panel, menos las
// revocadas desde el panel. En data/auth.json las creadas se guardan con hash (scrypt), nunca en claro,
// y cada contraseña se identifica por un id. Las sesiones se guardan en data/sessions.json (por hash del token).

const auth = readData('auth.json', { created: [], revoked: [] });
const saveAuth = () => writeData('auth.json', auth);
const sha = v => crypto.createHash('sha256').update(String(v)).digest('hex');
const envId = p => 'env-' + sha('env:' + p).slice(0, 12);

function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `${salt}:${crypto.scryptSync(String(pw), salt, 32).toString('hex')}`;
}
function verifyPassword(pw, stored) {
  const [salt, hex] = String(stored || '').split(':');
  if (!salt || !hex) return false;
  return crypto.timingSafeEqual(crypto.scryptSync(String(pw), salt, 32), Buffer.from(hex, 'hex'));
}
const hintOf = pw => `${String(pw).slice(0, 2)}${'•'.repeat(Math.max(2, Math.min(6, String(pw).length - 2)))}`;

// Migración: versiones anteriores guardaban las contraseñas en claro
{
  let migrated = false;
  auth.created = (auth.created || []).map(c => {
    if (!c.password) return c;
    migrated = true;
    return { id: 'pw-' + crypto.randomBytes(6).toString('hex'), hash: hashPassword(c.password), hint: hintOf(c.password), label: c.label || '', createdAt: c.createdAt || null };
  });
  auth.revoked = (auth.revoked || []).map(r => {
    if (/^env-[0-9a-f]{12}$/.test(r)) return r;
    migrated = true;
    return envId(r);
  });
  if (migrated) { saveAuth(); console.log('🔐 Contraseñas del panel migradas a hash'); }
}

function appPasswords() {
  const list = [];
  const seen = new Set();
  for (const p of ENV_APP_PASSWORDS) {
    const id = envId(p);
    if (auth.revoked.includes(id) || seen.has(id)) continue;
    seen.add(id);
    list.push({ id, hint: hintOf(p), label: '', source: 'env', createdAt: null });
  }
  for (const c of auth.created) list.push({ id: c.id, hint: c.hint, label: c.label, source: 'panel', createdAt: c.createdAt });
  return list;
}

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// Devuelve el id de la contraseña de usuario que coincide, o null
function matchUserPassword(pw) {
  for (const p of ENV_APP_PASSWORDS) if (safeEqual(pw, p) && !auth.revoked.includes(envId(p))) return envId(p);
  for (const c of auth.created) if (verifyPassword(pw, c.hash)) return c.id;
  return null;
}

function checkPassword(pw) {
  if (!pw) return null;
  if (safeEqual(pw, ADMIN_PASSWORD)) return { role: 'admin', pwId: null };
  const id = matchUserPassword(pw);
  return id ? { role: 'user', pwId: id } : null;
}

const SESSION_TTL = 7 * 24 * 3600 * 1000;
// hash del token → { role, pwId, expires }. Se guardan para que un reinicio no cierre las sesiones.
const sessions = new Map(Object.entries(readData('sessions.json', {})).filter(([, v]) => v.expires > Date.now()));
let saveSessTimer = null;
function saveSessions() {
  clearTimeout(saveSessTimer);
  saveSessTimer = setTimeout(() => {
    try { writeData('sessions.json', Object.fromEntries(sessions)); } catch (e) { console.error('No se pudo guardar sessions.json:', e.message); }
  }, 300);
}

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
  const key = token && sha(token);
  const s = key && sessions.get(key);
  if (!s) return null;
  // Expirada, o su contraseña fue eliminada → fuera
  if (s.expires < Date.now() || (s.role === 'user' && !appPasswords().some(p => p.id === s.pwId))) {
    sessions.delete(key);
    saveSessions();
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

// ─── LÍMITE DE TRÁFICO AL CINE ─────────────────────────────────────────────
// Todas las peticiones al cine pasan por aquí: como mucho CINE_RPS por segundo y CINE_CONCURRENCY a la
// vez. Las reservas (POST) tienen prioridad sobre las consultas, así un disparo no espera detrás de GETs.

const limiter = { tokens: CINE_RPS, last: Date.now(), active: 0, high: [], low: [], timer: null };
const traffic = { perMin: [], lastError: null };   // para la barra de estado del panel

function pumpLimiter() {
  const now = Date.now();
  limiter.tokens = Math.min(CINE_RPS, limiter.tokens + (now - limiter.last) / 1000 * CINE_RPS);
  limiter.last = now;
  while (limiter.active < CINE_CONCURRENCY && limiter.tokens >= 1) {
    const next = limiter.high.shift() || limiter.low.shift();
    if (!next) return;
    limiter.tokens--; limiter.active++;
    next();
  }
  if ((limiter.high.length || limiter.low.length) && !limiter.timer)
    limiter.timer = setTimeout(() => { limiter.timer = null; pumpLimiter(); }, Math.max(5, Math.ceil(1000 / CINE_RPS)));
}
const acquireSlot = high => new Promise(res => { (high ? limiter.high : limiter.low).push(res); pumpLimiter(); });
function releaseSlot() { limiter.active--; pumpLimiter(); }

function countRequest() {
  const now = Date.now();
  traffic.perMin.push(now);
  while (traffic.perMin.length && now - traffic.perMin[0] > 60000) traffic.perMin.shift();
}

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

  await acquireSlot(opts.method === 'POST');
  let res;
  try { res = await fetch(url, { ...opts, headers }); countRequest(); }
  catch (e) { traffic.lastError = { at: Date.now(), msg: e.message }; throw e; }
  finally { releaseSlot(); }
  if (res.status >= 400) traffic.lastError = { at: Date.now(), msg: `HTTP ${res.status} en ${new URL(url).pathname}` };

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

let sessionInit = null;   // renovación en curso: los demás esperan la misma en lugar de pisarla
function initSession(force = false) {
  if (sessionReady && !force) return Promise.resolve(true);
  if (!sessionInit) sessionInit = doInitSession().finally(() => { sessionInit = null; });
  return sessionInit;
}

async function doInitSession() {
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

// Mensajes informativos que igual son importantes para el análisis del job
const IMPORTANT_INFO = /Retención liberada|Hueco|Ráfaga|Renovaci|Liberadas|Vuelven|Compradas|Pausa|Job iniciado|Job reanudado|Job detenido|Job creado|Hora de fin|ya estaban libres|Configuración actualizada/;

function addLog(msg, type = 'info', job = null) {
  const entry = { time: new Date().toISOString(), msg, type, jobId: job?.id || null, jobName: job?.name || null };
  // Registro importante por job (no los vigías: tienen su propio registro)
  if (job && jobs.has(job.id) && (type !== 'info' || IMPORTANT_INFO.test(msg))) {
    job.events = job.events || [];
    job.events.unshift({ time: entry.time, type, msg });
    if (job.events.length > 200) job.events.length = 200;
  }
  logs.unshift(entry);
  if (logs.length > 300) logs.pop();
  const tag = type === 'error' ? '❌' : type === 'success' ? '✅' : type === 'warn' ? '⚠️' : '·';
  console.log(`${tag} ${job ? `[${job.name}] ` : ''}${msg}`);
}

// ─── AVISOS POR TELEGRAM ───────────────────────────────────────────────────
// Opcional (.env: TELEGRAM_BOT_TOKEN y TELEGRAM_CHAT_ID). Llegan aunque el panel esté cerrado.
// `key` evita repetir el mismo aviso; además se espacian para no pasar el límite de Telegram.

const tgSent  = new Map();   // key → ms del último envío
const tgQueue = [];
let tgBusy = false;

function notify(text, key = null, everyMs = 30 * 60000) {
  if (!TG_TOKEN || !TG_CHAT) return;
  if (key) {
    const last = tgSent.get(key);
    if (last && Date.now() - last < everyMs) return;
    tgSent.set(key, Date.now());
  }
  tgQueue.push(String(text).slice(0, 3500));
  if (tgQueue.length > 50) tgQueue.shift();
  drainTelegram();
}

async function drainTelegram() {
  if (tgBusy) return;
  tgBusy = true;
  while (tgQueue.length) {
    const text = tgQueue.shift();
    try {
      const r = await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: TG_CHAT, text, disable_web_page_preview: true }),
      });
      if (!r.ok) console.error('Telegram:', r.status, (await r.text().catch(() => '')).slice(0, 200));
    } catch (e) { console.error('Telegram:', e.message); }
    await new Promise(r => setTimeout(r, 1100));
  }
  tgBusy = false;
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
  threads:     3,        // hilos (balas) por reserva: se turnan para revisar y disparan juntos al ver butacas libres
  maxPerOrder: 10,       // butacas por orden (add-tickets); más butacas se reparten en varias órdenes
  fireMode:    'backup', // 'backup': un hilo por orden y, si falla por error del cine, el siguiente al instante; 'all': todos a la vez
  holdGuessMs: 0,        // retención conocida del cine (0 = medirla): permite apuntar la ráfaga desde la primera vuelta
  burst:           true, // ráfaga al vencer: alrededor del vencimiento esperado se revisa cada burstIntervalMs
  burstLeadMs:     8000, //   empieza esto antes del vencimiento esperado
  burstIntervalMs: 1000,
  burstSpanMs:    30000, //   y sigue hasta esto después
  renew:       false,    // experimental: reenviar cada orden con su mismo userSessionId antes de que venza
  renewLeadMs: 45000,    //   cuánto antes del vencimiento esperado
};
const BURST_MIN_MS = 500;

// Perfiles de ritmo: el panel y /preestreno los muestran y los aplican con un clic. El perfil queda
// guardado en el job; si luego se cambia algún valor, el panel lo muestra como "ajustado".
const PROFILES = {
  preventa: {
    label: '⚡ Preventa',
    values: { intervalMs: 180000, baselineMs: 10000, windowMinMs: 5000, windowMaxMs: 10000, retryMinMs: 3000, retryMaxMs: 5000,
              threads: 3, fireMode: 'backup', burst: true, burstLeadMs: 8000, burstIntervalMs: 1000, burstSpanMs: 30000 },
    info: ['Para estrenos y preventas muy pedidos: todos quieren las mismas butacas.',
           'Revisa la sala seguido: sin medición a los 3 min, complementaria cada 10 s, ventana cada 5–10 s, reintentos cada 3–5 s.',
           'Ráfaga al vencer cada 1 s, desde 8 s antes hasta 30 s después: el hueco queda en ~1 s.',
           '3 hilos con respaldo. Más tráfico hacia el cine.'],
  },
  normal: {
    label: 'Normal',
    values: { intervalMs: 600000, baselineMs: 60000, windowMinMs: 30000, windowMaxMs: 60000, retryMinMs: 10000, retryMaxMs: 20000,
              threads: 1, fireMode: 'backup', burst: true, burstLeadMs: 5000, burstIntervalMs: 2000, burstSpanMs: 20000 },
    info: ['Para funciones con poca demanda: nadie compite por las butacas.',
           'Ritmo tranquilo: sin medición a los 10 min, complementaria cada 60 s, ventana cada 30–60 s, reintentos cada 10–20 s.',
           'Ráfaga suave al vencer (cada 2 s, desde 5 s antes): hueco de unos pocos segundos.',
           '1 hilo. Poco tráfico hacia el cine.'],
  },
};
const PROFILE_KEYS = Object.keys(PROFILES.preventa.values);
// Valores que difieren del perfil (para mostrar "ajustado")
function profileDiff(obj) {
  const p = PROFILES[obj.profile];
  return p ? PROFILE_KEYS.filter(k => obj[k] !== p.values[k]) : [];
}
// Perfil que corresponde a unos valores (jobs de versiones anteriores, sin perfil guardado)
function profileOf(obj) {
  return Object.keys(PROFILES).find(n => PROFILE_KEYS.every(k => obj[k] === PROFILES[n].values[k])) || 'custom';
}
const MIN_TICK_MS = 1000;   // nunca se revisa más seguido que esto

// Campos de configuración que el panel puede fijar
const CONFIG_KEYS = ['name', 'cinemaId', 'cinemaName', 'movieId', 'movieTitle', 'posterUrl', 'sessionId',
  'showtime', 'screenName', 'day', 'ticketCode', 'ticketDesc', 'targetSeats',
  'intervalMs', 'retryMinMs', 'retryMaxMs', 'baselineMs', 'windowMinMs', 'windowMaxMs', 'endAt', 'adaptive',
  'threads', 'maxPerOrder', 'fireMode', 'holdGuessMs', 'burst', 'burstLeadMs', 'burstIntervalMs', 'burstSpanMs',
  'renew', 'renewLeadMs', 'profile'];

// Estado persistido además de la configuración
const STATE_KEYS = ['id', 'createdAt', 'userSessionId', 'running', 'attempts', 'successes', 'lastResult', 'history',
  'heldSeats', 'lastReservedAt', 'cycle', 'holdSamples', 'holdHint', 'seatState',
  'uidReservations', 'orderExpiryInfo', 'expiryChecked', 'paused', 'watcherId',
  'heldAt', 'orderLimit', 'turn', 'orders', 'renewState', 'exposure', 'lostSeats', 'releases', 'bought', 'releaseWatchMs', 'failStreak',
  'timeline', 'events',
  'notified', 'prevCycle'];

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
    endAt: null, adaptive: true, threads: DEFAULTS.threads, maxPerOrder: DEFAULTS.maxPerOrder,
    fireMode: DEFAULTS.fireMode, holdGuessMs: DEFAULTS.holdGuessMs,
    burst: DEFAULTS.burst, burstLeadMs: DEFAULTS.burstLeadMs, burstIntervalMs: DEFAULTS.burstIntervalMs, burstSpanMs: DEFAULTS.burstSpanMs,
    renew: DEFAULTS.renew, renewLeadMs: DEFAULTS.renewLeadMs, profile: null,
    renewState:     null,   // renovación experimental: null | 'testing' | 'works' | 'fails'
    exposure:       [],     // huecos medidos al re-reservar: { ms, maxMs, at, lost }
    lostSeats:      0,      // butacas propias que otra persona tomó en el hueco (acumulado)
    releases:       {},     // butacas liberadas para que las compres tú: etiqueta → { at, status, since, ack }
                            //   status: 'waiting' (aún retenida/ocupada) | 'free' (¡libre! aviso) | 'gone' (se ocupó tras estar libre)
    bought:         [],     // etiquetas que marcaste como compradas (ya no son objetivo del job)
    releaseWatchMs: 0,      // vigilante independiente de las liberadas: revisa cada tantos ms (0 = no)
    timeline:       [],     // estado del bloque en el tiempo: { t, held, taken, free, rel, n } (panel de análisis)
    events:         [],     // registros importantes del job (reservas, huecos, avisos, errores…)
    failStreak:     0,      // intentos fallidos seguidos (para avisar)
    notified:       {},     // avisos de Telegram ya enviados (para no repetir)
    prevCycle:      null,   // vuelta anterior { reservedAt, releasedAt }: detecta butacas perdidas en el hueco
    running: false, mode: 'normal', nextAt: null, busy: false,
    attempts: 0, successes: 0, lastResult: null, history: [],
    heldSeats:      [],     // etiquetas retenidas por el job (en una o varias órdenes)
    heldAt:         {},     // etiqueta → ms en que se reservó
    orders:         [],     // órdenes vigentes: { uid, seats, at, hilo }
    orderLimit:     null,   // límite de butacas por orden aprendido (el cine rechazó órdenes más grandes)
    turn:           0,      // último hilo que revisó (se turnan 1..threads)
    pool:           [],     // balas cargadas: userSessionId ya registrados con gettickets { uid, at } (no se guarda)
    lastReservedAt: null,   // ms de esa reserva
    cycle:          null,   // vuelta actual: { reservedAt, newOrder, orderSeq, expiresAt, sawOccupied, lastOccupiedAt, measured, phase }
    holdSamples:    [],     // mediciones reales de la retención: { ms, loMs, hiMs, at, newOrder, orderSeq }
    holdHint:       null,   // estimación de un solo uso (ms): la retención duró menos de esto
    uidReservations: 0,     // reservas hechas con el userSessionId actual (0 → la próxima abre una orden nueva)
    paused:         false,  // en pausa = todas sus butacas liberadas para ti (ver releases)
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
  job.heldSeats = []; job.heldAt = {}; job.orders = []; job.lastReservedAt = null; job.cycle = null; job.seatState = {};
  job.pool = []; job.orderLimit = null;
}

function applyConfig(job, b) {
  const prevSession = job.sessionId;
  const prevSeats   = JSON.stringify(job.targetSeats);
  for (const k of CONFIG_KEYS) if (k in b) job[k] = b[k];
  job.name       = String(job.name || '').trim().slice(0, 60) || job.movieTitle || 'Job';
  job.intervalMs = Math.max(5000, parseInt(job.intervalMs) || DEFAULTS.intervalMs);
  job.retryMinMs = Math.max(1000, parseInt(job.retryMinMs) || DEFAULTS.retryMinMs);
  job.retryMaxMs = Math.max(job.retryMinMs, parseInt(job.retryMaxMs) || job.retryMinMs);
  job.endAt      = job.endAt ? (new Date(job.endAt).getTime() || null) : null;
  job.targetSeats = Array.isArray(job.targetSeats) ? job.targetSeats : [];
  job.adaptive   = job.adaptive !== false;
  job.threads     = Math.min(6, Math.max(1, parseInt(job.threads) || DEFAULTS.threads));
  job.maxPerOrder = Math.min(50, Math.max(1, parseInt(job.maxPerOrder) || DEFAULTS.maxPerOrder));
  job.fireMode    = job.fireMode === 'all' ? 'all' : 'backup';
  job.holdGuessMs = Math.max(0, parseInt(job.holdGuessMs) || 0);
  job.burst       = job.burst !== false;
  const bLead = parseInt(job.burstLeadMs);
  job.burstLeadMs     = Number.isFinite(bLead) ? Math.min(120000, Math.max(0, bLead)) : DEFAULTS.burstLeadMs;
  job.burstIntervalMs = Math.max(BURST_MIN_MS, parseInt(job.burstIntervalMs) || DEFAULTS.burstIntervalMs);
  job.burstSpanMs     = Math.min(600000, Math.max(1000, parseInt(job.burstSpanMs) || DEFAULTS.burstSpanMs));
  job.renew       = !!job.renew;
  if (!(job.profile in PROFILES) && job.profile !== 'custom') job.profile = profileOf(job);
  job.renewLeadMs = Math.min(600000, Math.max(5000, parseInt(job.renewLeadMs) || DEFAULTS.renewLeadMs));
  const bl = parseInt(job.baselineMs);
  job.baselineMs  = bl === 0 ? 0 : Math.max(2000, bl || DEFAULTS.baselineMs);
  job.windowMinMs = Math.max(1000, parseInt(job.windowMinMs) || DEFAULTS.windowMinMs);
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
  if (lo == null && job.holdGuessMs) lo = job.holdGuessMs;                    // retención conocida, sin medir aún
  if (!job.adaptive || lo == null) return { ...base, mode: 'interval', target: job.intervalMs };
  const windowStart = Math.max(5000, lo - 20000);
  return {
    ...base, mode: 'range', minMs: lo, maxMs: Math.max(hi || lo, lo),
    points: [lo / 2, lo * 2 / 3, lo * 3 / 4].map(Math.round).filter(p => p >= 5000 && p < windowStart),
    windowStart, windowEnd: Math.max(hi || lo, lo),
  };
}

// Cuándo se espera que se liberen las butacas (ms desde la reserva), o null si aún no se sabe
function expectMs(job, cycle) {
  const sch = holdSchedule(job, cycle);
  return sch.mode === 'expiry' ? sch.target + 20000 : sch.mode === 'range' ? sch.minMs : null;
}

const randBetween = (a, b) => a + Math.floor(Math.random() * (b - a + 1));
const effSec = (job, ms) => +(ms / 1000).toFixed(1);

// Espera hasta la próxima revisión de una vuelta en retención; registra en consola los cambios de fase
function holdDelay(job) {
  const c   = job.cycle;
  const sch = holdSchedule(job, c);
  const e   = Date.now() - c.reservedAt;
  // Los tiempos son el ritmo de la función: los hilos se turnan dentro de él (cada revisión la hace el siguiente)
  const baseline = sch.baselineMs > 0 ? Math.max(MIN_TICK_MS, Math.round(sch.baselineMs * (0.9 + Math.random() * 0.2))) : Infinity;
  const fmt = ms => (ms / 60000).toFixed(1);
  let phase, d;
  if (sch.mode === 'range') {
    if (e < sch.windowStart - 500) {
      phase = 'before';
      const next = sch.points.find(p => p > e + 500);
      d = Math.min(next != null ? next - e : Infinity, baseline, sch.windowStart - e);
    } else if (e < sch.windowEnd) {
      phase = 'window';
      d = Math.min(Math.max(MIN_TICK_MS, randBetween(job.windowMinMs, job.windowMaxMs)), baseline);
    } else {
      phase = 'after';
      d = randomRetry(job);
    }
  } else {
    if (e < sch.target - 500) { phase = 'before'; d = Math.min(baseline, sch.target - e); }
    else                      { phase = 'after';  d = randomRetry(job); }
  }
  // Ráfaga al vencer: alrededor del vencimiento esperado se revisa cada burstIntervalMs, para
  // re-reservar en cuanto se liberen y dejar el menor hueco posible a otros compradores
  const exp = expectMs(job, c);
  if (exp && job.burst) {
    const bStart = exp - job.burstLeadMs, bEnd = exp + job.burstSpanMs;
    if (e >= bStart - 200 && e < bEnd) { phase = 'burst'; d = job.burstIntervalMs; }
    else if (e < bStart) d = Math.min(d, bStart - e);
  }
  // Tras una renovación "confiada": ráfaga también alrededor del vencimiento original, por si dejó de funcionar
  if (c.verifyFrom && job.burst) {
    const n = Date.now();
    if (n >= c.verifyFrom - 200 && n < c.verifyUntil) { phase = 'burst'; d = job.burstIntervalMs; }
    else if (n < c.verifyFrom) d = Math.min(d, c.verifyFrom - n);
  }
  // Renovación experimental: despertar justo a tiempo para reenviar las órdenes
  if (exp && job.renew && job.renewState !== 'fails' && !c.renewTried) {
    const rAt = exp - job.renewLeadMs;
    if (e < rAt) d = Math.min(d, rAt - e);
  }
  if (phase === 'burst' && c.phase !== 'burst') {
    addLog(`Ráfaga al vencer: revisando cada ${job.burstIntervalMs / 1000}s (vencimiento esperado a los ${fmt(exp)} min)`, 'info', job);
    c.phase = phase;
    return Math.max(BURST_MIN_MS, Math.round(d));
  }
  if (phase !== c.phase && c.phase) {
    const range = `${effSec(job, job.retryMinMs)}-${effSec(job, job.retryMaxMs)}s`;
    if (phase === 'window') addLog(`Ventana probable de liberación (${fmt(sch.windowStart)}–${fmt(sch.windowEnd)} min): revisando cada ${effSec(job, job.windowMinMs)}-${effSec(job, job.windowMaxMs)}s`, 'info', job);
    if (phase === 'after')  addLog(sch.mode === 'range'
      ? `Superó la retención máxima observada (${fmt(sch.windowEnd)} min): reintentando cada ${range}`
      : `Sigue retenida tras la revisión objetivo: reintentando cada ${range}`, 'info', job);
  }
  c.phase = phase;
  return Math.max(phase === 'burst' ? BURST_MIN_MS : MIN_TICK_MS, Math.round(d));
}

// Texto del plan para la consola
function scheduleText(job, sch) {
  const fmt = ms => (ms / 60000).toFixed(1);
  const eff = ms => effSec(job, ms);
  const base = sch.baselineMs > 0 ? `revisión complementaria cada ${eff(sch.baselineMs)}s; ` : '';
  const fast = `${eff(job.retryMinMs)}-${eff(job.retryMaxMs)}s`;
  if (sch.mode === 'expiry') return `${base}vencimiento informado por el cine: revisión a los ${fmt(sch.target)} min; luego cada ${fast}`;
  if (sch.mode === 'interval') return `${base}revisión a los ${fmt(sch.target)} min (sin mediciones aún); luego cada ${fast}`;
  const burst = job.burst ? `; ráfaga cada ${job.burstIntervalMs / 1000}s desde ${fmt(sch.minMs - job.burstLeadMs)} min` : '';
  const renew = job.renew && job.renewState !== 'fails' ? `; renovación a los ${fmt(sch.minMs - job.renewLeadMs)} min (experimental)` : '';
  return `${base}${sch.points.length ? `puntos a los ${sch.points.map(fmt).join(', ')} min; ` : ''}`
    + `ventana probable ${fmt(sch.windowStart)}–${fmt(sch.windowEnd)} min cada ${eff(job.windowMinMs)}-${eff(job.windowMaxMs)}s${burst}${renew}; luego cada ${fast}`;
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
  delete out.timeline; delete out.events;
  // Liberadas para ti: 'released' (esperando que se liberen), 'forme' (¡libres, cómpralas!), 'gone' (se ocuparon)
  out.seatState = { ...job.seatState };
  for (const [l, r] of Object.entries(job.releases || {}))
    out.seatState[l] = r.status === 'free' ? 'forme' : r.status === 'gone' ? 'gone' : 'released';
  const ex = job.exposure || [];
  out.lastGapMs = ex.length ? ex[ex.length - 1].ms : null;
  const active = job.cycle && !job.cycle.measured && job.heldSeats?.length ? job.cycle : null;
  out.learnedHoldMs = learnedHold(job);
  out.schedule      = holdSchedule(job, active);   // vuelta en curso, o la que empezará tras la próxima reserva
  out.scheduleActive = !!active;
  out.profileDiff = profileDiff(job);
  // Por hilo: su última revisión y las órdenes que ganó y siguen vigentes
  const next = ((job.turn || 0) % job.threads) + 1;
  out.hilos = [...Array(job.threads)].map((_, i) => {
    const n = i + 1;
    const h = job.history.find(x => x.hilo === n);
    const ord = (job.orders || []).filter(o => o.hilo === n);
    return { n, next: job.running && n === next, lastAt: h?.time || null, kind: h?.kind || null, msg: h?.msg || '',
             orders: ord.length, seats: ord.reduce((k, o) => k + o.seats.length, 0) };
  });
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
  return Math.max(MIN_TICK_MS, randBetween(job.retryMinMs, job.retryMaxMs));
}

// Etiquetas compactas para la consola: ["H9","H10","H11","G10"] → "H9–H11, G10"
function fmtSeats(labels) {
  const rows = new Map();
  for (const l of labels) {
    const m = String(l).match(/^(.*?)(\d+)$/);
    const row = m ? m[1] : String(l);
    if (!rows.has(row)) rows.set(row, []);
    if (m) rows.get(row).push(+m[2]);
  }
  const out = [];
  for (const [row, nums] of rows) {
    if (!nums.length) { out.push(row); continue; }
    nums.sort((a, b) => a - b);
    for (let i = 0; i < nums.length;) {
      let j = i;
      while (j + 1 < nums.length && nums[j + 1] === nums[j] + 1) j++;
      out.push(j > i ? `${row}${nums[i]}–${row}${nums[j]}` : `${row}${nums[i]}`);
      i = j + 1;
    }
  }
  return out.join(', ');
}

// GET del mapa de la sala: estado de cada butaca objetivo ('free' | 'occupied' | 'missing')
async function readSeats(job) {
  const plan = await cpGet(`/api/v1-web/seatplan/cinema/${job.cinemaId}/session/${job.sessionId}`);
  const area = plan.SeatLayoutData?.Areas?.[0];
  if (!area) throw new Error('Sin datos de sala');
  const rows = area.Rows || [];
  const st = {};
  for (const t of job.targetSeats) {
    const seat = (rows[t.rowIndex]?.Seats || []).find(s => s.Position?.ColumnIndex === t.columnIndex);
    st[t.label] = !seat ? 'missing' : seat.Status === 0 ? 'free' : 'occupied';
  }
  return { area, st };
}

// Reparte las butacas en órdenes de hasta `size`, parejas y en orden de fila: así una butaca que
// otra persona toma en el último momento solo hace fallar su propia orden, no todo el bloque
function chunkSeats(seats, size) {
  const sorted = [...seats].sort((a, b) => a.rowIndex - b.rowIndex || a.columnIndex - b.columnIndex);
  const per = Math.ceil(sorted.length / Math.ceil(sorted.length / size));
  const out = [];
  for (let i = 0; i < sorted.length; i += per) out.push(sorted.slice(i, i + per));
  return out;
}

// Balas cargadas: userSessionId nuevos ya registrados en la función con gettickets, para que al ver
// butacas libres el add-tickets salga sin esperar. Se cargan mientras el job descansa.
const BULLET_TTL_MS = 10 * 60000;
const bulletsNeeded = (job, seatCount) => {
  const orders = Math.ceil(seatCount / (job.orderLimit || job.maxPerOrder));
  return job.fireMode === 'all' ? orders * job.threads : orders + job.threads - 1;
};

async function loadBullets(job, want, maxNew = want) {
  const now = Date.now();
  job.pool = (job.pool || []).filter(b => now - b.at < BULLET_TTL_MS);
  const n = Math.min(maxNew, want - job.pool.length);
  if (n <= 0) return;
  const fresh = await Promise.all([...Array(n)].map(async () => {
    const uid = genSessionId();
    const tickets = await getTickets(job.cinemaId, job.sessionId, uid);
    return { uid, at: Date.now(), ok: tickets.some(t => t.TicketTypeCode === job.ticketCode) };
  }));
  if (fresh.some(b => !b.ok)) throw new Error(`TicketTypeCode ${job.ticketCode} no disponible`);
  job.pool.push(...fresh);
}

// add-tickets de un grupo de butacas con la bala (userSessionId) dada
function postOrder(job, area, seats, uid) {
  return cpPost('/api/v1-web/add-tickets', {
    UserSessionId: uid,
    CinemaId:      job.cinemaId,
    SessionId:     job.sessionId,
    // Un solo tipo con Qty = nº de asientos, como lo envía la web
    TicketTypes:   [{ TicketTypeCode: job.ticketCode, LoyaltyRecognitionId: null, Qty: seats.length }],
    SelectedSeats: seats.map(s => ({
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
  });
}

// Disparo: las butacas se reparten en órdenes y cada orden se envía con TODOS los hilos a la vez,
// cada uno con su propia bala. Gana el que el cine acepte; los demás quedan rechazados (normal).
// Devuelve { won: [{ chunk, uid, hilo, result }], lost: [{ chunk, kind: 'error' | 'rejected', msg }] }
async function fire(job, area, seats, limit) {
  const chunks = chunkSeats(seats, limit);
  await loadBullets(job, job.fireMode === 'all' ? chunks.length * job.threads : chunks.length + job.threads - 1);
  const shoot = async (chunk, k) => {
    const uid = job.pool.shift()?.uid || genSessionId();
    try {
      const result = await postOrder(job, area, chunk, uid);
      return result.Result === 0 && result.Order
        ? { ok: true, uid, hilo: k + 1, result }
        : { ok: false, kind: 'rejected', msg: `Result=${result.Result}${result.ErrorDescription ? ` ${result.ErrorDescription}` : ''}` };
    } catch (e) {
      return { ok: false, kind: e.status >= 500 || !e.status ? 'error' : 'rejected', msg: e.message.slice(0, 160) };
    }
  };
  const results = await Promise.all(chunks.map(async chunk => {
    let shots;
    if (job.fireMode === 'all') {
      shots = await Promise.all([...Array(job.threads)].map((_, k) => shoot(chunk, k)));
    } else {
      // Respaldo: un hilo por orden; si el cine da error, el siguiente hilo dispara al instante.
      // Si la rechaza (butaca tomada), no sirve repetir: se recalcula con un GET nuevo.
      shots = [];
      for (let k = 0; k < job.threads; k++) {
        const r = await shoot(chunk, k);
        shots.push(r);
        if (r.ok || r.kind === 'rejected') break;
      }
    }
    const wins = shots.filter(s => s.ok);
    if (wins.length) return { won: wins.map(w => ({ chunk, uid: w.uid, hilo: w.hilo, result: w.result })) };
    // Sin ganador: si algún hilo tuvo error del servidor, se trata como error (se renueva la sesión)
    const err = shots.find(s => s.kind === 'error');
    return { lost: { chunk, kind: err ? 'error' : 'rejected', msg: (err || shots[0]).msg } };
  }));
  return { won: results.flatMap(r => r.won || []), lost: results.filter(r => r.lost).map(r => r.lost) };
}

// Butacas propias que otra persona tomó en el hueco entre la liberación y la nueva reserva
function lostInGap(job, labels) {
  job.lostSeats = (job.lostSeats || 0) + labels.length;
  // Se atribuyen a la última re-reserva (se detectan unos segundos después de ella)
  const last = job.exposure?.[job.exposure.length - 1];
  if (last && Date.now() - last.at < 120000) last.lost = (last.lost || 0) + labels.length;
  addLog(`⚠️ Perdidas en el hueco: ${fmtSeats(labels)} (las tomó otra persona). El job las reintenta por si se liberan`, 'warn', job);
  notify(`⚠️ ${job.name}: perdidas ${fmtSeats(labels)} en el hueco (otra persona las tomó)`);
}

// Renovación experimental: poco antes del vencimiento esperado, reenvía cada orden vigente con su mismo
// userSessionId y sus mismas butacas. Si el cine extiende la retención, no hay hueco. Se verifica sola:
// si pasado el vencimiento original las butacas siguen retenidas, funciona; si se liberan igual, se desactiva.
async function renewal(job, area, ownHeld, now) {
  const c = job.cycle;
  if (!job.renew || job.renewState === 'fails' || !c || c.measured) return;
  const exp = expectMs(job, c);
  if (!exp) return;
  const e = now - c.reservedAt;
  const min = ms => `${(ms / 60000).toFixed(1)} min`;

  // Verificación: se renovó y sigue retenida bien pasado el vencimiento original → funciona
  if (c.renewedAt && !c.renewed && e > exp + 10000) {
    job.renewState = 'works';
    addLog(`✅ Renovación confirmada: la retención siguió pasado el vencimiento original (${min(exp)}). Desde ahora se renueva antes de cada vencimiento`, 'success', job);
    notify(`✅ ${job.name}: la renovación funciona, ya no hay hueco al vencer`, `renewok-${job.id}`);
    shiftCycle(job, c, c.renewedAt);
    return;
  }
  if (c.renewTried || e < exp - job.renewLeadMs) return;

  c.renewTried = true;
  // Las órdenes con butacas liberadas para ti no se renuevan: tienen que vencer para que puedas comprarlas
  const orders = (job.orders || []).filter(o => !o.seats.some(l => job.releases?.[l]) && o.seats.some(l => ownHeld.includes(l)));
  if (!orders.length) return;
  const byLabel = Object.fromEntries(job.targetSeats.map(t => [t.label, t]));
  const res = await Promise.all(orders.map(async o => {
    const seats = o.seats.filter(l => ownHeld.includes(l)).map(l => byLabel[l]).filter(Boolean);
    try {
      const r = await postOrder(job, area, seats, o.uid);
      if (r.Result !== 0 || !r.Order) return { ok: false, msg: `Result=${r.Result}${r.ErrorDescription ? ` ${r.ErrorDescription}` : ''}` };
      const n = (r.Order.Sessions || []).reduce((k, s) => k + (s.Tickets || []).length, 0);
      return n > o.seats.length ? { ok: false, dup: true, msg: `la orden quedó con ${n} entradas para ${o.seats.length} butacas` } : { ok: true };
    } catch (err) { return { ok: false, msg: err.message.slice(0, 120) }; }
  }));
  const bad = res.find(r => !r.ok);
  if (bad) {
    job.renewState = 'fails';
    addLog(`Renovación experimental: el cine no la aceptó (${bad.msg}). Se desactiva; queda la ráfaga al vencer`, 'warn', job);
    notify(`⚠️ ${job.name}: el cine no acepta renovar la orden; se usa solo la ráfaga al vencer`, `renewfail-${job.id}`);
    return;
  }
  c.renewedAt = Date.now();
  if (job.renewState === 'works') {
    const orig = c.reservedAt;
    shiftCycle(job, c, c.renewedAt);
    c.renewed = true;
    c.verifyFrom = orig + exp - job.burstLeadMs; c.verifyUntil = orig + exp + 10000;
    addLog(`Renovadas ${orders.length} ${orders.length > 1 ? 'órdenes' : 'orden'} antes del vencimiento`, 'info', job);
  } else {
    job.renewState = 'testing';
    addLog(`Renovación experimental enviada (${orders.length} ${orders.length > 1 ? 'órdenes' : 'orden'} aceptadas): se verifica si la retención sigue pasado el vencimiento esperado (${min(exp)})`, 'info', job);
  }
}

// La retención vigente se cuenta desde `at` (tras una renovación que funcionó)
function shiftCycle(job, c, at) {
  const renewed = new Set((job.orders || []).filter(o => !o.seats.some(l => job.releases?.[l])).flatMap(o => o.seats));
  for (const l of job.heldSeats || []) if (renewed.has(l)) job.heldAt[l] = at;
  for (const o of job.orders || []) if (!o.seats.some(l => job.releases?.[l])) o.at = at;
  c.reservedAt = at; c.renewTried = false; c.renewedAt = null; c.phase = null; c.lastOccupiedAt = Date.now();
  job.lastReservedAt = at;
}

// Un intento del hilo de turno: 1) GET de disponibilidad; 2) si hay butacas objetivo libres, disparo
// de todos los hilos a la vez (add-tickets, repartido en órdenes). Si alguna orden falla, al instante:
// otro GET y otro disparo con las que siguen libres (hasta 3 rondas).
// - Las butacas propias ocupadas son la retención del job: se espera (y se aprovecha para cargar balas).
// - Cuando se liberan las de la última reserva, se mide cuánto duró la retención (espera adaptativa).
// - Las que tomó otra persona se saltan y se vuelven a intentar en cada vuelta por si se liberan.
async function attemptReserve(job, dryRun = false) {
  const { cinemaId, sessionId } = job;
  if (!cinemaId || !sessionId || !job.targetSeats.length) {
    addLog('Configuración incompleta', 'warn', job);
    return { success: false, error: 'Configuración incompleta' };
  }
  // Las liberadas para ti no se reservan: el job solo vigila que se liberen para avisarte
  const targetSeats = job.targetSeats.filter(t => !job.releases?.[t.label]);

  await ensureSession();
  job.attempts++;
  job.turn = ((job.turn || 0) % job.threads) + 1;   // hilo de turno: se turnan 1..threads
  const hilo = job.turn;
  let holdInfo = {};   // { holdMs, holdLoMs, holdHiMs } si en este intento se midió la retención
  const min = ms => `${(ms / 60000).toFixed(1)} min`;

  try {
    // 1. Disponibilidad (solo lectura)
    let { area, st } = await readSeats(job);
    const now    = Date.now();
    const heldAt = job.heldAt || {};
    updateReleases(job, st, `hilo ${hilo}`);
    if (!targetSeats.length) {
      job.seatState = {};
      return { success: false, watching: true, error: 'Todas sus butacas están liberadas para ti: solo vigila y avisa' };
    }
    // Butacas de la vuelta anterior que siguen ocupadas mucho después de que el resto se liberó:
    // otra persona las tomó en el hueco (las propias vencen todas juntas)
    const pc = job.prevCycle;
    if (pc?.releasedAt && now - pc.releasedAt > 15000) {
      const stolen = (job.heldSeats || []).filter(l => (heldAt[l] || 0) === pc.reservedAt && st[l] !== 'free');
      if (stolen.length) {
        job.heldSeats = job.heldSeats.filter(l => !stolen.includes(l));
        for (const l of stolen) delete heldAt[l];
        lostInGap(job, stolen);
      }
      job.prevCycle = null;
    }
    const atOf   = l => heldAt[l] || job.lastReservedAt || 0;
    const mine   = l => (job.heldSeats || []).includes(l) && now - atOf(l) < HOLD_MAX_MS;
    const ownHeld  = targetSeats.filter(t => mine(t.label) && st[t.label] === 'occupied').map(t => t.label);
    const released = targetSeats.filter(t => mine(t.label) && st[t.label] === 'free').map(t => t.label);
    const free     = targetSeats.filter(t => st[t.label] === 'free');
    const taken    = targetSeats.filter(t => st[t.label] !== 'free' && !ownHeld.includes(t.label));
    job.seatState  = Object.fromEntries(targetSeats.map(t =>
      [t.label, ownHeld.includes(t.label) ? 'held' : st[t.label] === 'free' ? 'free' : 'taken']));

    // 2. Retención de la última reserva: sigue mientras ninguna de sus butacas aparezca libre
    const c = job.cycle;
    const cycleSeats    = c ? (job.heldSeats || []).filter(l => atOf(l) === c.reservedAt) : [];
    const cycleReleased = released.filter(l => cycleSeats.includes(l));
    if (c && !c.measured && !cycleReleased.length && ownHeld.some(l => cycleSeats.includes(l))) {
      c.sawOccupied = true; c.lastOccupiedAt = now;
    }
    if (!free.length && ownHeld.length) {
      await renewal(job, area, ownHeld, now);
      // Descanso: se cargan balas para el próximo disparo (pocas por vez)
      loadBullets(job, bulletsNeeded(job, targetSeats.length), job.threads * 2).catch(() => {});
      return { success: false, holdActive: true,
        error: `Retención activa: ${ownHeld.length} butaca${ownHeld.length > 1 ? 's' : ''} retenida${ownHeld.length > 1 ? 's' : ''} por este job (${min(now - job.lastReservedAt)})${taken.length ? ` · ${taken.length} ocupada${taken.length > 1 ? 's' : ''} por otros` : ''}` };
    }

    // 3. La retención parece terminada: medir cuánto duró. Se confirma solo si el cine acepta la
    // reserva: a veces el mapa muestra libre por un momento una butaca que sigue retenida.
    const snapshot = { cycle: c && { ...c }, holdSamples: job.holdSamples, holdHint: job.holdHint };
    const pendingLogs = [];
    if (c && c.reservedAt && !c.measured && cycleReleased.length) {
      c.measured = true;
      const elapsed = now - c.reservedAt;
      job.prevCycle = { reservedAt: c.reservedAt, releasedAt: now };
      if (c.renewedAt || c.renewed) {
        // Se renovó y aun así se liberó: la renovación no extendió la retención
        const was = job.renewState;
        job.renewState = 'fails';
        pendingLogs.push(was === 'works'
          ? 'La renovación dejó de funcionar (las butacas se liberaron igual): se desactiva; queda la ráfaga al vencer'
          : 'Renovación experimental: el cine no extendió la retención (se liberó a la hora de siempre). Se desactiva; queda la ráfaga al vencer');
        notify(`⚠️ ${job.name}: la renovación no extiende la retención; se usa solo la ráfaga al vencer`, `renewfail-${job.id}`);
      }
      if (c.sawOccupied && c.renewed) {
        // Medida desde una renovación: no es una retención normal, no se guarda
      } else if (c.sawOccupied) {
        // Medición real: se liberó entre la última revisión en que seguía ocupada y esta
        const lo = c.lastOccupiedAt - c.reservedAt;
        const ms = Math.round((lo + elapsed) / 2);
        holdInfo = { holdMs: ms, holdLoMs: lo, holdHiMs: elapsed, holdNewOrder: !!c.newOrder, holdOrderSeq: c.orderSeq || null };
        job.holdSamples = [...(job.holdSamples || []),
          { ms, loMs: lo, hiMs: elapsed, at: now, newOrder: !!c.newOrder, orderSeq: c.orderSeq || null }].slice(-HOLD_SAMPLES);
        job.holdHint = null;
        pendingLogs.push(`Retención liberada tras ~${min(ms)} (entre ${min(lo)} y ${min(elapsed)})`);
        if (c.expiresAt) pendingLogs.push(`Vencimiento informado por el cine: ${min(c.expiresAt - c.reservedAt)}; liberación medida: ~${min(ms)}`);
      } else {
        // Ya estaba libre en la primera revisión: solo se sabe que duró menos. No es una medición;
        // se usa como estimación para la próxima vuelta, que revisará antes y la medirá bien.
        job.holdHint = elapsed;
        pendingLogs.push(`Las butacas ya estaban libres en la primera revisión (${min(elapsed)}): la retención duró menos. La próxima vuelta revisará antes para medirla`);
      }
    }
    const commitRelease = () => { for (const m of pendingLogs) addLog(m, 'info', job); pendingLogs.length = 0; };

    // 4. Qué se puede reservar ahora
    if (!free.length) {
      commitRelease();
      job.heldSeats = []; job.heldAt = {}; job.orders = [];
      const msg = `No disponibles: ${fmtSeats(taken.map(t => t.label))}`;
      addLog(msg, 'warn', job);
      return { success: false, error: msg, taken: taken.map(t => t.label), ...holdInfo };
    }
    const freeLabels = free.map(t => t.label);
    const releaseEst = c?.sawOccupied && cycleReleased.length ? Math.round((c.lastOccupiedAt + now) / 2) : null;
    addLog(`Hilo ${hilo}: ${free.length} libre${free.length > 1 ? 's' : ''} (${fmtSeats(freeLabels)})`
      + `${ownHeld.length ? ` · ${ownHeld.length} ya retenidas` : ''}${taken.length ? ` · ${taken.length} ocupadas por otros: ${fmtSeats(taken.map(t => t.label))}` : ''}`, 'info', job);


    if (dryRun) {
      commitRelease();
      const n = chunkSeats(free, job.orderLimit || job.maxPerOrder).length;
      addLog(`[TEST] Se reservarían ${free.length} butacas (${fmtSeats(freeLabels)}) en ${n} ${n > 1 ? 'órdenes' : 'orden'} × ${job.threads} hilo${job.threads > 1 ? 's' : ''}`, 'success', job);
      return { success: true, dryRun: true, partial: taken.length > 0, seats: freeLabels, taken: taken.map(t => t.label), ...holdInfo };
    }

    // 5. Disparo de todos los hilos y, si alguna orden falla, recálculo al instante
    const won = [], lostMsgs = [];
    let toFire = free, limit = job.orderLimit || job.maxPerOrder, renewed = false, shrunk = false;
    for (let round = 1; toFire.length && round <= 3; round++) {
      const r = await fire(job, area, toFire, limit);
      won.push(...r.won);
      if (shrunk && !r.lost.some(x => x.kind === 'rejected')) {
        job.orderLimit = limit;
        addLog(`El cine no acepta órdenes más grandes: se usan órdenes de hasta ${limit} butacas`, 'warn', job);
      }
      if (!r.lost.length) break;
      lostMsgs.push(...r.lost.map(x => x.msg));
      if (r.lost.some(x => x.kind === 'error') && !renewed) {
        renewed = true;
        addLog(`Error del servidor del cine (${r.lost.find(x => x.kind === 'error').msg.slice(0, 80)}): renovando sesión y reintentando con balas nuevas`, 'warn', job);
        await initSession(true);
        job.pool = [];
      }
      if (round === 3) break;
      ({ area, st } = await readSeats(job));
      const lostSeats = r.lost.flatMap(x => x.chunk);
      const still = lostSeats.filter(t => st[t.label] === 'free');
      // Orden rechazada con todas sus butacas aún libres: quizá el cine no acepta tantas por orden.
      // Se prueba con órdenes de la mitad; si así entran, se recuerda el límite.
      const big = r.lost.filter(x => x.kind === 'rejected' && x.chunk.length > 1 && x.chunk.every(t => st[t.label] === 'free'));
      if (big.length) {
        const maxBig = Math.max(...big.map(x => x.chunk.length));
        const told = big.map(x => +(x.msg.match(/m[aá]x\D{0,30}?(\d{1,3})/i)?.[1] || 0)).find(n => n >= 1 && n < maxBig);
        limit = told || Math.max(1, Math.floor(maxBig / 2));
        shrunk = true;
      }
      else shrunk = false;
      addLog(`Recalculando: ${lostSeats.length - still.length} de ${lostSeats.length} ya no están libres; ${still.length ? `se dispara de nuevo con ${fmtSeats(still.map(t => t.label))}` : 'nada más que intentar'}`, 'warn', job);
      toFire = still;
    }

    // 6. Resultado
    const t2 = Date.now();
    const wonLabels = new Set(won.flatMap(w => w.chunk.map(t => t.label)));
    // Butacas propias que el mapa mostró libres pero el cine rechazó y ahora se ven ocupadas: se
    // asume que la retención del job sigue activa y se deshace la medición
    const stillMine = released.filter(l => !wonLabels.has(l) && st[l] === 'occupied');
    const rolledBack = cycleReleased.length > 0 && cycleReleased.every(l => stillMine.includes(l));
    if (rolledBack) {
      Object.assign(job, snapshot);
      holdInfo = {};
      pendingLogs.length = 0;
      addLog(`El mapa mostraba libres ${fmtSeats(stillMine)} pero el cine rechazó la reserva: se asume que la retención de este job sigue activa`, 'warn', job);
    } else commitRelease();

    const heldNow = {};
    for (const l of ownHeld) heldNow[l] = atOf(l);
    if (rolledBack) for (const l of stillMine) heldNow[l] = atOf(l);
    for (const l of wonLabels) heldNow[l] = t2;
    job.heldSeats = Object.keys(heldNow);
    job.heldAt    = heldNow;
    job.orders    = [...(job.orders || []).filter(o => o.seats.some(l => l in heldNow && heldNow[l] !== t2)),
                     ...won.map(w => ({ uid: w.uid, hilo: w.hilo, seats: w.chunk.map(t => t.label), at: t2 }))];
    job.seatState = Object.fromEntries(targetSeats.map(t =>
      [t.label, t.label in heldNow ? 'held' : st[t.label] === 'free' ? 'free' : 'taken']));

    // Hueco: desde que se liberaron (estimado) hasta que se volvieron a reservar; las propias que no se
    // pudieron re-reservar las tomó otra persona
    if (!rolledBack && cycleReleased.length) {
      const lost = cycleReleased.filter(l => !wonLabels.has(l));
      if (releaseEst) {
        job.exposure = [...(job.exposure || []), { ms: t2 - releaseEst, maxMs: t2 - c.lastOccupiedAt, at: t2, lost: lost.length }].slice(-60);
        addLog(`Hueco: ~${((t2 - releaseEst) / 1000).toFixed(1)} s (máx. ${((t2 - c.lastOccupiedAt) / 1000).toFixed(1)} s) entre la liberación y la nueva reserva`, lost.length ? 'warn' : 'info', job);
      }
      if (lost.length) lostInGap(job, lost);
    }

    if (!won.length) {
      if (rolledBack) return { success: false, error: `Rechazada (${lostMsgs[0] || ''}): la retención propia sigue activa` };
      throw new Error(`Reserva rechazada: ${lostMsgs[0] || 'sin respuesta'}`);
    }

    job.successes++;
    job.lastReservedAt = t2;
    job.userSessionId  = won[0].uid;   // la última orden (informativo)
    const exp = findExpiry(won[0].result);
    job.orderExpiryInfo = exp.fields.length ? { fields: exp.fields, at: t2, usable: !!exp.expiresAt } : null;
    if (!job.expiryChecked || exp.fields.length) {
      addLog(exp.fields.length
        ? `Respuesta de la reserva con datos de vencimiento: ${exp.fields.join(', ')}${exp.expiresAt ? '' : ' (no se pudo interpretar como hora)'}`
        : 'La respuesta de la reserva no trae hora de vencimiento: se usa la retención medida', 'info', job);
      job.expiryChecked = true;
    }
    // Ronda nueva de retención, salvo que la anterior siga en curso (se reservaron butacas sueltas
    // mientras el bloque sigue retenido): así la medición sigue siendo la del bloque
    const ongoing = c && !c.measured && ownHeld.some(l => atOf(l) === c.reservedAt);
    if (!ongoing) {
      job.cycle = { reservedAt: t2, newOrder: true, orderSeq: 1, expiresAt: exp.expiresAt,
                    sawOccupied: false, lastOccupiedAt: null, measured: false, phase: null };
    }

    const total   = (won.reduce((n, w) => n + (w.result.Order.TotalValueCents || 0), 0) / 100).toFixed(2);
    const missing = targetSeats.map(t => t.label).filter(l => !(l in heldNow));
    const hilos   = [...new Set(won.map(w => w.hilo))].sort().join(', ');
    addLog(`✅ ${missing.length ? 'RESERVA PARCIAL' : 'RESERVADO'}: ${fmtSeats([...wonLabels])} · ${won.length} ${won.length > 1 ? 'órdenes' : 'orden'} (hilo${hilos.includes(',') ? 's' : ''} ${hilos}) | S/.${total}`
      + `${ownHeld.length ? ` · ${ownHeld.length} seguían retenidas` : ''}${missing.length ? ` · sin retener: ${fmtSeats(missing)}` : ''}`, 'success', job);
    if (!job.notified?.first) {
      job.notified = { ...job.notified, first: t2 };
      notify(`✅ ${job.name}: ${job.heldSeats.length}/${targetSeats.length} butacas retenidas`);
    }
    // Reponer balas para la próxima vez, sin bloquear
    loadBullets(job, bulletsNeeded(job, targetSeats.length), job.threads * 2).catch(() => {});
    return { success: true, partial: missing.length > 0, seats: fmtSeats([...wonLabels]), total, taken: missing, ...holdInfo };

  } catch (err) {
    addLog(`Error: ${err.message}`, 'error', job);
    return { success: false, error: err.message, ...holdInfo };
  }
}

// Estado del bloque para la línea de tiempo: solo se guarda un punto si algo cambió (o cada 60 s)
function sampleTimeline(job) {
  const c = { held: 0, taken: 0, free: 0, rel: 0 };
  for (const t of job.targetSeats) {
    const st = job.releases?.[t.label] ? 'rel' : job.seatState?.[t.label];
    if (st in c) c[st]++;
  }
  const tl = job.timeline || (job.timeline = []);
  const last = tl[tl.length - 1];
  const now = Date.now();
  if (!last || last.held !== c.held || last.taken !== c.taken || last.free !== c.free || last.rel !== c.rel
      || last.n !== job.targetSeats.length || now - last.t > 60000) tl.push({ t: now, ...c, n: job.targetSeats.length });
  if (tl.length > 600) tl.splice(0, tl.length - 600);
}

// Ejecuta un intento y lo registra en el histórico. source: 'auto' | 'manual' | 'test'
async function doReserve(job, dryRun, source) {
  if (job.busy) return { success: false, skipped: true, error: 'Ya hay un intento en curso para este job' };
  job.busy = true;
  let r;
  try { r = await attemptReserve(job, dryRun); }
  finally { job.busy = false; }

  job.lastResult = { ...r, timestamp: new Date().toISOString() };
  if (!r.skipped && !r.dryRun) sampleTimeline(job);
  if (r.success || r.holdActive || r.watching) job.failStreak = 0;
  else if (!r.skipped && !r.dryRun && ++job.failStreak === 5)
    notify(`❗ ${job.name}: 5 intentos fallidos seguidos (${String(r.error || '').slice(0, 120)})`);
  job.history.unshift({
    time:     new Date().toISOString(),
    source,
    hilo:     job.turn || null,
    success:  !!r.success,
    dryRun:   !!r.dryRun,
    // reserved | partial | hold (retención propia activa) | watch (todo liberado para ti: solo vigila) | failed | test
    kind:     r.dryRun ? 'test' : r.success ? (r.partial ? 'partial' : 'reserved') : r.holdActive ? 'hold' : r.watching ? 'watch' : 'failed',
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

  const range = `${effSec(job, job.retryMinMs)}-${effSec(job, job.retryMaxMs)}s`;
  const c     = job.cycle;
  const inHold = (r.success || r.holdActive) && c && !c.measured;
  if (r.success && c) c.phase = null;
  const delay = inHold ? holdDelay(job) : randomRetry(job);

  if (!r.skipped) {
    const mode = r.success ? 'normal' : r.holdActive ? 'hold' : r.watching ? 'watch' : 'retry';
    if (mode !== job.mode) {
      if (mode === 'retry') addLog(`Reserva fallida; reintentando cada ${range}`, 'warn', job);
      if (mode === 'normal' && job.mode === 'retry') addLog('Reserva recuperada', 'info', job);
    }
    if (r.success && c && c.reservedAt === job.lastReservedAt) addLog(`Plan${job.threads > 1 ? ` (${job.threads} hilos turnándose)` : ''}: ${scheduleText(job, holdSchedule(job, c))}`, 'info', job);
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

// Pausa = liberar para ti todas las butacas del job (ver releaseSeats); quitarla = volver a tomarlas
function setPaused(job, paused) {
  if (!!job.paused === !!paused) return;
  job.paused = !!paused;
  const labels = job.targetSeats.map(t => t.label);
  if (paused) releaseSeats(job, labels, '⏸ Pausa');
  else        takeBackSeats(job, labels, '▶ Pausa quitada');
  saveJobs();
}

// ─── BUTACAS LIBERADAS PARA TI ────────────────────────────────────────────────
// Eliges butacas retenidas de una función: los jobs dejan de tomarlas (y de renovar sus órdenes), y el
// primero que las vea libres —cualquier hilo, la ráfaga o el vigilante independiente— te avisa para que
// las compres desde otro dispositivo. Luego las marcas como compradas o las devuelves al job.

// Intento inmediato (para notar cuanto antes un cambio)
function kickJob(job) {
  if (job.running && !job.busy) { clearTimeout(job.timer); runTick(job); }
}

function releaseSeats(job, labels, why = '🔓 Liberadas para ti') {
  const valid = labels.filter(l => job.targetSeats.some(t => t.label === l) && !job.releases[l]);
  if (!valid.length) return 0;
  const now = Date.now();
  for (const l of valid) {
    job.releases[l] = { at: now, status: 'waiting', since: now, ack: false };
    delete job.heldAt[l];
  }
  job.heldSeats = job.heldSeats.filter(l => !job.releases[l]);
  const held = valid.filter(l => job.seatState?.[l] === 'held');
  addLog(`${why}: ${fmtSeats(valid)}. El bot no las vuelve a tomar y te avisará apenas estén libres`
    + `${held.length ? ` (${held.length} siguen en una orden del bot: se liberan cuando venza)` : ''}`, 'warn', job);
  if (job.releaseWatchMs) armReleaseWatch(job);
  saveJobs();
  kickJob(job);
  return valid.length;
}

function takeBackSeats(job, labels, why = '🔒 Vuelven a reservarse') {
  const valid = labels.filter(l => job.releases[l]);
  if (!valid.length) return 0;
  for (const l of valid) delete job.releases[l];
  if (!Object.keys(job.releases).length) job.paused = false;
  addLog(`${why}: ${fmtSeats(valid)}. El bot las vuelve a tomar`, 'info', job);
  saveJobs();
  kickJob(job);
  return valid.length;
}

function markBought(job, labels) {
  const valid = labels.filter(l => job.targetSeats.some(t => t.label === l));
  if (!valid.length) return 0;
  for (const l of valid) delete job.releases[l];
  job.targetSeats = job.targetSeats.filter(t => !valid.includes(t.label));
  job.bought = [...new Set([...(job.bought || []), ...valid])];
  job.heldSeats = job.heldSeats.filter(l => !valid.includes(l));
  if (!Object.keys(job.releases).length) job.paused = false;
  addLog(`✅ Compradas: ${fmtSeats(valid)}. Ya no son objetivo del job (quedan ${job.targetSeats.length})`, 'success', job);
  if (!job.targetSeats.length && job.running) { addLog('No quedan butacas por reservar', 'info', job); stopJob(job); }
  saveJobs();
  return valid.length;
}

// Con el mapa recién leído, actualiza las liberadas y avisa de los cambios
function updateReleases(job, st, who) {
  const rel = job.releases || {};
  const now = Date.now();
  const nowFree = [], nowGone = [];
  for (const [l, r] of Object.entries(rel)) {
    const free = st[l] === 'free';
    if (free && r.status !== 'free') { r.status = 'free'; r.since = now; r.ack = false; nowFree.push(l); }
    else if (!free && r.status === 'free') { r.status = 'gone'; r.since = now; r.ack = false; nowGone.push(l); }
  }
  if (nowFree.length) {
    addLog(`🔔 ¡LIBRES PARA TI!: ${fmtSeats(nowFree)} — cómpralas ahora desde otro dispositivo (lo vio el ${who})`, 'success', job);
    notify(`🔔 ¡LIBRES! ${job.cinemaName} · ${shortWhen(job.showtime)} · ${job.movieTitle}: ${fmtSeats(nowFree)} — cómpralas ya`);
  }
  if (nowGone.length) {
    addLog(`${fmtSeats(nowGone)} ya no están libres (¿las compraste? márcalas como compradas, o vuelve a tomarlas)`, 'warn', job);
    notify(`ℹ️ ${job.name}: ${fmtSeats(nowGone)} ya no están libres (¿las compraste?)`);
  }
  if (nowFree.length || nowGone.length) saveJobs();
}

// Vigilante independiente: revisa las liberadas cada releaseWatchMs, aparte del ritmo del job
function armReleaseWatch(job) {
  clearTimeout(job.rwTimer); job.rwTimer = null;
  if (!job.releaseWatchMs || !Object.keys(job.releases || {}).length || !jobs.has(job.id)) return;
  job.rwTimer = setTimeout(async () => {
    try {
      if (Object.keys(job.releases || {}).length) updateReleases(job, (await readSeats(job)).st, 'vigilante independiente');
    } catch (e) { addLog(`Vigilante de liberadas: ${e.message}`, 'warn', job); }
    armReleaseWatch(job);
  }, job.releaseWatchMs);
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
  clearTimeout(job.rwTimer); job.rwTimer = null;
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
  job.heldAt      = job.heldAt || {};
  job.orders      = Array.isArray(job.orders) ? job.orders : [];
  job.exposure    = Array.isArray(job.exposure) ? job.exposure : [];
  job.releases    = job.releases || {};
  job.timeline    = Array.isArray(job.timeline) ? job.timeline : [];
  job.events      = Array.isArray(job.events) ? job.events : [];
  job.bought      = Array.isArray(job.bought) ? job.bought : [];
  // Versiones anteriores: la pausa no liberaba butacas; ahora pausa = todas liberadas
  if (job.paused && !Object.keys(job.releases).length)
    for (const t of job.targetSeats) job.releases[t.label] = { at: Date.now(), status: 'waiting', since: Date.now(), ack: false };
  job.notified    = job.notified || {};
  job.lostSeats   = job.lostSeats || 0;
  job.failStreak  = 0;
  job.pool        = [];
  job.uidReservations = job.uidReservations || 0;
  jobs.set(job.id, job);
}

// Resumen para la barra de estado del panel
function statusStats() {
  let held = 0, target = 0, lost = 0, lastGap = null;
  for (const j of jobs.values()) {
    if (!j.running) continue;
    const active = j.targetSeats.filter(t => !j.releases?.[t.label]);
    target += active.length;
    held   += active.filter(t => j.seatState?.[t.label] === 'held').length;
    lost   += j.lostSeats || 0;
    const g = (j.exposure || []).slice(-1)[0];
    if (g && (!lastGap || g.at > lastGap.at)) lastGap = g;
  }
  return { held, target, lost, lastGap, perMin: traffic.perMin.length, lastError: traffic.lastError,
           telegram: !!(TG_TOKEN && TG_CHAT), cineUrl: BASE_URL, rps: CINE_RPS };
}

// Avisos vigentes: liberadas que están libres (¡cómpralas!) o que se ocuparon (¿las compraste?), sin silenciar
function jobAlerts() {
  const out = [];
  for (const j of jobs.values()) {
    const rel = Object.entries(j.releases || {}).filter(([, r]) => !r.ack && (r.status === 'free' || r.status === 'gone'));
    if (!rel.length) continue;
    const free = rel.filter(([, r]) => r.status === 'free'), gone = rel.filter(([, r]) => r.status === 'gone');
    out.push({ jobId: j.id, cinemaId: j.cinemaId, sessionId: j.sessionId, name: j.name, cinemaName: j.cinemaName,
      movieTitle: j.movieTitle, showtime: j.showtime, screenName: j.screenName,
      seats: free.map(([l]) => l), gone: gone.map(([l]) => l),
      at: Math.min(...rel.map(([, r]) => r.since)) });
  }
  return out;
}

// ─── VIGÍAS DE PREESTRENO ─────────────────────────────────────────────────────
// Consultan la cartelera cada pollMin–pollMax. Cuando la película tiene funciones en los cines
// elegidos, eligen asientos centrales juntos en cada función y crean (e inician) un job de reserva.
// Cada función se procesa una sola vez; si falla (sala sin publicar, sin asientos) se reintenta más tarde.

// sessionsPerCinema: cuántas funciones reservar por cine (las de los primeros días, una por día);
// prefFrom–prefTo: horario preferido dentro de cada día (si no hay, la función más cercana a ese rango)
// Bloque de butacas: blockCols × blockRows, centrado con desplazamiento blockShift (butacas; + = a la derecha
// vista desde la pantalla) y con su centro a blockDepth % de la profundidad, contando desde la pantalla
const WATCH_DEFAULTS = { pollMinMs: 3000, pollMaxMs: 5000, ticketCode: DEFAULTS.ticketCode,
                         sessionsPerCinema: 3, prefFrom: '20:00', prefTo: '21:00',
                         blockCols: 5, blockRows: 1, blockDepth: 60, blockShift: 0,
                         maxPerOrder: DEFAULTS.maxPerOrder,
                         // Los jobs que crea un vigía son de preventa: ritmo, hilos y ráfaga del perfil Preventa
                         ...PROFILES.preventa.values, profile: 'preventa',
                         holdGuessMs: 0, renew: false, renewLeadMs: DEFAULTS.renewLeadMs, slowPollMs: 60000 };
const WATCH_TIMING = ['intervalMs', 'baselineMs', 'windowMinMs', 'windowMaxMs', 'retryMinMs', 'retryMaxMs'];
// Lo que el vigía pasa a sus jobs (al crearlos, y al editar el vigía con "aplicar a sus jobs")
const WATCH_JOB_KEYS = [...WATCH_TIMING, 'threads', 'maxPerOrder', 'fireMode', 'holdGuessMs', 'burst', 'burstLeadMs',
  'burstIntervalMs', 'burstSpanMs', 'renew', 'renewLeadMs', 'profile'];
const BLOCK_MAX_COLS = 30, BLOCK_MAX_ROWS = 15;
const WATCH_MAX_SESSIONS = 3;
const WATCH_SLOW_MS      = 60000;     // con todo reservado: revisión más espaciada, por si aparece una función mejor (configurable: slowPollMs)
const WATCH_NODETAIL_MS = 120000;   // tiempo que se espera el detalle (hora) de una función nueva antes de elegir sin él
const WATCH_RETRY_MS = 30000;   // reintento de una función que no se pudo procesar
const WATCHER_KEYS   = ['id', 'createdAt', 'name', 'movieId', 'movieTitle', 'posterUrl', 'cinemas', 'pollMinMs', 'pollMaxMs',
  'ticketCode', 'sessionsPerCinema', 'prefFrom', 'prefTo',
  'blockCols', 'blockRows', 'blockDepth', 'blockShift', 'threads', 'maxPerOrder',
  'intervalMs', 'baselineMs', 'windowMinMs', 'windowMaxMs', 'retryMinMs', 'retryMaxMs',
  'fireMode', 'holdGuessMs', 'burst', 'burstLeadMs', 'burstIntervalMs', 'burstSpanMs', 'renew', 'renewLeadMs', 'slowPollMs', 'profile',
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
  const int = (v, d, lo, hi) => { const n = parseInt(v); return Math.min(hi, Math.max(lo, Number.isFinite(n) ? n : d)); };
  if ('seatCount' in b && !('blockCols' in b)) { w.blockCols = int(b.seatCount, 5, 1, BLOCK_MAX_COLS); w.blockRows = 1; }   // formato anterior
  if ('blockCols' in b)   w.blockCols   = int(b.blockCols, WATCH_DEFAULTS.blockCols, 1, BLOCK_MAX_COLS);
  if ('blockRows' in b)   w.blockRows   = int(b.blockRows, WATCH_DEFAULTS.blockRows, 1, BLOCK_MAX_ROWS);
  if ('blockDepth' in b)  w.blockDepth  = int(b.blockDepth, WATCH_DEFAULTS.blockDepth, 0, 100);
  if ('blockShift' in b)  w.blockShift  = int(b.blockShift, 0, -20, 20);
  if ('threads' in b)     w.threads     = int(b.threads, WATCH_DEFAULTS.threads, 1, 6);
  if ('maxPerOrder' in b) w.maxPerOrder = int(b.maxPerOrder, WATCH_DEFAULTS.maxPerOrder, 1, 50);
  // Mismos límites que en el job (applyConfig)
  if ('intervalMs' in b)  w.intervalMs  = int(b.intervalMs, WATCH_DEFAULTS.intervalMs, 5000, 86400000);
  if ('baselineMs' in b)  w.baselineMs  = parseInt(b.baselineMs) === 0 ? 0 : int(b.baselineMs, WATCH_DEFAULTS.baselineMs, 2000, 3600000);
  if ('retryMinMs' in b)  w.retryMinMs  = int(b.retryMinMs, WATCH_DEFAULTS.retryMinMs, 1000, 3600000);
  if ('retryMaxMs' in b)  w.retryMaxMs  = int(b.retryMaxMs, WATCH_DEFAULTS.retryMaxMs, 1000, 3600000);
  if ('windowMinMs' in b) w.windowMinMs = int(b.windowMinMs, WATCH_DEFAULTS.windowMinMs, 1000, 3600000);
  if ('windowMaxMs' in b) w.windowMaxMs = int(b.windowMaxMs, WATCH_DEFAULTS.windowMaxMs, 1000, 3600000);
  if ('fireMode' in b)        w.fireMode        = b.fireMode === 'all' ? 'all' : 'backup';
  if ('holdGuessMs' in b)     w.holdGuessMs     = int(b.holdGuessMs, 0, 0, 3 * 3600000);
  if ('burst' in b)           w.burst           = b.burst !== false;
  if ('burstLeadMs' in b)     w.burstLeadMs     = int(b.burstLeadMs, DEFAULTS.burstLeadMs, 0, 120000);
  if ('burstIntervalMs' in b) w.burstIntervalMs = int(b.burstIntervalMs, DEFAULTS.burstIntervalMs, BURST_MIN_MS, 60000);
  if ('burstSpanMs' in b)     w.burstSpanMs     = int(b.burstSpanMs, DEFAULTS.burstSpanMs, 1000, 600000);
  if ('renew' in b)           w.renew           = !!b.renew;
  if ('slowPollMs' in b)      w.slowPollMs      = int(b.slowPollMs, WATCH_SLOW_MS, 10000, 3600000);
  if ('profile' in b)         w.profile         = b.profile in PROFILES || b.profile === 'custom' ? b.profile : 'preventa';
  if ('renewLeadMs' in b)     w.renewLeadMs     = int(b.renewLeadMs, DEFAULTS.renewLeadMs, 5000, 600000);
  if (w.retryMaxMs < w.retryMinMs)   [w.retryMinMs, w.retryMaxMs]   = [w.retryMaxMs, w.retryMinMs];
  if (w.windowMaxMs < w.windowMinMs) [w.windowMinMs, w.windowMaxMs] = [w.windowMaxMs, w.windowMinMs];
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
  o.slowMode = !!w.slowMode;
  o.profileDiff = profileDiff(w);
  // Funciones procesadas, con el estado actual de su job
  o.sessions = Object.entries(w.handled || {}).filter(([, h]) => h.status !== 'dropped').map(([key, h]) => {
    const j = h.jobId && jobs.get(h.jobId);
    return { key, ...h, job: j ? { id: j.id, name: j.name, running: j.running, paused: !!j.paused, mode: j.mode,
      successes: j.successes, alert: Object.values(j.releases || {}).some(r => r.status === 'free' && !r.ack) } : null };
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
  // Modo lento: todos los cines elegidos ya tienen sus funciones con job. Sigue revisando (por si aparece
  // una función anterior o una elegida se agota), pero más espaciado (slowPollMs) para no gastar tráfico.
  const slow = watcherComplete(w);
  if (slow !== !!w.slowMode) {
    w.slowMode = slow;
    addWLog(w, slow
      ? `Todos los cines elegidos tienen sus funciones reservadas: se pasa a revisar cada ${w.slowPollMs / 1000} s`
      : `Faltan funciones por reservar: se vuelve a consultar cada ${w.pollMinMs / 1000}–${w.pollMaxMs / 1000} s`, slow ? 'success' : 'info');
    saveWatchers();
  }
  const delay = slow ? w.slowPollMs : w.pollMinMs + Math.floor(Math.random() * (w.pollMaxMs - w.pollMinMs + 1));
  w.nextAt = Date.now() + delay;
  w.timer  = setTimeout(() => watcherTick(w), delay);
}

// Cada cine elegido tiene su selección de funciones y todas ya tienen job
function watcherComplete(w) {
  return w.cinemas.length > 0 && w.cinemas.every(c => {
    const keys = (w.chosen[c.id] || '').split(',').filter(Boolean);
    return keys.length > 0 && keys.every(k => w.handled[k]?.status === 'job');
  });
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
    notify(`🎉 ${w.movieTitle}: funciones detectadas en ${perCinema.map(([n, k]) => `${n} (${k})`).join(', ')}`);
  }

  const sc = await cpGet('/api/v1-web/cache/sessioncache');
  const sessMap = {};
  for (const s of (sc.sessions || [])) sessMap[s.id] = s;

  // Jobs creados sin la hora de su función: completarla en cuanto el cine la publique
  for (const [key, h] of Object.entries(w.handled)) {
    const ss = sessMap[key];
    if (h.status !== 'job' || h.showtime || !ss?.showtime) continue;
    h.showtime = ss.showtime; h.screenName = ss.screenName || '';
    const j = jobs.get(h.jobId);
    if (j) {
      j.showtime = ss.showtime; j.screenName = ss.screenName || '';
      j.name = `${h.cinemaName} · ${shortWhen(ss.showtime)} · ${j.movieTitle}`.slice(0, 60);
      const showAt = limaTime(ss.showtime);
      if (showAt && !j.endAt) { j.endAt = showAt + 20 * 60000; armEndTimer(j); }
      addLog(`Hora de la función obtenida: ${shortWhen(ss.showtime)}${ss.screenName ? ` · ${ss.screenName}` : ''}`, 'info', j);
      saveJobs();
    }
    addWLog(w, `${h.cinemaName}: hora de la función completada → ${shortWhen(ss.showtime)}`);
  }

  // Por cine: elegir las funciones de los primeros días (ver chooseSessions)
  const pending = [];
  for (const c of w.cinemas) {
    // Sin la hora no se puede saber cuál es la primera ni cuál cae en el horario preferido:
    // si alguna función de este cine aún no tiene detalle, se espera (hasta WATCH_NODETAIL_MS)
    const noDetailYet = found.filter(f => f.cinemaId === c.id && !sessMap[f.key]
      && !(typeof w.considered[f.key] === 'number' && w.considered[f.key] > 1 && now - w.considered[f.key] >= WATCH_NODETAIL_MS));
    if (noDetailYet.length) {
      w.waitNote = w.waitNote || {};
      if (!w.waitNote[c.id]) { w.waitNote[c.id] = 1; addWLog(w, `${c.name}: ${noDetailYet.length} funciones aún sin hora publicada; se espera el detalle antes de elegir`); }
      continue;
    }
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
        if (j?.running && j.heldSeats?.length) {
          // Ya tiene butacas retenidas: no se toca, decides tú en el panel
          if (!h.outside) {
            h.outside = true;
            addWLog(w, `${c.name} ${h.showtime ? shortWhen(h.showtime) : key}: quedó fuera de la selección, pero su job ya retiene ${j.heldSeats.length} butacas; se mantiene (elimínalo en el panel si no lo quieres)`, 'warn');
          }
          continue;
        }
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

// Completa la hora (y sala, fin y nombre) de jobs que no la tienen, sea cual sea su origen y aunque
// su vigía esté detenido o eliminado. Se usa a pedido: el panel la pide al abrir un job sin hora.
// Devuelve cuántos se completaron.
async function backfillJobTimes(list) {
  const missing = list.filter(j => j.cinemaId && j.sessionId && !j.showtime);
  if (!missing.length) return 0;
  let filled = 0;
  try {
    await ensureSession();
    const sc = await cpGet('/api/v1-web/cache/sessioncache');
    const byKey = {};
    for (const x of (sc.sessions || [])) byKey[x.id] = x;
    for (const j of missing) {
      const ss = byKey[`${j.cinemaId}-${j.sessionId}`];
      if (!ss?.showtime) continue;
      j.showtime = ss.showtime;
      j.screenName = j.screenName || ss.screenName || '';
      if (j.watcherId || /^.+ · \d\d\/\d\d · /.test(j.name)) {   // nombre puesto por el vigía: con la hora
        j.name = `${j.cinemaName || j.cinemaId} · ${shortWhen(ss.showtime)} · ${j.movieTitle}`.slice(0, 60);
      }
      const showAt = limaTime(ss.showtime);
      if (showAt && !j.endAt) { j.endAt = showAt + 20 * 60000; armEndTimer(j); }
      addLog(`Hora de la función completada: ${shortWhen(ss.showtime)}${j.screenName ? ` · ${j.screenName}` : ''}`, 'info', j);
      filled++;
      // Y en el registro del vigía que lo creó, si existe
      for (const w of watchers.values()) for (const h of Object.values(w.handled || {}))
        if (h.jobId === j.id && !h.showtime) { h.showtime = ss.showtime; h.screenName = j.screenName; saveWatchers(); }
    }
    saveJobs();
  } catch (e) {
    addLog(`No se pudo completar la hora de las funciones: ${e.message}`, 'warn');
  }
  return filled;
}

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
    const pick = pickBlock(area, w.blockCols, w.blockRows, w.blockDepth, w.blockShift);
    if (!pick) return fail('noseats', 'no hay butacas libres en la zona del bloque; se reintentará');

    const name = `${cinemaName} · ${when} · ${movie.title || w.movieTitle}`.slice(0, 60);
    const showAt = limaTime(s?.showtime);
    const job = newJob({
      name, cinemaId: f.cinemaId, cinemaName, movieId: w.movieId, movieTitle: movie.title || w.movieTitle,
      posterUrl: posterPath(movie) || w.posterUrl, sessionId, showtime: s?.showtime || null, screenName: s?.screenName || '',
      day: String(f.date).slice(0, 10), ticketCode: w.ticketCode, targetSeats: pick.seats,
      endAt: showAt ? showAt + 20 * 60000 : null,
      ...Object.fromEntries(WATCH_JOB_KEYS.map(k => [k, w[k]])),
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
    const labels = fmtSeats(pick.seats.map(x => x.label));
    w.handled[f.key] = { ...base, status: 'job', jobId: job.id, seats: pick.seats.map(x => x.label) };
    const size = `${pick.cols}×${pick.rows}`;
    addWLog(w, `${cinemaName} ${when}: job creado con bloque ${size} (${pick.seats.length} butacas, ${pick.free} libres ahora: ${labels})`
      + `${pick.cols < w.blockCols || pick.rows < w.blockRows ? ` · la sala no da para ${w.blockCols}×${w.blockRows}` : ''} · ${job.ticketDesc || job.ticketCode} · ${w.threads} hilo${w.threads > 1 ? 's' : ''}`, 'success');
    addLog(`Job creado por el vigía de preestreno (${labels})`, 'info', job);
    const r = startJob(job);
    if (!r.ok) addWLog(w, `${name}: no se pudo iniciar (${r.error})`, 'warn');
    saveJobs();
  } catch (e) {
    fail('error', `${e.message.slice(0, 120)}; se reintentará`);
  }
}

// Bloque de butacas para un vigía: h filas seguidas × w butacas por fila, ubicado según la preferencia
// (centro de la sala + desplazamiento, profundidad desde la pantalla). Incluye las butacas ya ocupadas
// del bloque: el job reserva las libres y reintenta las demás en cada vuelta por si se liberan.
// Se prueban posiciones cercanas (±2 filas, ±3 columnas) y gana la de más butacas libres, penalizando
// alejarse de la preferencia. Si la sala es más chica que el bloque, el bloque se recorta.
// Las butacas de silla de ruedas y las bloqueadas no entran. Un pasillo dentro del bloque no lo corta.
function pickBlock(area, W, H, depthPct = 60, shift = 0) {
  const col    = s => s.Position?.ColumnIndex ?? 0;
  const usable = s => s.SeatStyle !== 3 && s.Status !== 7;
  // Filas con butacas, de la pantalla al fondo (Rows[0] es la del fondo)
  const rows = (area.Rows || []).map((r, ri) => ({ r, ri, seats: (r.Seats || []).filter(usable).sort((a, b) => col(a) - col(b)) }))
    .filter(x => x.seats.length).reverse();
  if (!rows.length) return null;
  const h    = Math.min(H, rows.length);
  const cols = rows.flatMap(x => x.seats.map(col));
  // La columna 0 es el extremo derecho visto desde la pantalla: desplazar a la derecha = columnas menores
  const target = (Math.min(...cols) + Math.max(...cols)) / 2 - shift;
  const ideal  = Math.min(rows.length - h, Math.max(0, Math.round(depthPct / 100 * (rows.length - 1) - (h - 1) / 2)));
  const rowPenalty = Math.max(2, W * 0.3), colPenalty = Math.max(1, h * 0.4);

  let best = null;
  for (let dr = -2; dr <= 2; dr++) {
    const start = ideal + dr;
    if (start < 0 || start + h > rows.length) continue;
    for (let dc = -3; dc <= 3; dc++) {
      const seats = [];
      let free = 0, wMax = 0;
      for (let k = 0; k < h; k++) {
        const row = rows[start + k];
        const n = Math.min(W, row.seats.length);
        wMax = Math.max(wMax, n);
        // Ventana de n butacas seguidas con el centro más cerca del objetivo
        let bi = 0, bd = Infinity;
        for (let i = 0; i + n <= row.seats.length; i++) {
          const d = Math.abs((col(row.seats[i]) + col(row.seats[i + n - 1])) / 2 - (target + dc));
          if (d < bd) { bd = d; bi = i; }
        }
        for (const s of row.seats.slice(bi, bi + n)) {
          if (s.Status === 0) free++;
          seats.push({ rowIndex: row.ri, columnIndex: col(s), areaNumber: area.AreaNumber || 1, label: `${row.r.PhysicalName}${s.Id || col(s)}` });
        }
      }
      if (!free) continue;
      const score = free - Math.abs(dr) * rowPenalty - Math.abs(dc) * colPenalty;
      if (!best || score > best.score) best = { score, seats, free, cols: wMax, rows: h };
    }
  }
  return best;
}

for (const saved of readData('watchers.json', [])) {
  const w = { ...saved, timer: null, nextAt: null, busy: false };
  w.handled = w.handled || {}; w.events = w.events || []; w.cinemas = w.cinemas || [];
  w.considered = w.considered || {}; w.chosen = w.chosen || {};
  if (w.blockCols == null && w.seatCount) { w.blockCols = w.seatCount; w.blockRows = 1; }   // formato anterior
  for (const k of ['sessionsPerCinema', 'prefFrom', 'prefTo', 'blockCols', 'blockRows', 'blockDepth', 'blockShift', 'slowPollMs', ...WATCH_JOB_KEYS])
    if (w[k] == null) w[k] = WATCH_DEFAULTS[k];
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

// Análisis de un job: línea de tiempo, huecos, retención medida, eventos y conteo por hilo
function jobInsights(job) {
  const byHilo = {};
  for (const h of job.history) {
    if (!h.hilo) continue;
    const k = byHilo[h.hilo] = byHilo[h.hilo] || { reserved: 0, partial: 0, hold: 0, watch: 0, failed: 0, test: 0, free: 0 };
    k[h.kind] = (k[h.kind] || 0) + 1;
  }
  const kinds = {};
  for (const h of job.history) kinds[h.kind] = (kinds[h.kind] || 0) + 1;
  return { id: job.id, now: Date.now(), timeline: job.timeline || [], exposure: job.exposure || [], holdSamples: job.holdSamples || [],
           events: (job.events || []).slice(0, 150), byHilo, kinds, historyCount: job.history.length };
}

const JOB_ROUTE = /^\/bot\/jobs\/([a-f0-9]+)(?:\/(start|stop|test|reserve-once|delete|pause|resume|fill-time))?$/;
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
      sessions.set(sha(token), { ...who, expires: Date.now() + SESSION_TTL });
      saveSessions();
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
      sessions.delete(sha(parseCookies(req).cpb_session || ''));
      saveSessions();
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
        if (safeEqual(password, ADMIN_PASSWORD) || matchUserPassword(password))
          return json(res, 400, { error: 'Esa contraseña ya existe' });
        auth.created.push({ id: 'pw-' + crypto.randomBytes(6).toString('hex'), hash: hashPassword(password), hint: hintOf(password),
                            label, createdAt: new Date().toISOString() });
        auth.revoked = auth.revoked.filter(r => !ENV_APP_PASSWORDS.some(p => envId(p) === r && p === password));
        saveAuth();
        return json(res, 200, { ok: true, password, passwords: appPasswords() });
      }

      if (method === 'POST' && pathname === '/admin/passwords/delete') {
        const { id } = await readBody(req);
        auth.created = auth.created.filter(c => c.id !== id);
        // Las del .env no se pueden borrar del archivo: quedan revocadas
        if (ENV_APP_PASSWORDS.some(p => envId(p) === id) && !auth.revoked.includes(id)) auth.revoked.push(id);
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
        profiles:     PROFILES,
        stats:        statusStats(),
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

    // Butacas liberadas para ti, por función (todos los jobs de esa función):
    // action 'release' | 'take' (volver a tomar) | 'bought' (compradas) | 'ack' (silenciar el aviso)
    // | 'watch' (vigilante independiente cada everyMs; 0 = apagado)
    if (method === 'POST' && pathname === '/bot/seats') {
      const b = await readBody(req);
      const list = [...jobs.values()].filter(j => j.cinemaId === b.cinemaId && String(j.sessionId) === String(b.sessionId));
      if (!list.length) return json(res, 404, { error: 'Ningún job tiene esa función' });
      const labels = (Array.isArray(b.labels) ? b.labels : []).map(String);
      let n = 0;
      for (const j of list) {
        if (b.action === 'release') n += releaseSeats(j, labels);
        else if (b.action === 'take') n += takeBackSeats(j, labels);
        else if (b.action === 'bought') n += markBought(j, labels);
        else if (b.action === 'ack') { for (const l of labels) if (j.releases[l]) { j.releases[l].ack = true; n++; } saveJobs(); }
        else if (b.action === 'watch') {
          j.releaseWatchMs = Math.max(0, Math.min(600000, parseInt(b.everyMs) || 0));
          if (j.releaseWatchMs && j.releaseWatchMs < 1000) j.releaseWatchMs = 1000;
          addLog(j.releaseWatchMs ? `Vigilante independiente de las liberadas: cada ${j.releaseWatchMs / 1000} s` : 'Vigilante independiente apagado', 'info', j);
          armReleaseWatch(j); saveJobs(); n++;
        }
        else return json(res, 400, { error: 'Acción inválida' });
      }
      return json(res, 200, { ok: true, changed: n });
    }

    if (method === 'POST' && pathname === '/bot/telegram-test') {
      if (!TG_TOKEN || !TG_CHAT) return json(res, 400, { error: 'Falta TELEGRAM_BOT_TOKEN o TELEGRAM_CHAT_ID en .env' });
      notify('🧪 Prueba de avisos del Cine Bot: funciona');
      return json(res, 200, { ok: true });
    }

    if (method === 'POST' && pathname === '/bot/jobs/pause-all') {
      const { paused } = await readBody(req);
      for (const j of jobs.values()) if (j.running) setPaused(j, !!paused);
      return json(res, 200, { ok: true });
    }

    // Avisos vigentes (butacas libres en jobs en pausa), para cualquier página
    const im = pathname.match(/^\/bot\/jobs\/([a-f0-9]+)\/insights$/);
    if (method === 'GET' && im) {
      const job = jobs.get(im[1]);
      return job ? json(res, 200, jobInsights(job)) : json(res, 404, { error: 'Job no encontrado' });
    }

    // Eventos importantes de todos los jobs, mezclados (análisis con "Todos los jobs")
    if (method === 'GET' && pathname === '/bot/events') {
      const all = [...jobs.values()].flatMap(j => (j.events || []).slice(0, 60).map(e => ({ ...e, jobId: j.id, jobName: j.name })));
      all.sort((a, b) => b.time.localeCompare(a.time));
      return json(res, 200, { events: all.slice(0, 200) });
    }

    if (method === 'GET' && pathname === '/bot/alerts') {
      return json(res, 200, { alerts: jobAlerts() });
    }

    // ── Vigías de preestreno ──────────────────────────────────────────────
    if (method === 'GET' && pathname === '/bot/watchers') {
      return json(res, 200, { watchers: [...watchers.values()].map(publicWatcher), profiles: PROFILES });
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
      const body = await readBody(req);
      const err = applyWatcherConfig(w, body);
      if (err) return json(res, 400, { error: err });
      addWLog(w, `Configuración actualizada: ${w.cinemas.map(c => c.name).join(', ')}`);
      if (body.applyToJobs) {
        // Ritmo, hilos y opciones de disparo; el bloque de butacas no se cambia en jobs ya creados
        const list = [...jobs.values()].filter(j => j.watcherId === w.id);
        for (const j of list) {
          applyConfig(j, Object.fromEntries(WATCH_JOB_KEYS.map(k => [k, w[k]])));
          addLog('Configuración actualizada desde el vigía', 'info', j);
        }
        if (list.length) { addWLog(w, `Cambios aplicados a ${list.length} job${list.length > 1 ? 's' : ''}`); saveJobs(); }
      }
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
      if (action === 'fill-time') {          // el panel abrió un job sin hora: se consulta una vez y se guarda
        const filled = await backfillJobTimes([job]);
        return json(res, 200, { ok: true, filled: filled > 0, showtime: job.showtime });
      }
      if (action === 'pause')  { setPaused(job, true);  return json(res, 200, { ok: true }); }
      if (action === 'resume') { setPaused(job, false); return json(res, 200, { ok: true }); }
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
  for (const job of jobs.values()) if (job.running) { startJob(job, true); armReleaseWatch(job); }
  for (const w of watchers.values()) if (w.running) startWatcher(w, true);
});
