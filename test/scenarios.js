/**
 * Pruebas de escenarios contra el cine simulado: npm test
 * ==========================================================
 * Levanta el cine simulado y un bot en puertos y carpeta temporales (no toca data/ ni data-mock/),
 * y comprueba los comportamientos clave de la reserva. Tarda unos minutos (hay retenciones reales de
 * ~20 s). Solo un escenario: npm test -- hueco
 */

'use strict';

const path = require('path');
const fs   = require('fs');
const os   = require('os');
const { spawn } = require('child_process');

const ROOT      = path.join(__dirname, '..');
const MOCK_PORT = 5480, BOT_PORT = 5481;
const M = `http://127.0.0.1:${MOCK_PORT}`, B = `http://127.0.0.1:${BOT_PORT}`;
const PASSWORD  = 'test-admin-' + Date.now();
const DATA      = fs.mkdtempSync(path.join(os.tmpdir(), 'cinebot-test-'));
const SALAVERRY = { id: '0000000022', name: 'CP Salaverry' };
const MOVIE     = 'HO00099001';

let cookie = '';
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function req(base, p, body) {
  const r = await fetch(base + p, body === undefined ? { headers: { Cookie: cookie } }
    : { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: JSON.stringify(body) });
  const sc = r.headers.get('set-cookie');
  if (sc) cookie = sc.split(';')[0];
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${p}: ${r.status} ${j.error || ''}`);
  return j;
}
const mock   = (p, b) => req(M, p, b);
const bot    = (p, b) => req(B, p, b);
const status = () => bot('/bot/status');
const jobsOf = async () => (await status()).jobs;

async function waitFor(what, fn, ms = 60000) {
  const end = Date.now() + ms;
  let last;
  while (Date.now() < end) {
    try { last = await fn(); if (last) return last; } catch (e) { last = e; }
    await sleep(700);
  }
  throw new Error(`Tiempo agotado esperando: ${what}`);
}

// Deja el bot y el cine como nuevos
async function reset(cfg = {}) {
  for (const w of (await bot('/bot/watchers')).watchers) await bot(`/bot/watchers/${w.id}/delete`, {});
  for (const j of await jobsOf()) await bot(`/bot/jobs/${j.id}/delete`, {});
  await mock('/mock/api/reset', {});
  await mock('/mock/api/config', {
    holdSec: 20, detailDelaySec: 0, seatplanDelaySec: 0, ticketsDelaySec: 0, soldPct: 0, failRate: 0,
    maxPerOrder: 10, renewMode: 'extends', crowdOn: false, times: '14:20, 16:50, 19:10, 20:30, 22:00', days: 4, ...cfg,
  });
}

async function watcher(extra = {}) {
  await bot('/bot/watchers', {
    movieId: MOVIE, movieTitle: 'PELICULA DE PRUEBA', cinemas: [SALAVERRY], sessionsPerCinema: 1,
    blockCols: 8, blockRows: 3, threads: 2, maxPerOrder: 10, pollMinMs: 2000, pollMaxMs: 2000,
    intervalMs: 60000, baselineMs: 5000, windowMinMs: 3000, windowMaxMs: 4000, retryMinMs: 2000, retryMaxMs: 3000,
    ...extra,
  });
  await mock('/mock/api/enable', { cinemas: [SALAVERRY.id] });
}

const heldOf = j => j.targetSeats.filter(t => j.seatState?.[t.label] === 'held').length;
function assert(cond, msg) { if (!cond) throw new Error(msg); }

// ── Escenarios ────────────────────────────────────────────────────────────────

const scenarios = {
  async bloque() {
    await reset();
    await watcher();
    const j = await waitFor('bloque 8×3 retenido', async () => (await jobsOf()).find(j => heldOf(j) === 24));
    assert(j.targetSeats.length === 24, `el bloque tiene ${j.targetSeats.length} butacas, no 24`);
  },

  async errores502() {
    await reset({ failRate: 50 });
    await watcher({ threads: 3 });
    await waitFor('bloque completo pese a 50 % de 502', async () => (await jobsOf()).find(j => heldOf(j) === 24), 30000);
  },

  async limitePorOrden() {
    await reset({ maxPerOrder: 6 });
    await watcher();
    const j = await waitFor('bloque completo con el cine limitado a 6', async () => (await jobsOf()).find(j => heldOf(j) === 24), 30000);
    assert(j.orderLimit === 6, `límite aprendido ${j.orderLimit}, se esperaba 6 (el número del mensaje del cine)`);
  },

  async hueco() {
    // Retención conocida (20 s): la ráfaga apunta al vencimiento desde la primera vuelta
    await reset({ holdSec: 20 });
    await watcher({ holdGuessMs: 20000, burstLeadMs: 3000, burstIntervalMs: 500 });
    const j = await waitFor('re-reserva tras vencer', async () => (await jobsOf()).find(j => j.lastGapMs != null), 60000);
    assert(j.lastGapMs < 2000, `hueco de ${j.lastGapMs} ms (se esperaba < 2 s con ráfaga cada 0.5 s)`);
    assert(heldOf(j) === 24, `retiene ${heldOf(j)} de 24 tras re-reservar`);
  },

  async robadaEnHueco() {
    await reset({ holdSec: 120 });
    await watcher();
    const j = await waitFor('bloque retenido', async () => (await jobsOf()).find(j => heldOf(j) === 24));
    // El cine libera las órdenes y otra persona compra una butaca antes de que el bot vuelva a mirar
    const st = await mock('/mock/api/state');
    const key = st.sessions.find(s => s.held > 0).key;
    await mock(`/mock/api/session/${key}/release`, {});
    const view = await mock(`/mock/api/session/${key}`);
    const t = j.targetSeats[0];
    await mock(`/mock/api/session/${key}/seat`, { ri: t.rowIndex, ci: t.columnIndex });
    void view;
    const after = await waitFor('butaca perdida detectada', async () => (await jobsOf()).find(x => x.id === j.id && x.lostSeats >= 1), 45000);
    assert(heldOf(after) === 23, `retiene ${heldOf(after)}, se esperaban 23`);
    assert(after.seatState[t.label] === 'taken', `${t.label} figura como ${after.seatState[t.label]}`);
  },

  async renovacionFunciona() {
    await reset({ holdSec: 20, renewMode: 'extends' });
    await watcher({ holdGuessMs: 20000, renew: true, renewLeadMs: 8000, burstLeadMs: 3000 });
    const j = await waitFor('renovación confirmada', async () => (await jobsOf()).find(j => j.renewState === 'works'), 60000);
    // Sigue sin hueco: la retención no se soltó nunca
    assert(j.lastGapMs == null, 'hubo un hueco aunque la renovación funciona');
    assert(heldOf(j) === 24, `retiene ${heldOf(j)} de 24`);
  },

  async renovacionRechazada() {
    await reset({ holdSec: 20, renewMode: 'rejects' });
    await watcher({ holdGuessMs: 20000, renew: true, renewLeadMs: 8000 });
    await waitFor('renovación desactivada', async () => (await jobsOf()).find(j => j.renewState === 'fails'), 40000);
    // Y la ráfaga sigue cubriendo el vencimiento
    await waitFor('re-reserva con ráfaga tras desactivar la renovación', async () => (await jobsOf()).find(j => j.lastGapMs != null && heldOf(j) === 24), 40000);
  },

  async liberarYAvisar() {
    await reset({ holdSec: 120 });
    await watcher();
    const j = await waitFor('bloque retenido', async () => (await jobsOf()).find(j => heldOf(j) === 24));
    const mine = j.targetSeats.slice(0, 2).map(t => t.label);
    await bot('/bot/seats', { cinemaId: j.cinemaId, sessionId: j.sessionId, labels: mine, action: 'release' });
    await bot('/bot/seats', { cinemaId: j.cinemaId, sessionId: j.sessionId, labels: [], action: 'watch', everyMs: 1000 });
    // Vence la retención del bot (se liberan todas sus órdenes)
    const st = await mock('/mock/api/state');
    await mock(`/mock/api/session/${st.sessions.find(s => s.held > 0).key}/release`, {});
    // Aviso con las 2 liberadas; el bot re-reserva las otras 22 pero no esas
    const a = await waitFor('aviso de liberadas libres', async () => (await bot('/bot/alerts')).alerts.find(a => a.seats.length === 2), 20000);
    assert(mine.every(l => a.seats.includes(l)), `el aviso trae ${a.seats}, se esperaban ${mine}`);
    const after = await waitFor('22 re-reservadas', async () => (await jobsOf()).find(x => x.id === j.id && heldOf(x) === 22), 20000);
    assert(mine.every(l => after.seatState[l] === 'forme'), 'las liberadas no figuran como libres para ti');
    await sleep(3000);
    const still = (await mock(`/mock/api/session/${a.cinemaId}-${a.sessionId}`)).rows.flatMap(r => r.seats).filter(x => x && mine.includes(x.label));
    assert(still.every(x => x.kind === 'free'), 'el bot volvió a tomar butacas liberadas para ti');
    // Compradas: salen del job
    await bot('/bot/seats', { cinemaId: j.cinemaId, sessionId: j.sessionId, labels: mine, action: 'bought' });
    const done = (await jobsOf()).find(x => x.id === j.id);
    assert(done.targetSeats.length === 22 && done.bought.length === 2, `quedan ${done.targetSeats.length} objetivo y ${done.bought.length} compradas`);
    assert(!(await bot('/bot/alerts')).alerts.length, 'sigue habiendo aviso tras marcarlas compradas');
  },

  async volverATomar() {
    await reset({ holdSec: 120 });
    await watcher();
    const j = await waitFor('bloque retenido', async () => (await jobsOf()).find(j => heldOf(j) === 24));
    const mine = j.targetSeats.slice(0, 3).map(t => t.label);
    await bot('/bot/seats', { cinemaId: j.cinemaId, sessionId: j.sessionId, labels: mine, action: 'release' });
    const st = await mock('/mock/api/state');
    await mock(`/mock/api/session/${st.sessions.find(s => s.held > 0).key}/release`, {});
    await waitFor('aviso', async () => (await bot('/bot/alerts')).alerts.find(a => a.seats.length === 3), 20000);
    await bot('/bot/seats', { cinemaId: j.cinemaId, sessionId: j.sessionId, labels: mine, action: 'take' });
    await waitFor('las 24 retenidas otra vez', async () => (await jobsOf()).find(x => x.id === j.id && heldOf(x) === 24), 20000);
  },

  async pausaLiberaTodo() {
    await reset({ holdSec: 120 });
    await watcher();
    const j = await waitFor('bloque retenido', async () => (await jobsOf()).find(j => heldOf(j) === 24));
    await bot(`/bot/jobs/${j.id}/pause`, {});
    const st = await mock('/mock/api/state');
    await mock(`/mock/api/session/${st.sessions.find(s => s.held > 0).key}/release`, {});
    await waitFor('aviso con las 24', async () => (await bot('/bot/alerts')).alerts.find(a => a.seats.length === 24), 20000);
    const x = (await jobsOf()).find(x => x.id === j.id);
    assert(heldOf(x) === 0 && x.mode === 'watch', `en pausa retiene ${heldOf(x)} (modo ${x.mode})`);
  },

  async primeraSiempre() {
    // Con una sola función por cine y preferencia 20:00–21:00, igual debe tomar la primera (11:00 del estreno)
    await reset({ times: '11:00, 20:30', days: 2 });
    // Vigía con lo mínimo (sin tocar el ritmo): sus jobs deben nacer como Preventa sin ajustes
    await bot('/bot/watchers', { movieId: MOVIE, movieTitle: 'PELICULA DE PRUEBA', cinemas: [SALAVERRY], sessionsPerCinema: 1,
      prefFrom: '20:00', prefTo: '21:00', blockCols: 4, blockRows: 2, pollMinMs: 2000, pollMaxMs: 2000 });
    await mock('/mock/api/enable', { cinemas: [SALAVERRY.id] });
    const j = await waitFor('job creado', async () => (await jobsOf())[0], 20000);
    const st = await mock('/mock/api/state');
    assert(j.showtime === `${st.test.openingDate}T11:00:00`, `eligió ${j.showtime}, se esperaba la primera (${st.test.openingDate} 11:00)`);
    assert(j.profile === 'preventa' && !j.profileDiff.length, `el job del vigía es ${j.profile} (ajustado: ${j.profileDiff})`);
    // Con 2 por cine: la primera y la del horario preferido
    await reset({ times: '11:00, 20:30', days: 2 });
    await watcher({ sessionsPerCinema: 2, prefFrom: '20:00', prefTo: '21:00' });
    const two = await waitFor('2 jobs', async () => { const l = await jobsOf(); return l.length === 2 && l; }, 20000);
    const times = two.map(x => x.showtime).sort();
    assert(times[0] === `${st.test.openingDate}T11:00:00` && times[1] === `${st.test.openingDate}T20:30:00`, `eligió ${times}`);
  },

  async vigiaNoBorraRetenidas() {
    await reset({ holdSec: 120 });
    await watcher({ slowPollMs: 10000 });
    const first = await waitFor('primer job retenido', async () => (await jobsOf()).find(j => heldOf(j) === 24));
    // El cine publica una función anterior: el vigía la elige, pero no borra el job que ya retiene
    const st = await mock('/mock/api/state');
    await mock('/mock/api/add-session', { cinemaId: SALAVERRY.id, day: st.test.openingDate, time: '10:00', screenName: 'SALA 9' });
    await waitFor('job de la función nueva', async () => (await jobsOf()).some(j => j.showtime?.includes('T10:00')), 30000);
    assert((await jobsOf()).some(j => j.id === first.id), 'el vigía eliminó un job que ya retenía butacas');
  },
};

// ── Ejecución ─────────────────────────────────────────────────────────────────

async function main() {
  const only = process.argv.slice(2);
  const list = Object.entries(scenarios).filter(([n]) => !only.length || only.some(o => n.toLowerCase().includes(o.toLowerCase())));
  const logFile = path.join(DATA, 'run.log');
  const out = fs.openSync(logFile, 'w');
  const proc = spawn(process.execPath, [path.join(ROOT, 'mock', 'run.js')], {
    cwd: ROOT, stdio: ['ignore', out, out, 'ipc'],
    env: { ...process.env, MOCK_PORT: String(MOCK_PORT), MOCK_BOT_PORT: String(BOT_PORT), MOCK_DATA: DATA,
           ADMIN_PASSWORD: PASSWORD, APP_PASSWORDS: '', TELEGRAM_BOT_TOKEN: '', TELEGRAM_CHAT_ID: '' },
  });
  let failed = 0;
  try {
    await waitFor('arranque del bot', async () => (await fetch(`${B}/login`)).ok, 20000);
    await bot('/auth/login', { password: PASSWORD });
    for (const [name, fn] of list) {
      const t0 = Date.now();
      process.stdout.write(`· ${name} … `);
      try { await fn(); console.log(`✓ (${((Date.now() - t0) / 1000).toFixed(0)} s)`); }
      catch (e) { failed++; console.log(`✗ ${e.message}`); }
    }
  } finally {
    const exited = new Promise(r => proc.once('exit', r));
    proc.send('stop');
    await Promise.race([exited, sleep(5000)]);
    if (proc.exitCode == null) proc.kill();
  }
  console.log(failed ? `\n${failed} de ${list.length} escenarios fallaron. Registro: ${logFile}` : `\nTodos los escenarios OK (${list.length})`);
  if (!failed) try { fs.rmSync(DATA, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }); } catch {}
  process.exit(failed ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
