/**
 * Arranca el cine simulado y una instancia del bot apuntada a él, con sus propios datos (data-mock/),
 * para no tocar los jobs ni vigías reales.
 *
 *   node mock/run.js
 *     → cine simulado: http://localhost:5200/mock
 *     → bot de prueba: http://localhost:5101   (misma contraseña de admin que el .env)
 *
 * Puertos: MOCK_PORT (5200) y MOCK_BOT_PORT (5101). Carpeta de datos: MOCK_DATA (data-mock).
 */

'use strict';

const path = require('path');
const { spawn } = require('child_process');

const ROOT     = path.join(__dirname, '..');
const BOT_PORT = process.env.MOCK_BOT_PORT || 5101;
const DATA     = path.resolve(ROOT, process.env.MOCK_DATA || 'data-mock');
// El cine simulado lee estas variables al cargarse
process.env.MOCK_STATE    = process.env.MOCK_STATE || path.join(DATA, 'mock-state.json');
process.env.MOCK_BOT_PORT = String(BOT_PORT);
const mock = require('./mock-cine');

mock.start(mock.MOCK_PORT, '127.0.0.1');

// Las variables ya definidas tienen prioridad sobre el .env del bot (ver loadEnv en server.js)
const bot = spawn(process.execPath, [path.join(ROOT, 'server.js')], {
  cwd: ROOT,
  stdio: 'inherit',
  env: {
    ...process.env,
    URL_CINE:     `http://127.0.0.1:${mock.MOCK_PORT}`,
    URL_CINE_CDN: '',                              // sin pósters
    DATA_DIR:     DATA,
    PORT:         String(BOT_PORT),
    HOST:         '127.0.0.1',
  },
});

console.log(`🤖 Bot de prueba   → http://localhost:${BOT_PORT}  (datos en ${path.relative(ROOT, DATA) || DATA})\n`);

bot.on('exit', code => { console.log(`Bot terminado (${code})`); process.exit(code || 0); });
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { bot.kill(); process.exit(0); });
// Apagado ordenado desde las pruebas (en Windows, matar este proceso no cierra el bot hijo)
process.on('message', m => { if (m === 'stop') { bot.once('exit', () => process.exit(0)); bot.kill(); } });
