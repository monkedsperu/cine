// pm2: pm2 start ecosystem.config.js
// La configuración (contraseñas, puerto, host) se lee del .env que está junto a server.js.
module.exports = {
  apps: [{
    name:        'cine-bot',
    script:      'server.js',
    cwd:         __dirname,
    autorestart: true,
    max_restarts: 20,
    time:        true,   // hora en cada línea de pm2 logs
  }],
};
