# 🎬 Cine Bot

Panel web para programar jobs que reservan y mantienen retenidas butacas de una función de cine.

- Node.js 18 o superior, **sin dependencias npm** (no hace falta `npm install`).
- Acceso con contraseña: un administrador y contraseñas de usuario.
- Varios jobs, cada uno con su función, butacas, entrada y horario.
- Espera adaptativa: mide cuánto dura la retención de las butacas y revisa poco antes de que se libere.
- Reserva parcial: si otra persona toma alguna butaca, sigue con las que quedan libres.

## Configuración (`.env`)

Copia `.env.example` a `.env` y completa:

| Variable | Obligatoria | Descripción |
|---|---|---|
| `ADMIN_PASSWORD` | sí | Contraseña del administrador (gestiona las contraseñas de usuario desde el panel) |
| `APP_PASSWORDS` | no | Contraseñas de usuario separadas por comas |
| `URL_CINE` | sí | URL del sitio del cine |
| `URL_CINE_CDN` | no | URL del CDN de pósters (sin ella no se muestran pósters) |
| `PORT` | no | Puerto del bot (por defecto `5100`) |
| `HOST` | no | Interfaz de red; `127.0.0.1` en el servidor, detrás de nginx |
| `TRUST_PROXY` | no | `1` detrás de nginx, para limitar los intentos de login por la IP real |

## Uso local

```bash
node server.js
```

Abre **http://localhost:5100** y entra con una de las contraseñas.

Los jobs, las contraseñas creadas en el panel y el histórico se guardan en `data/` (no subir a git).

## Despliegue (Lightsail / Ubuntu con pm2 y nginx)

El bot escucha en `127.0.0.1:5100` y nginx lo expone en el puerto **4100**.

1. Copiar al servidor: `server.js`, `package.json`, `ecosystem.config.js`, `.env`, `public/`, `deploy/`.
2. En el servidor:
   ```bash
   cd ~/cine-bot
   printf 'PORT=5100\nHOST=127.0.0.1\nTRUST_PROXY=1\n' >> .env
   chmod 600 .env
   pm2 start ecosystem.config.js && pm2 save && pm2 startup
   ```
3. nginx:
   ```bash
   sudo apt install -y nginx
   sudo cp deploy/nginx-cine-bot.conf /etc/nginx/sites-available/cine-bot
   sudo ln -s /etc/nginx/sites-available/cine-bot /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl reload nginx
   ```
4. Firewall de Lightsail: abrir **TCP 4100** (no abrir el 5100).

Actualizar: copiar los archivos cambiados y `pm2 restart cine-bot`. Consola: `pm2 logs cine-bot`.

## Estructura

```
server.js              servidor HTTP, jobs y lógica de reserva
ecosystem.config.js    configuración de pm2
deploy/                config de nginx (4100 → 5100)
public/index.html      panel
public/login.html      acceso
data/                  jobs, contraseñas del panel e histórico (se crea solo)
```
