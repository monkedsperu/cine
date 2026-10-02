# 🎬 Cine Bot

Panel web para programar jobs que reservan y mantienen retenidas butacas de una función de cine.

- Node.js 18 o superior, **sin dependencias npm** (no hace falta `npm install`).
- Acceso con contraseña: un administrador y contraseñas de usuario.
- Varios jobs, cada uno con su función, butacas, entrada y horario.
- Espera adaptativa: mide cuánto dura la retención de las butacas y revisa poco antes de que se libere.
- Reserva parcial: si otra persona toma alguna butaca, sigue con las que quedan libres.
- **Liberar butacas para comprarlas** (🎟️ en cada job): ves la sala en vivo de una función retenida y marcas butacas de tu bloque. Todos los jobs de esa función dejan de tomarlas (y de renovar sus órdenes); cuando vence la orden del bot y quedan libres, el primero que lo nota (cualquier hilo, la ráfaga o un vigilante independiente opcional cada X s) te avisa: banda roja, sonido, notificación y Telegram. Luego las marcas **compradas** (salen del job) o las **vuelves a tomar**. La pausa de un job libera así todas sus butacas.
- Vigías de preestreno (`/preestreno`): consultan la cartelera cada pocos segundos y, cuando la película tiene funciones en los cines elegidos, ubican en cada función el bloque de butacas elegido en la grilla (p. ej. 12×6) y crean un job por función (el nombre empieza con el cine). Siempre incluyen la primera función.
- Perfiles **⚡ Preventa** y **Normal** (ⓘ en el panel explica cada uno): fijan ritmo, hilos y ráfaga con un clic. Los jobs de los vigías nacen siempre como Preventa; si cambias algún valor, el job se marca "ajustado".
- Hilos por reserva: se turnan para revisar al ritmo configurado. Al ver butacas libres disparan con respaldo (si el cine da error, el siguiente hilo al instante) o todos a la vez. Si una orden falla, se vuelve a mirar la sala al instante y se dispara con las que siguen libres. Los bloques grandes se reparten en varias órdenes (máximo por orden configurable; si el cine rechaza ese tamaño, el bot lo ajusta solo).
- **Ráfaga al vencer**: con la retención medida (o la que indiques), unos segundos antes del vencimiento revisa cada segundo y re-reserva en cuanto se liberan, para dejar el menor hueco posible a otros compradores. El panel muestra el hueco medido y las butacas perdidas en huecos.
- **Renovar antes de vencer** (experimental): reenvía cada orden con su mismo `userSessionId` antes de que venza; si el cine extiende la retención, no hay hueco. Se verifica solo y se desactiva si no funciona.
- **Actividad de los vigías** (panel principal y `/preestreno`): salud (funcionando / con errores / sin respuesta / detenido), qué está haciendo, cuenta atrás a la próxima consulta, consultas y tiempo de respuesta de los últimos 5 min, funciones vistas por cine y último evento.
- **Análisis** (panel inferior, por job): resumen con indicadores, línea de tiempo de butacas retenidas, huecos de cada re-reserva, actividad por hilo, eventos importantes filtrables y la tabla de intentos.
- Avisos por Telegram (opcional), aunque el panel esté cerrado.
- Límite global de tráfico hacia el cine (`CINE_RPS`, `CINE_CONCURRENCY`), con prioridad para las reservas.

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
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | no | Avisos por Telegram (ver `.env.example`) |
| `CINE_RPS`, `CINE_CONCURRENCY` | no | Máximo de peticiones por segundo (15) y simultáneas (10) hacia el cine |

Las contraseñas creadas en el panel se guardan con hash en `data/auth.json` (las de versiones anteriores se migran solas al arrancar; después solo se ven sus primeros caracteres).

## Uso local

```bash
node server.js
```

Abre **http://localhost:5100** y entra con una de las contraseñas.

Los jobs, las contraseñas creadas en el panel, las sesiones y el histórico se guardan en `data/` (no subir a git).

## Cine simulado (pruebas)

```bash
node mock/run.js
```

Arranca un cine falso que responde igual que la API del cine real y una segunda instancia del bot apuntada a él:

- **http://localhost:5200/mock**: panel del cine simulado.
- **http://localhost:5101**: bot de prueba (misma contraseña de admin; sus datos van en `data-mock/`, no toca `data/`).

La película **PELICULA DE PRUEBA** empieza como próximo estreno sin funciones. Crea tus vigías en `/preestreno` del bot de prueba y pulsa **HABILITAR** en el panel: se publican funciones en los cines elegidos, por etapas (primero la cartelera, luego la hora, el mapa y las entradas, con retrasos configurables). En el panel se eligen los horarios, los días y el desfase entre cines de las funciones que se publican, y también la retención por orden, si reenviar una orden la renueva, el máximo por orden, los 502 simulados y el "público comprando", y se puede ver cada sala, vender o liberar butacas y liberar retenciones.

Otros puertos o carpeta: `MOCK_PORT`, `MOCK_BOT_PORT`, `MOCK_DATA`.

## Pruebas

```bash
npm test               # todos los escenarios (unos 3 minutos)
npm test -- hueco      # solo los que contienen "hueco"
```

Levantan el cine simulado y un bot en puertos y carpeta temporales y comprueban: bloque completo, 502 al 50 %, límite por orden, hueco con ráfaga (< 2 s), butaca robada en el hueco, renovación que funciona y que el cine rechaza, que el vigía no borra jobs con butacas retenidas, y el aviso de butacas liberadas (compradas, volver a tomar y pausa).

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

**Recomendado: HTTPS.** Con el 4100 sin cifrar, la contraseña y la cookie de sesión viajan en texto plano. Con un dominio apuntando al servidor, usa `deploy/nginx-cine-bot-https.conf` (instrucciones de certbot dentro) y abre el 443 en lugar del 4100. Sin dominio, al menos limita el 4100 a tu IP en el firewall de Lightsail.

Actualizar: copiar los archivos cambiados y `pm2 restart cine-bot`. Consola: `pm2 logs cine-bot`.

## Estructura

```
server.js              servidor HTTP, jobs y lógica de reserva
ecosystem.config.js    configuración de pm2
deploy/                config de nginx (4100 → 5100, o HTTPS)
public/index.html      panel
public/preestreno.html consultar si una película ya tiene funciones (/preestreno)
public/login.html      acceso
public/vigia-pulso.js  pulso de los vigías (compartido por el panel y /preestreno)
mock/                  cine simulado para pruebas (node mock/run.js)
test/                  escenarios automáticos contra el cine simulado (npm test)
data/                  jobs, vigías, contraseñas del panel e histórico (se crea solo)
```
