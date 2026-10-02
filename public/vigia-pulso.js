// Pulso de los vigías: salud, qué está haciendo, cuenta atrás a la próxima consulta y actividad reciente.
// Lo usan el panel (/) y /preestreno. Las barras y los "hace X s" se animan solos entre consultas.
(() => {
  const css = `
.vp { display: flex; flex-direction: column; gap: 6px; font-size: .78rem; }
.vp-top { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.vp-health { display: inline-flex; align-items: center; gap: 6px; font-weight: 700; font-size: .74rem; padding: 3px 9px; border-radius: 99px; white-space: nowrap; }
.vp-health i { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.vp-ok { background: rgba(12,163,12,.1); color: #0a7d0a; } .vp-ok i { background: #0ca30c; animation: vpPulse 1.6s ease-out infinite; }
.vp-error { background: rgba(249,107,26,.12); color: #b4500f; } .vp-error i { background: #f96b1a; }
.vp-stale { background: rgba(208,59,59,.12); color: #b02a2a; } .vp-stale i { background: #d03b3b; }
.vp-stopped { background: #eceef5; color: #6b6f85; } .vp-stopped i { background: #9aa0b4; }
@keyframes vpPulse { 0% { box-shadow: 0 0 0 0 rgba(12,163,12,.5); } 70% { box-shadow: 0 0 0 7px rgba(12,163,12,0); } 100% { box-shadow: 0 0 0 0 rgba(12,163,12,0); } }
.vp-doing { color: var(--text, #1f1f2e); }
.vp-timing { display: flex; align-items: center; gap: 10px; color: var(--muted, #8d90a5); flex-wrap: wrap; font-variant-numeric: tabular-nums; }
.vp-bar { flex: 1; min-width: 120px; max-width: 260px; height: 5px; background: #eceef5; border-radius: 3px; overflow: hidden; }
.vp-bar i { display: block; height: 100%; width: 0; background: linear-gradient(90deg, #1ccfd9, #8f5fe8); }
.vp-bar.busy i { width: 100% !important; background: #0ca30c; animation: vpBusy .8s ease-in-out infinite alternate; }
@keyframes vpBusy { from { opacity: .4; } to { opacity: 1; } }
.vp-strip { display: flex; align-items: flex-end; gap: 2px; height: 26px; }
.vp-strip i { width: 5px; border-radius: 2px 2px 0 0; background: #2a78d6; min-height: 3px; display: block; }
.vp-strip i.err { background: #d03b3b; }
.vp-strip i.hit { background: #0ca30c; }
.vp-stats { color: var(--muted, #8d90a5); }
.vp-stats b { color: var(--text, #1f1f2e); font-weight: 500; }
.vp-cines { display: flex; gap: 6px; flex-wrap: wrap; }
.vp-cines span { background: #f3f4f9; border-radius: 4px; padding: 2px 7px; font-size: .74rem; }
.vp-cines span b { font-weight: 700; }
.vp-err { color: #b02a2a; }`;
  const st = document.createElement('style');
  st.textContent = css;
  document.head.appendChild(st);

  const e = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const clock = t => new Date(t).toLocaleTimeString('es-PE', { hour12: false });
  const HEALTH = {
    ok: ['vp-ok', 'Funcionando', 'Consulta la cartelera a tiempo'],
    error: ['vp-error', 'Con errores', 'La última consulta falló; sigue intentando'],
    stale: ['vp-stale', 'Sin respuesta', 'No consulta hace más de lo esperado: puede estar colgado (prueba Detener e Iniciar)'],
    stopped: ['vp-stopped', 'Detenido', 'No está consultando'],
  };

  // Qué está haciendo, en palabras
  function doing(w) {
    if (!w.running) return 'Detenido.';
    const s = w.status;
    if (!w.movieSeenAt || s?.inCatalog === false) return 'Esperando que la película aparezca en el catálogo del cine.';
    if (w.slowMode) return `Todas sus funciones tienen job: revisa cada ${Math.round((w.slowPollMs || 60000) / 1000)} s por si aparece una mejor.`;
    if (w.foundAt) {
      const n = Object.keys(s?.perCinema || {}).length, total = (w.cinemas || []).length;
      return n < total ? `Funciones en ${n} de ${total} cines: sigue vigilando el resto.` : 'Funciones detectadas: eligiendo funciones y creando jobs.';
    }
    if (s && !s.selected) return `La película figura en el catálogo, pero aún sin funciones en tus cines${s.others ? ` (sí en otros: ${s.others})` : ''}.`;
    return 'Consultando la cartelera.';
  }

  window.watcherPulseHtml = function (w, cinemaNames = {}) {
    const [cls, label, tip] = HEALTH[w.health] || HEALTH.stopped;
    const act = w.act || {};
    const list = w.activity || [];
    const max = Math.max(300, ...list.map(a => a.ms));
    const strip = list.map(a => `<i class="${!a.ok ? 'err' : a.found ? 'hit' : ''}" style="height:${Math.max(3, Math.round(a.ms / max * 26))}px"
      title="${e(`${clock(a.t)} · ${a.ok ? `${a.ms} ms · ${a.found} funciones en tus cines` : `error: ${a.err || ''}`}`)}"></i>`).join('');
    const per = Object.entries(w.status?.perCinema || {});
    const busy = w.running && w.busy;
    return `<div class="vp">
      <div class="vp-top"><span class="vp-health ${cls}" title="${e(tip)}"><i></i>${label}</span><span class="vp-doing">${e(doing(w))}</span></div>
      ${w.running ? `<div class="vp-timing">
        <span>Última consulta <b data-vp-ago="${w.lastCheckAt || ''}">${w.lastCheckAt ? '' : 'aún ninguna'}</b></span>
        <div class="vp-bar ${busy ? 'busy' : ''}"><i ${w.lastCheckAt && w.nextAt ? `data-vp-from="${w.lastCheckAt}" data-vp-to="${w.nextAt}"` : ''}></i></div>
        <span>${busy ? 'consultando ahora…' : w.nextAt ? `próxima <b data-vp-eta="${w.nextAt}"></b>` : ''}</span>
      </div>` : ''}
      ${list.length ? `<div class="vp-top"><div class="vp-strip" title="Últimas ${list.length} consultas: altura = tiempo de respuesta · verde = vio funciones · rojo = error">${strip}</div>
        <span class="vp-stats"><b>${(w.checks || 0).toLocaleString('es-PE')}</b> consultas · <b>${act.checks5m || 0}</b> en 5 min
          ${act.avgMs != null ? ` · respuesta ~<b>${act.avgMs} ms</b>` : ''} · <b>${act.errors5m || 0}</b> errores (5 min)</span></div>` : ''}
      ${per.length ? `<div class="vp-cines">${per.map(([id, n]) => `<span>${e(cinemaNames[id] || id)}: <b>${n}</b> función${n > 1 ? 'es' : ''}</span>`).join('')}</div>` : ''}
      ${w.lastError ? `<div class="vp-err">⚠ ${e(w.lastError)}</div>` : ''}
    </div>`;
  };

  // Anima "hace X s", cuentas atrás y barras
  setInterval(() => {
    const now = Date.now();
    for (const el of document.querySelectorAll('[data-vp-ago]')) {
      const t = +el.dataset.vpAgo; if (!t) continue;
      const s = Math.max(0, Math.round((now - t) / 1000));
      el.textContent = s < 60 ? `hace ${s} s` : s < 3600 ? `hace ${Math.round(s / 60)} min` : `a las ${clock(t)}`;
    }
    for (const el of document.querySelectorAll('[data-vp-eta]')) {
      const ms = +el.dataset.vpEta - now;
      el.textContent = ms > 0 ? `en ${(ms / 1000).toFixed(1)} s` : 'ya';
    }
    for (const el of document.querySelectorAll('.vp-bar i[data-vp-from]')) {
      const a = +el.dataset.vpFrom, b = +el.dataset.vpTo;
      el.style.width = `${Math.max(0, Math.min(100, (now - a) / Math.max(1, b - a) * 100))}%`;
    }
  }, 200);
})();
