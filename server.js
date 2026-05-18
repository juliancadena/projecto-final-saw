'use strict';

const express    = require('express');
const session    = require('express-session');
const path       = require('path');
const fs         = require('fs');
const { exec }   = require('child_process');
const md5        = require('md5');
const { initDb, DB_PATH } = require('./db');

const app = express();
const db  = initDb();

// Flags estáticas — cada una se revela al explotar la vuln correspondiente
const FLAGS = {
  sqli:      'FLAG{sql_1nj3ct10n}',
  cmdi:      'FLAG{cmd_1nj3ct10n}',
  xss:       'FLAG{xss_st0r3d}',
  csrf:      'FLAG{csrf_4tt4ck}',
  lfi:       'FLAG{f1l3_1nclus10n}',
  sensitive: 'FLAG{s3ns1t1v3_d4t4}',
  privesc:   'FLAG{pr1v_3sc4l4t10n}',
};

// Crear flag_cmd.txt en disco (la flag de cmd injection se lee con ; cat flag_cmd.txt)
fs.writeFileSync(path.join(__dirname, 'flag_cmd.txt'), FLAGS.cmdi + '\n');

// ── Middleware ────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sesión INTENCIONALMENTE insegura
app.use(session({
  secret: 'supersecretkey123',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: false,  // cookie accesible desde JS (permite robo via XSS)
    secure:   false,
    sameSite: false,  // permite CSRF cross-origin
  },
}));

// db.sqlite servido como archivo estático (exposición de datos sensibles)
app.get('/db.sqlite', (req, res) => res.download(DB_PATH));

// Archivos estáticos del frontend
app.use(express.static(path.join(__dirname, 'public')));

// ── POST /login — VULNERABLE: SQL Injection ──────────────────
app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body;
  const hash = md5(password);

  // VULNERABLE: concatenación directa sin parámetros preparados
  const query = `SELECT * FROM usuarios WHERE username = '${username}' AND password = '${hash}'`;

  let user;
  try {
    user = db.prepare(query).get();
  } catch (e) {
    // Fuga de detalle de error (información sensible)
    return res.status(400).json({ error: e.message, query });
  }

  if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });

  req.session.user = { id: user.id, username: user.username, rol: user.rol, nombre: user.nombre };

  const response = { ok: true, rol: user.rol, nombre: user.nombre };

  // Si el payload contiene metacaracteres SQL, la flag se revela
  if (username.includes("'") || username.includes('--') || username.toLowerCase().includes(' or ')) {
    response.flag  = FLAGS.sqli;
    response.debug = `Query ejecutada: ${query}`;
  }

  return res.json(response);
});

// ── GET /logout ───────────────────────────────────────────────
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// ── GET /search — VULNERABLE: SQL Injection (UNION) ──────────
app.get('/search', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'No autenticado' });

  const q = req.query.q || '';
  // VULNERABLE: concatenación directa
  const query = `SELECT id, username, nombre, email, rol FROM usuarios WHERE nombre LIKE '%${q}%' OR username LIKE '%${q}%'`;

  let results;
  try {
    results = db.prepare(query).all();
  } catch (e) {
    return res.status(400).json({ error: e.message, query });
  }

  return res.json({ results, query });
});

// ── GET /api/users — VULNERABLE: sin autenticación, expone hashes ──
app.get('/api/users', (req, res) => {
  // VULNERABLE: no requiere sesión, retorna campos sensibles incluyendo password hash
  const users = db.prepare('SELECT id, username, email, rol, password FROM usuarios').all();
  return res.json({ users, flag: FLAGS.sensitive });
});

// ── GET /messages — VULNERABLE: XSS Reflected (?msg=) ────────
app.get('/messages', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'No autenticado' });

  const msg = req.query.msg || '';
  const messages = db.prepare('SELECT * FROM mensajes ORDER BY fecha DESC').all();

  // VULNERABLE: msg y contenidos se insertan en HTML sin escapar
  res.send(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Mensajes — Portal Universitario</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  <nav><a href="/dashboard.html">← Volver</a> | <a href="/logout">Cerrar sesión</a></nav>
  <h1>Tablero de mensajes</h1>
  ${msg ? `<div class="notif">Notificación: ${msg}</div>` : ''}
  <ul class="messages">
    ${messages.map(m => `<li><strong>${m.autor}</strong> <span class="date">${m.fecha}</span><br>${m.contenido}</li>`).join('')}
  </ul>
  <form id="msgForm">
    <textarea name="contenido" placeholder="Escribe un mensaje..." rows="3"></textarea>
    <button type="submit">Enviar</button>
  </form>
  <script>
    document.getElementById('msgForm').addEventListener('submit', async e => {
      e.preventDefault();
      const body = new URLSearchParams(new FormData(e.target));
      await fetch('/messages', { method: 'POST', body });
      location.reload();
    });
  </script>
</body>
</html>`);
});

// ── POST /messages — VULNERABLE: XSS Stored ──────────────────
app.post('/messages', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'No autenticado' });

  const { contenido = '' } = req.body;
  // VULNERABLE: se guarda sin sanitizar
  db.prepare('INSERT INTO mensajes (autor, contenido) VALUES (?, ?)').run(req.session.user.username, contenido);
  return res.json({ ok: true });
});

// ── GET /api/xss-flag — la llama el payload XSS para obtener la flag ──
app.get('/api/xss-flag', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'No autenticado' });
  return res.json({ flag: FLAGS.xss });
});

// ── Rutas (se añaden en tareas posteriores) ───────────────────

// Iniciar servidor solo cuando se ejecuta directamente
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log('\n╔══════════════════════════════════════════════════╗');
    console.log('║  PORTAL UNIVERSITARIO — LABORATORIO VULNERABLE   ║');
    console.log('╚══════════════════════════════════════════════════╝');
    console.log(`\n  URL: http://localhost:${PORT}`);
    console.log('  ADVERTENCIA: Esta app es INTENCIONALMENTE VULNERABLE');
    console.log('  Usar SOLO en ambiente local de laboratorio.\n');
  });
}

module.exports = app;
