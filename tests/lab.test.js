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
