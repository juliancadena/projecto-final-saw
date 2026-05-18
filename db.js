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
