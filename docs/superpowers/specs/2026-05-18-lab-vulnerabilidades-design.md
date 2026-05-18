# Diseño: Laboratorio de Vulnerabilidades Web — Portal Universitario

**Fecha:** 2026-05-18
**Autor:** Julian Cadena
**Estado:** Aprobado

---

## Contexto y objetivo

Aplicación web intencionalmente vulnerable para uso educativo en la clase de Seguridad en Aplicaciones Web. Los alumnos realizan un análisis de vulnerabilidades usando OWASP ZAP, Nikto y Burp Suite, más validación manual, y posteriormente proponen mitigaciones. El ambiente corre localmente en la máquina de cada alumno.

---

## Stack técnico

- **Frontend:** HTML + CSS + Vanilla JS (sin framework)
- **Backend:** Node.js + Express (monolítico, un solo proceso)
- **Base de datos:** SQLite (archivo `db.sqlite`)
- **Arranque:** `npm install && npm start` (Node.js 18+ requerido)

---

## Estructura de archivos

```
projecto-final/
├── server.js              # Punto de entrada, todas las rutas Express
├── db.js                  # Inicialización y seed de SQLite
├── package.json
├── public/                # Servido estáticamente
│   ├── index.html         # Login
│   ├── dashboard.html     # Panel general según rol
│   ├── admin.html         # Panel administrador
│   ├── docente.html       # Panel docente
│   └── css/ js/
├── uploads/               # Destino de archivos subidos
├── README.md              # Guía para alumnos
└── docs/
    ├── guia-docente.md    # Guía paso a paso para el profesor
    └── superpowers/
        └── specs/
            └── 2026-05-18-lab-vulnerabilidades-design.md
```

---

## Roles y cuentas de prueba

| Usuario | Contraseña | Rol |
|---|---|---|
| `admin` | `admin123` | admin |
| `prof_garcia` | `docente123` | docente |
| `alumno_lopez` | `alumno123` | alumno |
| `alumno_perez` | `alumno456` | alumno |

Las contraseñas se almacenan como hash MD5 débil en la DB (exposición de dato sensible intencional).

---

## Rutas principales

```
POST /login                   # Autenticación (SQLi)
GET  /logout
GET  /api/users               # Lista usuarios sin autenticación (dato sensible)
GET  /search?q=               # Búsqueda de alumnos (SQLi)
GET  /download?file=          # Descarga de material (file inclusion / path traversal)
POST /messages                # Enviar mensaje (XSS stored)
GET  /messages?msg=           # Ver mensajes con notificación (XSS reflected)
POST /profile/update          # Actualizar perfil y rol (CSRF + escalación de privilegios)
GET  /admin/ping?host=        # Ping de diagnóstico (command injection)
GET  /admin/panel             # Panel admin (control de acceso insuficiente)
```

**Sesiones:** `express-session` sin flags `httpOnly`, `Secure` ni `SameSite` — intencionalmente inseguras.

---

## Catálogo de vulnerabilidades y flags

| # | Vulnerabilidad | Módulo | Mecanismo vulnerable | Flag |
|---|---|---|---|---|
| 1 | SQL Injection | Búsqueda de alumnos + Login | Concatenación directa en query SQL | `FLAG{sql_1nj3ct10n}` |
| 2 | Inyección de comandos | Panel admin — "Ping al servidor" | Input pasado a `child_process.exec()` sin validación | `FLAG{cmd_1nj3ct10n}` |
| 3 | XSS (Stored + Reflected) | Módulo de mensajes | Stored: mensajes sin escapar en DB. Reflected: `?msg=` sin sanitizar | `FLAG{xss_st0r3d}` |
| 4 | CSRF | Cambio de contraseña en perfil | Formulario sin token CSRF, acepta peticiones cross-origin | `FLAG{csrf_4tt4ck}` |
| 5 | Inclusión de archivos | Descarga de material | `?file=` permite path traversal (`../../etc/passwd`) | `FLAG{f1l3_1nclus10n}` |
| 6 | Exposición de datos sensibles | Múltiples superficies | MD5 en DB, `/api/users` sin auth, comentarios HTML con credenciales, `db.sqlite` servible | `FLAG{s3ns1t1v3_d4t4}` |
| 7 | Escalamiento de privilegios vertical | Actualización de perfil | El campo `rol` se acepta desde el cliente sin verificar el rol actual | `FLAG{pr1v_3sc4l4t10n}` |

Las flags son estáticas, hardcodeadas en `server.js`. Se revelan en la respuesta HTTP cuando el alumno explota exitosamente la vulnerabilidad correspondiente.

---

## Documentación incluida en el repo

### README.md (para alumnos)
- Requisitos e instalación
- Cuentas de prueba por rol
- Descripción de módulos del portal
- Instrucciones de entrega: reporte con hallazgos, evidencia (capturas) y mitigaciones propuestas
- Advertencia de uso ético

### docs/guia-docente.md (para el profesor)
- Lista de las 7 vulnerabilidades con flag esperada
- Pasos exactos de explotación: payloads, comandos, configuración de Burp/ZAP/Nikto
- Qué validar en el reporte del alumno por cada vulnerabilidad
- Criterios de evaluación sugeridos (hallazgo + evidencia + mitigación)
- Cómo reiniciar la DB a estado limpio entre grupos

---

## Decisiones de diseño

- **Sin Docker:** arranque con solo Node.js para minimizar dependencias en equipos de alumnos.
- **Sin flags dinámicas:** flags estáticas, la honestidad académica queda a criterio del docente.
- **Monolítico:** un solo servidor facilita la lectura del código fuente y reduce la curva de configuración.
- **Tres roles (alumno, docente, admin):** dan suficientes escalones para un ejercicio de escalación vertical no trivial.
- **Frontend sin framework:** el alumno puede inspeccionar el HTML/JS directamente sin compilación, lo que facilita la búsqueda de comentarios con credenciales y tokens expuestos.
