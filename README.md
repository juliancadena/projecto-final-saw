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

## Ejecución con Docker (recomendado)

Solo necesitas tener Docker instalado. Funciona igual en equipos x64 y ARM
(Intel/AMD, Apple Silicon): la imagen se construye para tu arquitectura
automáticamente.

```bash
docker compose up --build
```

Abrir el navegador en: **http://localhost:3000**

Para detener: `Ctrl+C` (o `docker compose down` en otra terminal).

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

Con Docker, cada arranque ya parte de una base de datos limpia:

```bash
docker compose down && docker compose up --build
```
