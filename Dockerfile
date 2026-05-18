# Laboratorio web INTENCIONALMENTE VULNERABLE — solo uso educativo en ambiente aislado.
# Imagen multi-arquitectura: el build usa la arquitectura del host (x64 o ARM).
FROM node:22-bookworm-slim

WORKDIR /app

# Instalar solo dependencias de producción (better-sqlite3 trae binarios precompilados
# para linux x64 y arm64, no se requieren herramientas de build).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Código de la aplicación
COPY . .

ENV PORT=3000
EXPOSE 3000

CMD ["npm", "start"]
