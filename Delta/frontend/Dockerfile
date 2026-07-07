# syntax=docker/dockerfile:1
#
# Anoryx Delta Admin Console — Next.js standalone runtime (D-007).
# Separate from the Delta API images: they stay Node-free.
#
# No secrets baked. DELTA_API_URL / DELTA_ADMIN_TOKEN / SESSION_SECRET are
# injected at runtime via env / mounted secrets.

# --------------------------------------------------------------------------- #
# Stage 1 — deps
# --------------------------------------------------------------------------- #
FROM node:20-slim AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci

# --------------------------------------------------------------------------- #
# Stage 2 — builder
# --------------------------------------------------------------------------- #
FROM node:20-slim AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# --------------------------------------------------------------------------- #
# Stage 3 — runner (non-root, standalone output)
# --------------------------------------------------------------------------- #
FROM node:20-slim AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000

RUN groupadd --gid 1001 nodejs \
    && useradd --uid 1001 --gid 1001 --create-home --shell /usr/sbin/nologin nextjs

# Standalone build = self-contained server.js + minimal node_modules.
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public

USER 1001
EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/login',r=>process.exit(r.statusCode<500?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "server.js"]
