# ─── VulnGuard Dockerfile ────────────────────────────────────────────────────
# Multi-stage build for a self-contained vulnerability scanning platform
# Includes: nmap, nikto, nuclei — all scanning tools built-in
#
# Deploy on:
#   - Fly.io (free tier: 3 shared-cpu-1x VMs, 160GB bandwidth)
#   - Railway ($5 credit/month free)
#   - Render (free tier available)
#   - Any VPS (Oracle Cloud Always Free recommended)
# ─────────────────────────────────────────────────────────────────────────────

# ─── Stage 1: Install scanning tools ─────────────────────────────────────────
FROM debian:bookworm-slim AS scanner-tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /tmp/nuclei.zip \
    && apt-get update && apt-get install -y --no-install-recommends unzip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && apt-get remove -y unzip && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Pre-download nuclei templates (saves startup time)
RUN mkdir -p /root/nuclei-templates \
    && nuclei -update-templates -t /root/nuclei-templates 2>/dev/null || true

# ─── Stage 2: Build Next.js app ──────────────────────────────────────────────
FROM node:22-slim AS builder

WORKDIR /app

# Install bun
RUN curl -fsSL https://bun.sh/install | bash
ENV PATH="/root/.bun/bin:${PATH}"

# Copy package files
COPY package.json bun.lockb* ./
COPY prisma ./prisma/

# Install dependencies
RUN bun install --frozen-lockfile 2>/dev/null || bun install

# Copy source code
COPY . .

# Generate Prisma client
RUN bun run db:generate

# Build Next.js
ENV NEXT_TELEMETRY_DISABLED=1
RUN bun run build

# ─── Stage 3: Production runtime ─────────────────────────────────────────────
FROM node:22-slim AS runner

WORKDIR /app

# Install runtime dependencies for scanning tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    curl \
    perl \
    libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei binary
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /tmp/nuclei.zip \
    && apt-get update && apt-get install -y --no-install-recommends unzip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && apt-get remove -y unzip && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy nuclei templates from builder
COPY --from=scanner-tools /root/nuclei-templates /root/nuclei-templates

# Create non-root user for Next.js
RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 nextjs

# Copy built application
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/run-*.sh ./

# Make scanner scripts executable
RUN chmod +x /app/run-*.sh

# Create data directory for SQLite
RUN mkdir -p /app/prisma/db && chown -R nextjs:nodejs /app/prisma/db
RUN mkdir -p /tmp/vulnguard-scans && chown -R nextjs:nodejs /tmp/vulnguard-scans

# Environment
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV DATABASE_URL=file:./db/custom.db
ENV NUCLEI_TEMPLATES_DIR=/root/nuclei-templates
ENV HOME=/home/nextjs
ENV PATH="/usr/local/bin:/usr/bin:${PATH}"

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

USER nextjs

CMD ["node", "server.js"]
