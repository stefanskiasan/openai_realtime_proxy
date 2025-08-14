# Build stage
FROM node:20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files
COPY proxy/package*.json ./
COPY proxy/tsconfig.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY proxy/src ./src

# Build TypeScript
RUN npm run build

# Production stage
FROM node:20-alpine

# Install PM2 globally
RUN npm install -g pm2

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy package files
COPY proxy/package*.json ./

# Install production dependencies only
RUN npm ci --only=production && \
    npm cache clean --force

# Copy built application from builder
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist

# Copy PM2 configuration
COPY --chown=nodejs:nodejs proxy/ecosystem.config.js ./

# Create necessary directories
RUN mkdir -p /app/logs && \
    chown -R nodejs:nodejs /app/logs

# Switch to non-root user
USER nodejs

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node dist/healthcheck.js || exit 1

# Expose port
EXPOSE 8080

# Start with PM2
CMD ["pm2-runtime", "start", "ecosystem.config.js"]