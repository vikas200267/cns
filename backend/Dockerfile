# Backend API server Dockerfile
FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy application code
COPY . .

# Create logs and artifacts directories
RUN mkdir -p /app/logs /artifacts

# Install Docker CLI for container management
RUN apk add --no-cache docker-cli

# Non-root user for API server
# Create docker group with the host's docker GID (103 in GitHub Codespaces)
RUN addgroup -g 1001 -S labapi && \
    adduser -S -u 1001 -G labapi labapi && \
    addgroup -g 103 -S dockergroup && \
    addgroup labapi dockergroup && \
    chown -R labapi:labapi /app /artifacts

USER labapi

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

CMD ["node", "app.js"]