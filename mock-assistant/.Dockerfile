FROM node:20-slim

WORKDIR /app

# Copy application files
COPY mock-assistant.js creds.json package.json ./

# Set environment variable default (can be overridden at runtime)
ENV DATA_PATH=/app/creds.json

# The server listens on this port, matching docker-compose.loads.yaml
EXPOSE 3000

# Run with the same command used in docker-compose.loads.yaml
CMD ["node", "/app/mock-assistant.js"]

