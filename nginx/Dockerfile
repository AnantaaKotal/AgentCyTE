FROM nginx:1.27-alpine

# Install openssl for runtime certificate generation
RUN apk add --no-cache openssl

# Copy custom entrypoint hook (must be executable)
COPY entrypoint.sh /docker-entrypoint.d/10-gen-certs.sh
RUN chmod +x /docker-entrypoint.d/10-gen-certs.sh

# Copy nginx configuration (still bind-mountable for overrides if desired)
# (We intentionally do not COPY nginx.conf here so local edits with bind mount take precedence.)

