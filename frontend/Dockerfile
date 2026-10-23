FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
# Зеркало реестра npm (NPM_REGISTRY в .env), например при недоступности registry.npmjs.org. Адреса в package-lock.json подменяются только внутри сборки;
# целостность пакетов по-прежнему проверяется по контрольным суммам (integrity) из package-lock.json.
ARG NPM_REGISTRY=""
ENV NPM_CONFIG_FETCH_RETRIES=5 NPM_CONFIG_FETCH_TIMEOUT=120000 NODE_OPTIONS="--dns-result-order=ipv4first"
RUN if [ -n "$NPM_REGISTRY" ]; then reg="${NPM_REGISTRY%/}"; npm config set registry "$reg/"; sed -i "s#https://registry.npmjs.org/#$reg/#g" package-lock.json; echo "npm: зеркало $reg"; fi; \
    for i in 1 2 3; do npm ci --no-audit --no-fund && ok=1 && break; echo "npm ci: сбой, повтор $i/3"; sleep $((i * 10)); done; [ "${ok:-0}" = 1 ]
COPY tsconfig.json vite.config.ts index.html ./
COPY public ./public
COPY src ./src
RUN npm run build
ARG APP_VERSION=0.0.0
ARG APP_GIT_COMMIT=unknown
ARG APP_BUILT_AT=unknown
RUN printf '{"version":"%s","commit":"%s","built_at":"%s"}\n' "$APP_VERSION" "$APP_GIT_COMMIT" "$APP_BUILT_AT" > dist/version.json

FROM nginxinc/nginx-unprivileged:1.27-alpine
LABEL kavcheck.component="web"
USER root
RUN rm -f /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh
USER 101
COPY --chown=101:101 nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build --chown=101:101 /app/dist /usr/share/nginx/html
EXPOSE 8080
