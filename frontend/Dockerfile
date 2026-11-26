ARG NODE_IMAGE=docker.io/library/node@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5
ARG NGINX_IMAGE=docker.io/nginxinc/nginx-unprivileged@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0
FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY package.json package-lock.json ./
# Зеркало реестра npm (NPM_REGISTRY в .env), например при недоступности registry.npmjs.org. Адреса в package-lock.json подменяются только внутри сборки;
# целостность пакетов по-прежнему проверяется по контрольным суммам (integrity) из package-lock.json.
ARG NPM_REGISTRY=""
ARG NPM_REGISTRIES=""
ENV NPM_CONFIG_FETCH_RETRIES=2 NPM_CONFIG_FETCH_RETRY_MINTIMEOUT=2000 NPM_CONFIG_FETCH_RETRY_MAXTIMEOUT=15000 NPM_CONFIG_FETCH_TIMEOUT=60000 NODE_OPTIONS="--dns-result-order=ipv4first"
# Несколько реестров по порядку (NPM_REGISTRIES, затем NPM_REGISTRY, затем официальный): у каждого не больше 2 попыток по 15 минут. Бесконечных повторов нет. Адреса в package-lock.json
# подменяются только внутри сборки; целостность пакетов по-прежнему проверяется по контрольным суммам (integrity). Кэш npm сохраняется между сборками (BuildKit);
# подробный вывод (--loglevel=http) даёт контролю обновления признак прогресса.
RUN --mount=type=cache,target=/root/.npm cp package-lock.json /tmp/lock.orig; regs="$NPM_REGISTRIES $NPM_REGISTRY https://registry.npmjs.org"; ok=0; \
    for reg in $regs; do reg="${reg%/}"; cp /tmp/lock.orig package-lock.json; sed -i "s#https://registry.npmjs.org/#$reg/#g" package-lock.json; npm config set registry "$reg/"; echo "npm: реестр $reg"; \
      for i in 1 2; do timeout 900 npm ci --no-audit --no-fund --prefer-offline --loglevel=http && ok=1 && break 2; echo "npm ci: сбой на $reg, попытка $i/2"; sleep 5; done; done; [ "$ok" = 1 ]
COPY tsconfig.json vite.config.ts index.html ./
COPY public ./public
COPY src ./src
RUN npm run build
ARG APP_VERSION=0.0.0
ARG APP_GIT_COMMIT=unknown
ARG APP_BUILT_AT=unknown
RUN printf '{"version":"%s","commit":"%s","built_at":"%s"}\n' "$APP_VERSION" "$APP_GIT_COMMIT" "$APP_BUILT_AT" > dist/version.json

FROM ${NGINX_IMAGE}
ARG APP_VERSION=0.0.0
ARG APP_GIT_COMMIT=unknown
LABEL kavcheck.component="web" org.opencontainers.image.revision="${APP_GIT_COMMIT}" org.opencontainers.image.version="${APP_VERSION}"
USER root
RUN rm -f /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh
USER 101
COPY --chown=101:101 nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build --chown=101:101 /app/dist /usr/share/nginx/html
EXPOSE 8080
