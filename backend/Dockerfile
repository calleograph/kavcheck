FROM python:3.12-slim
LABEL kavcheck.component="backend"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_RETRIES=2 PIP_DEFAULT_TIMEOUT=30
WORKDIR /srv/app
COPY requirements.txt ./
# Зеркало индекса pip (PIP_INDEX_URL в .env), если pypi.org недоступен; пусто — pypi.org
ARG PIP_INDEX_URL=""
ARG PIP_INDEX_URLS=""
# Несколько индексов по порядку (PIP_INDEX_URLS, затем PIP_INDEX_URL, затем pypi.org), у каждого не больше 2 попыток по 10 минут.
RUN unset PIP_INDEX_URL; ok=0; for u in $PIP_INDEX_URLS $PIP_INDEX_URL https://pypi.org/simple; do echo "pip: индекс $u"; \
      for i in 1 2; do timeout 600 pip install --index-url "$u" -r requirements.txt && ok=1 && break 2; echo "pip: сбой на $u, попытка $i/2"; sleep 5; done; done; [ "$ok" = 1 ]
COPY alembic.ini ./
COPY migrations ./migrations
COPY app ./app

# Метаданные сборки — в конце, чтобы смена коммита не сбрасывала кэш слоёв с зависимостями. Версия запекается в образ.
ARG APP_VERSION=0.0.0
ARG APP_GIT_COMMIT=unknown
ARG APP_BUILT_AT=unknown
ENV APP_VERSION=${APP_VERSION} APP_GIT_COMMIT=${APP_GIT_COMMIT} APP_BUILT_AT=${APP_BUILT_AT}

RUN useradd --system --uid 10001 --no-create-home appuser && mkdir -p /data && chown appuser /data
USER appuser
EXPOSE 8000
CMD ["uvicorn", "app.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
