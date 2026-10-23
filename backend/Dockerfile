FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_RETRIES=5 PIP_DEFAULT_TIMEOUT=60
WORKDIR /srv/app
COPY requirements.txt ./
RUN pip install -r requirements.txt
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
