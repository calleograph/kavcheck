FROM python:3.12-slim
LABEL kavcheck.component="backend"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_RETRIES=2 PIP_DEFAULT_TIMEOUT=30
# Nmap нужен только сканеру Pentest (контейнер pentest); веб-процесс его не запускает. Образ общий, чтобы не вести вторую сборку.
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*
# Nuclei (MIT) и релиз шаблонов nuclei-templates (MIT) — фиксированные версии с проверкой SHA-256; нужны только сканеру Pentest. Шаблоны лежат в образе: Nuclei работает без интернета,
# обновление шаблонов — по запросу администратора (Администрирование → Pentest: шаблоны и проверки). Лицензии — docs/THIRD_PARTY.md.
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_SHA256_AMD64=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_SHA256_ARM64=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07
ARG NUCLEI_TEMPLATES_VERSION=10.5.1
ARG NUCLEI_TEMPLATES_SHA256=30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb
COPY docker/licenses /opt/kavcheck/licenses
COPY docker/install_nuclei.py /tmp/install_nuclei.py
RUN python /tmp/install_nuclei.py "$NUCLEI_VERSION" "$NUCLEI_SHA256_AMD64" "$NUCLEI_SHA256_ARM64" "$NUCLEI_TEMPLATES_VERSION" "$NUCLEI_TEMPLATES_SHA256" && rm /tmp/install_nuclei.py
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

RUN useradd --system --uid 10001 --no-create-home appuser && mkdir -p /data /data/pentest && chown appuser /data /data/pentest
USER appuser
EXPOSE 8000
CMD ["uvicorn", "app.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
