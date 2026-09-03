# =============================================================================
# ULPF Core Engine — container image
# =============================================================================
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only runtime code and configuration; tests stay outside the release image.
COPY core/ ./core/
COPY src/ ./src/
COPY schemas/ ./schemas/
COPY source_packs/ ./source_packs/
COPY config/ ./config/
COPY main.py .

# Run as a non-root user
RUN useradd --create-home --shell /bin/bash ulpf \
    && mkdir -p /var/lib/ulpf \
    && chown -R ulpf:ulpf /app /var/lib/ulpf
USER ulpf

# Sanity-check: load all Source Packs at build/run time via a quick smoke test.
# (Kept lightweight — full pytest run is expected in CI, not the image build.)
RUN python -c "from core.engine import ParsingEngine; e = ParsingEngine('source_packs'); print(f'Loaded {len(e.registry.packs)} Source Pack(s)')"

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz', timeout=3)" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
