# syntax=docker/dockerfile:1.7
# ─────────────────────────────────────────────────────────────────────────────
# Ransomware Detector — production image (audit P3-DevOps)
#
# Multi-stage build:
#   1. ``builder`` installs runtime deps into a clean virtualenv.
#   2. ``runtime``  copies that venv onto a slim base, drops privileges to
#      a non-root ``app`` user, and exposes the FastAPI service on :8000.
#
# Why slim-bookworm: smaller surface than ``python:3.11`` (~150 MB vs ~900 MB)
# while still providing libffi/openssl needed for cryptography / yara-python.
# We deliberately do NOT use ``-alpine`` because scikit-learn + numpy need
# glibc-compiled wheels that aren't available on musl.
# ─────────────────────────────────────────────────────────────────────────────

ARG PYTHON_VERSION=3.11

# ─── Stage 1: builder ────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

# Build-time deps for native wheels (yara-python, scapy, lxml from oletools).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        libffi-dev \
        libpcap-dev \
        pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Install dependencies into an isolated virtualenv that we copy verbatim
# into the runtime stage. This yields a very small final layer.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

COPY requirements.txt ./
RUN pip install --upgrade pip \
 && pip install -r requirements.txt

# ─── Stage 2: runtime ────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    RANSOMWARE_LOG_FORMAT=json \
    RANSOMWARE_LOG_LEVEL=INFO

# Runtime libs only — no compilers in the final image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        ca-certificates \
        tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1000 app \
 && useradd  --system --uid 1000 --gid app --shell /usr/sbin/nologin --create-home app

# Copy the prepared virtualenv from the builder stage.
COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

# Copy ONLY application code — never tests, datasets, real malware samples,
# .git, or local debug logs (see .dockerignore).
COPY --chown=app:app api/      api/
COPY --chown=app:app core/     core/
COPY --chown=app:app scripts/  scripts/
COPY --chown=app:app data/config.json.template data/config.json.template
COPY --chown=app:app data/threat_intel/        data/threat_intel/
COPY --chown=app:app models/rf_ransomware_detector.joblib \
                     models/rf_ransomware_detector.joblib.sha256 \
                     models/

# Writable runtime directories (logs, quarantine, scratch).
RUN mkdir -p /app/logs /app/quarantine /app/data \
 && chown -R app:app /app/logs /app/quarantine /app/data

USER app

EXPOSE 8000

# tini reaps zombies and forwards signals so SIGTERM cleanly stops uvicorn.
ENTRYPOINT ["/usr/bin/tini", "--"]

# Health check hits the (auth-protected) /health endpoint with no creds —
# we expect 401 from a healthy server, anything else (5xx, connection
# refused) is treated as unhealthy by Docker.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; \
import urllib.error as e; \
r=None; \
try: r=urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3); \
except e.HTTPError as h: sys.exit(0 if h.code==401 else 1); \
except Exception: sys.exit(1); \
sys.exit(0 if r and r.status==200 else 1)"

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
