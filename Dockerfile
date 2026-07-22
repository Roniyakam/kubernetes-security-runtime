# Multi-stage build for the S2 response webhook (webhook/app.py). Minimal
# runtime image, non-root user, no build tooling in the final stage.

FROM python:3.12-slim AS builder

WORKDIR /build
COPY webhook/requirements.txt .
RUN pip install --no-cache-dir --target=/deps -r requirements.txt

FROM python:3.12-slim

# Fixed numeric UID: Kubernetes' runAsNonRoot check (gitops/webhook/deployment.yaml)
# can't verify a non-numeric USER is non-root, so the pod spec pins runAsUser to
# this same value.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin --uid 10001 webhook

COPY --from=builder /deps /deps
COPY webhook/app.py /app/app.py

ENV PYTHONPATH=/deps \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
USER webhook

EXPOSE 8080 9090

# python app.py (runs main(), not `python -m uvicorn app:app`): main() also
# starts the dedicated metrics-only server on 9090 (see app.py's module
# docstring) before handing off to uvicorn for the main app on 8080.
CMD ["python", "app.py"]
