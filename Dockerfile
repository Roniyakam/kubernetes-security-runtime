# Multi-stage build for the S2 response webhook (webhook/app.py). Minimal
# runtime image, non-root user, no build tooling in the final stage.

FROM python:3.12-slim AS builder

WORKDIR /build
COPY webhook/requirements.txt .
RUN pip install --no-cache-dir --target=/deps -r requirements.txt

FROM python:3.12-slim

RUN useradd --system --no-create-home --shell /usr/sbin/nologin webhook

COPY --from=builder /deps /deps
COPY webhook/app.py /app/app.py

ENV PYTHONPATH=/deps \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
USER webhook

EXPOSE 8080

# python -m uvicorn, not the /deps/bin/uvicorn console script: pip --target
# bakes an absolute shebang pointing at the builder stage's interpreter,
# which is fragile to rely on even though both stages share a base image.
CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
