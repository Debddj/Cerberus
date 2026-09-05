FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir uv

COPY pyproject.toml README.md ./
RUN uv pip install --system -e .

COPY src/ ./src
COPY policies/ ./policies

# Non-root security posture (Bug 24)
RUN adduser --disabled-password --gecos '' cerberus && chown -R cerberus:cerberus /app
USER cerberus

EXPOSE 8000 9090

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/healthz || exit 1

CMD ["uvicorn", "cerberus.proxy.server:app", "--host", "0.0.0.0", "--port", "8000"]
