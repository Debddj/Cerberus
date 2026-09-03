FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir uv

COPY pyproject.toml README.md ./
RUN uv pip install --system -e .

COPY src/ ./src
COPY policies/ ./policies

EXPOSE 8000 9090

CMD ["uvicorn", "cerberus.proxy.server:app", "--host", "0.0.0.0", "--port", "8000"]
