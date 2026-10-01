FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
WORKDIR /app
COPY pyproject.toml README.md uv.lock ./
COPY src ./src
COPY docs/threat-framework-map.yaml ./docs/threat-framework-map.yaml
COPY policies ./policies
RUN pip install --no-cache-dir 'uv==0.11.24' \
    && uv sync --locked --no-dev --no-install-project \
    && rm -rf /root/.cache/uv
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app/src PATH="/app/.venv/bin:$PATH"
CMD ["uvicorn", "agentsentry.main:app", "--host", "0.0.0.0", "--port", "8000"]
