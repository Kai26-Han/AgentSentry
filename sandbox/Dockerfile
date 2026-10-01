FROM python:3.12-slim
WORKDIR /app
COPY sandbox/server.py sandbox/exec.py ./
USER 65534:65534
ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/server.py"]
