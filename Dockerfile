FROM python:3.12-slim AS builder
WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir --target=/app/deps -r requirements.txt

FROM scratch
COPY --from=builder /app/deps /app/deps
COPY app/app.py /app/app.py
COPY app/index.html /app/index.html
ENV PYTHONPATH=/app/deps
WORKDIR /app
