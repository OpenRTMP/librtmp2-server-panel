FROM python:alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev libffi-dev

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:alpine

WORKDIR /app

COPY --from=builder /install /usr/local
COPY . .

RUN mkdir -p /data && adduser -D -h /app appuser && chown -R appuser:appuser /app /data
ENV PANEL_DB_PATH=/data/panel.db

USER appuser
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]
