FROM python:alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev rust cargo

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:alpine

WORKDIR /app

RUN apk add --no-cache libffi openssl

COPY --from=builder /install /usr/local
COPY . .

RUN mkdir -p /data && \
    adduser -D -h /app openrtmp && \
    chown -R openrtmp:openrtmp /app /data

USER openrtmp
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:8000/login || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "app:app"]
