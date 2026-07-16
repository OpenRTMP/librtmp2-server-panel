FROM python:alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev rust cargo

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:alpine

ARG APP_VERSION=""

WORKDIR /app

RUN apk add --no-cache libffi openssl

COPY --from=builder /install /usr/local
COPY . .
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN version="${APP_VERSION:-development}" && \
    mkdir -p /data /usr/local/share/openrtmp && \
    printf '%s\n' "$version" > /usr/local/share/openrtmp/VERSION && \
    chmod 0755 /usr/local/bin/entrypoint.sh && \
    adduser -D -h /app openrtmp && \
    chown -R openrtmp:openrtmp /app /data

ENV OPENRTMP_VERSION_FILE=/usr/local/share/openrtmp/VERSION

USER openrtmp
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:8000/login || exit 1

ENTRYPOINT ["entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--worker-class", "gthread", "--threads", "4", "--timeout", "60", "app:app"]
