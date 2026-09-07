FROM python:3.14.7-alpine3.24 AS builder

WORKDIR /app

RUN apk add --no-cache \
    cargo=1.96.1-r0 \
    gcc=15.2.0-r5 \
    libffi-dev=3.5.2-r1 \
    musl-dev=1.2.6-r2 \
    openssl-dev=3.5.8-r0 \
    rust=1.96.1-r0

COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary :all: --prefix=/install -r requirements.txt

FROM python:3.14.7-alpine3.24

ARG APP_VERSION=""

WORKDIR /app

RUN apk add --no-cache \
    libffi=3.5.2-r1 \
    openssl=3.5.8-r0

COPY --from=builder /install /usr/local
COPY app.py config.py lrtmp2_client.py session_store.py ./
COPY templates templates/
COPY static static/
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
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--worker-class", "gthread", "--threads", "4", "--timeout", "330", "app:app"]
