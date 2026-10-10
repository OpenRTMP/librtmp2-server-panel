# Pin the Python minor version: pip installs wheels only (--only-binary :all:),
# so an unannounced jump of the floating `alpine` tag to a Python release that
# some dependency has no musllinux wheel for yet would break the image build.
FROM python:3.14-alpine AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary :all: --require-hashes --prefix=/install -r requirements.txt

FROM python:3.14-alpine

ARG APP_VERSION=""

WORKDIR /app

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
