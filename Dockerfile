# Pin the Python minor version: pip installs wheels only (--only-binary :all:),
# so an unannounced jump of the floating `alpine` tag to a Python release that
# some dependency has no musllinux wheel for yet would break the image build.
FROM python:3.15-alpine AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary :all: --require-hashes --prefix=/install -r requirements.txt

FROM python:3.15-alpine

ARG APP_VERSION=""

WORKDIR /app

COPY --from=builder /install /usr/local
COPY app.py config.py lrtmp2_client.py session_store.py ./
COPY VERSION ./
COPY templates templates/
COPY static static/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY gunicorn_config_probe.py /usr/local/bin/gunicorn_config_probe.py

RUN version="${APP_VERSION:-$(cat VERSION)}" && \
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
# The entrypoint adds the default bind (and the worker flags) when the
# effective Gunicorn configuration does not already supply a bind. Keeping
# --bind out of the image CMD is required: Gunicorn applies CLI arguments
# last, so a bind here would override an operator's GUNICORN_CMD_ARGS or
# gunicorn.conf.py and expose the panel on 0.0.0.0.
CMD ["app:app"]
