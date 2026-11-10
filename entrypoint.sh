#!/bin/sh
set -eu

VERSION_FILE="${OPENRTMP_VERSION_FILE:-/usr/local/share/openrtmp/VERSION}"
VERSION="unknown"
if [ -r "$VERSION_FILE" ]; then
    VERSION="$(cat "$VERSION_FILE")"
fi

if printf '%s\n' "$VERSION" | grep -qE '^v[0-9]+\.[0-9]+'; then
    DISPLAY_VERSION="$VERSION"
elif printf '%s\n' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+'; then
    DISPLAY_VERSION="v$VERSION"
else
    DISPLAY_VERSION="$VERSION"
fi

cat <<'BANNER'
   ___                   ____ ______ __  __ ____
  / _ \ _ __   ___ _ __ |  _ \_   _|  \/  |  _ \
 | | | | '_ \ / _ \ '_ \| |_) || | | |\/| | |_) |
 | |_| | |_) |  __/ | | |  _ < | | | |  | |  __/
  \___/| .__/ \___|_| |_|_| \_\|_| |_|  |_|_|
       |_|
BANNER
printf '  librtmp2-server-panel %s\n\n' "$DISPLAY_VERSION"

# Return 0 when the given Gunicorn option takes its value as the next
# argument. Without this the value of an option such as --config or --chdir
# would be mistaken for the WSGI application target.
option_takes_value() {
    case "$1" in
        -b|--bind|-w|--workers|-k|--worker-class|-t|--timeout|-c|--config|\
        --chdir|-n|--name|-u|--user|-g|--group|-m|--umask|-p|--pid|-e|--env|\
        --threads|--worker-connections|--graceful-timeout|--keep-alive|\
        --max-requests|--max-requests-jitter|--backlog|--worker-tmp-dir|\
        --log-level|--log-file|--access-logfile|--error-logfile|\
        --access-logformat|--logger-class|--certfile|--keyfile|--ca-certs|\
        --ssl-version|--ciphers|--forwarded-allow-ips|--proxy-allow-from|\
        --statsd-host|--dogstatsd|--paste|--pythonpath|--reload-engine|\
        --reload-extra-file|--limit-request-line|--limit-request-fields|\
        --limit-request-field-size|--sendfile|--raw-passthrough|--spec|\
        --protocol|--log-config|--log-config-json|--header-map|\
        --forwarder-headers|--root-path|--statsd-prefix|--dogstatsd-tags|\
        --log-syslog-to|--log-syslog-facility|--log-syslog-prefix|\
        --cert-reqs|--http-protocols|--http-parser|--control-socket|\
        --http2-*|--server-hooks|\
        --paste-global|--paster|--uwsgi-allow-from|--asgi-*|--dirty-*)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

# Return 0 when the option takes its value only when the next token is not
# another flag (Gunicorn's ``--proxy-protocol`` is MODE with nargs='?').
option_takes_optional_value() {
    case "$1" in
        --proxy-protocol)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

# Return 0 when the value looks like a WSGI application target: a
# "module:callable" pair (optionally written "module:callable()"), a path to a
# python file, or a dotted module name. A host:port value (for example the
# "0.0.0.0:8000" of --bind) is not an application target.
is_app_target() {
    case "$1" in
        *'()')
            # "module:create_app()" - the trailing call is not part of the name.
            is_app_target "${1%()}"
            return $? ;;
        *)
            ;;
    esac
    case "$1" in
        *.py)
            return 0 ;;
        *)
            ;;
    esac
    case "$1" in
        *:*)
            ;;
        *)
            case "$1" in
                ''|[0-9]*|*[!A-Za-z0-9_.]*)
                    return 1 ;;
                *)
                    return 0 ;;
            esac ;;
    esac
    module="${1%%:*}"
    callable="${1#*:}"
    case "$module" in
        ''|[0-9]*|*[!A-Za-z0-9_.]*)
            return 1 ;;
        *)
            ;;
    esac
    case "$callable" in
        ''|*[!A-Za-z0-9_]*)
            return 1 ;;
        *)
            return 0 ;;
    esac
}

# Return 0 when the arguments carry a WSGI application target. Option values
# are skipped, so "--config gunicorn.conf.py" is not read as an application.
app_target_supplied() {
    expect_value=0
    expect_optional=0
    for arg in "$@"; do
        if [ "$expect_value" -eq 1 ]; then
            expect_value=0
            continue
        fi
        if [ "$expect_optional" -eq 1 ]; then
            expect_optional=0
            case "$arg" in
                -*) ;;
                *) continue ;;
            esac
        fi
        case "$arg" in
            --*=*)
                continue ;;
            -*)
                if option_takes_value "$arg"; then
                    expect_value=1
                elif option_takes_optional_value "$arg"; then
                    expect_optional=1
                fi
                continue ;;
            *)
                ;;
        esac
        if is_app_target "$arg"; then
            return 0
        fi
    done
    return 1
}

# Path to the helper that mirrors Gunicorn's configuration precedence without
# importing or executing the operator's config file.
PROBE_SCRIPT="${OPENRTMP_CONFIG_PROBE:-}"
if [ -z "$PROBE_SCRIPT" ]; then
    case "$0" in
        */*)
            PROBE_SCRIPT="$(dirname "$0")/gunicorn_config_probe.py" ;;
        *)
            PROBE_SCRIPT=/usr/local/bin/gunicorn_config_probe.py ;;
    esac
fi

# Gunicorn is a Python program, so the image always ships an interpreter; the
# loop only keeps a shell-only environment from failing outright.
PYTHON_BIN=
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done

# Ask the probe whether the effective Gunicorn configuration provides a
# setting. Returns 0 when it does, 1 when it provably does not, and 2 when the
# configuration cannot be inspected (no interpreter or no helper script).
config_probe() {
    probe_mode="$1"
    shift
    if [ -z "$PYTHON_BIN" ] || [ ! -r "$PROBE_SCRIPT" ]; then
        return 2
    fi
    set +e
    "$PYTHON_BIN" "$PROBE_SCRIPT" "$probe_mode" "$@"
    probe_status=$?
    set -e
    return "$probe_status"
}

# Return 0 when the effective configuration already supplies a bind address.
# Gunicorn reads GUNICORN_CMD_ARGS (shlex-split), then the -c config file and
# the implicit gunicorn.conf.py, and the command line; the probe mirrors that
# order. An uninspectable configuration counts as supplied so the image never
# overrides an operator setting with its own default.
bind_configured() {
    probe_status=0
    config_probe bind "$@" || probe_status=$?
    [ "$probe_status" -ne 1 ]
}

# Return 0 when the effective configuration already supplies the application
# itself (``wsgi_app``). Gunicorn serves the first positional argument in
# preference to ``wsgi_app``, so the image's default application must not be
# added when the operator's config already supplies one. An uninspectable
# configuration counts as supplied: the alternative would silently override a
# wrapper (for example an auth or IP-allowlist app) the probe cannot see. If the
# config truly has no ``wsgi_app``, Gunicorn fails loudly instead of serving
# the wrong application.
config_supplies_app() {
    probe_status=0
    config_probe wsgi-app "$@" || probe_status=$?
    [ "$probe_status" -ne 1 ]
}

# The image CMD is the WSGI target ("app:app"), not a full gunicorn command
# line. Wrapping it here keeps the default bind/worker flags out of Gunicorn's
# CLI layer: Gunicorn applies CLI settings last, so a `--bind` in CMD would
# override an operator's GUNICORN_CMD_ARGS or gunicorn.conf.py. A flag-first
# invocation and an empty argument list are wrapped too. An explicit
# `gunicorn ...` command is executed unchanged.
if [ "$#" -eq 0 ] || [ "${1#-}" != "$1" ] || [ "$1" = "app:app" ]; then
    # Add the image's default bind only when the effective Gunicorn
    # configuration does not already provide one. `bind` is append-valued
    # within a single argparse parse, but a CLI value replaces config-file and
    # environment values, so the default must not be present at all when the
    # operator supplied one.
    if bind_configured "$@"; then
        default_bind=
    else
        default_bind="--bind 0.0.0.0:8000"
    fi
    if [ "$#" -eq 1 ] && [ "$1" = "app:app" ] && config_supplies_app "$@"; then
        # The image CMD is only a default. Gunicorn serves the first positional
        # argument in preference to `wsgi_app`, so the default must be dropped
        # when the operator's configuration names its own application (for
        # example an auth or IP-allowlist wrapper).
        set -- gunicorn $default_bind --worker-class gthread --threads 4 --timeout 450
    elif app_target_supplied "$@" || config_supplies_app "$@"; then
        # Gunicorn serves the first positional argument, so an application
        # target supplied by the operator (or by its config) must not be
        # preceded by the image's default one.
        set -- gunicorn $default_bind --worker-class gthread --threads 4 --timeout 450 "$@"
    else
        set -- gunicorn $default_bind --worker-class gthread --threads 4 --timeout 450 app:app "$@"
    fi
fi

exec "$@"
