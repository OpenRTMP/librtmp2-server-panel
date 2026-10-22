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
        --wsgi-app)
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
    for arg in "$@"; do
        if [ "$expect_value" -eq 1 ]; then
            expect_value=0
            continue
        fi
        case "$arg" in
            --*=*)
                continue ;;
            -*)
                if option_takes_value "$arg"; then
                    expect_value=1
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

# Return 0 when the arguments carry a Gunicorn bind option, i.e. "-b",
# "--bind" or "--bind=ADDRESS". A host:port value (for example the
# "0.0.0.0:8000" of the default --bind) is not a bind option.
bind_option_supplied() {
    for arg in "$@"; do
        case "$arg" in
            -b|-b*|--bind|--bind=*)
                return 0 ;;
            *)
                ;;
        esac
    done
    return 1
}

# The image's default command (kept in sync with the Dockerfile CMD). Without
# this guard an empty argument list would exit 0 without ever starting
# gunicorn, and a flag-first invocation would be consumed by the shell's own
# exec builtin. Mirrors the guard in ../librtmp2-server/entrypoint.sh.
if [ "$#" -eq 0 ] || [ "${1#-}" != "$1" ]; then
    # Gunicorn's bind setting is append-valued, so a bind address supplied
    # by the operator has to replace the image's default one instead of
    # being appended to it: otherwise the service keeps listening on
    # 0.0.0.0:8000 and the operator's restriction is defeated.
    if bind_option_supplied "$@"; then
        default_bind=
    else
        default_bind="--bind 0.0.0.0:8000"
    fi
    if app_target_supplied "$@"; then
        # Gunicorn serves the first positional argument, so an application
        # target supplied by the operator must not be preceded by the
        # image's default one.
        set -- gunicorn $default_bind --worker-class gthread --threads 4 --timeout 450 "$@"
    else
        set -- gunicorn $default_bind --worker-class gthread --threads 4 --timeout 450 app:app "$@"
    fi
fi

exec "$@"
