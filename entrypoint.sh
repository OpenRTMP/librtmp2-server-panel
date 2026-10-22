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

# Return 0 when the arguments carry a WSGI application target, i.e. a
# "module:callable" pair or a path to a python file. A host:port value (for
# example the "0.0.0.0:8000" of --bind) is not an application target.
app_target_supplied() {
    for arg in "$@"; do
        case "$arg" in
            -*) continue ;;
        esac
        case "$arg" in
            *.py) return 0 ;;
        esac
        case "$arg" in
            *:*) ;;
            *) continue ;;
        esac
        module="${arg%%:*}"
        callable="${arg#*:}"
        case "$module" in
            ''|[0-9]*|*[!A-Za-z0-9_.]*) continue ;;
        esac
        case "$callable" in
            ''|*[!A-Za-z0-9_]*) continue ;;
        esac
        return 0
    done
    return 1
}

# Return 0 when the arguments carry a Gunicorn bind option, i.e. "-b",
# "--bind" or "--bind=ADDRESS". A host:port value (for example the
# "0.0.0.0:8000" of the default --bind) is not a bind option.
bind_option_supplied() {
    for arg in "$@"; do
        case "$arg" in
            -b|-b*|--bind|--bind=*) return 0 ;;
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
