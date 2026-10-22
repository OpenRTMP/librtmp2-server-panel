#!/bin/sh
set -eu

VERSION_FILE="${OPENRTMP_VERSION_FILE:-/usr/local/share/openrtmp/VERSION}"
VERSION="unknown"
if [ -r "$VERSION_FILE" ]; then
    VERSION="$(cat "$VERSION_FILE")"
fi

if printf '%s\n' "$VERSION" | grep -qE '^v[0-9]+\.[0-9]'; then
    DISPLAY_VERSION="$VERSION"
elif printf '%s\n' "$VERSION" | grep -qE '^[0-9]+\.[0-9]'; then
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

# The image's default command (kept in sync with the Dockerfile CMD). Without
# this guard an empty argument list would exit 0 without ever starting
# gunicorn, and a flag-first invocation would be consumed by the shell's own
# exec builtin. Mirrors the guard in ../librtmp2-server/entrypoint.sh.
if [ "$#" -eq 0 ] || [ "${1#-}" != "$1" ]; then
    set -- gunicorn --bind 0.0.0.0:8000 --worker-class gthread --threads 4 --timeout 450 app:app "$@"
fi

exec "$@"
