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

exec "$@"