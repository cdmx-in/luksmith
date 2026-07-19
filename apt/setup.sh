#!/bin/sh
# luksmith apt repo setup — curl -fsSL https://cdmx-in.github.io/luksmith/setup.sh | sudo sh
set -eu

BASE="https://cdmx-in.github.io/luksmith"
KEYRING=/usr/share/keyrings/luksmith-archive-keyring.gpg
LIST=/etc/apt/sources.list.d/luksmith.list

[ "$(id -u)" -eq 0 ] || { echo "error: run as root (pipe to 'sudo sh')" >&2; exit 1; }

if curl -fsSL "$BASE/luksmith-archive-keyring.gpg" -o "$KEYRING"; then
    echo "deb [signed-by=$KEYRING] $BASE ./" > "$LIST"
    echo "Added signed luksmith apt repo."
else
    # ponytail: repo published without a signing key; runtime fallback beats build-time templating
    echo "" >&2
    echo "############################################################" >&2
    echo "# WARNING: the luksmith repo is NOT GPG-signed.            #" >&2
    echo "# Using [trusted=yes] — apt will NOT verify packages.      #" >&2
    echo "# Only continue if you accept that risk.                   #" >&2
    echo "############################################################" >&2
    echo "" >&2
    echo "deb [trusted=yes] $BASE ./" > "$LIST"
fi

apt-get update
echo "Done. Install with: apt-get install luksmith"
