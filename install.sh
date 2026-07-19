#!/bin/sh
# luksmith agent installer for Ubuntu. Run from a repo checkout as root:
#   sudo ./install.sh
set -e

[ "$(id -u)" = 0 ] || { echo "run as root: sudo ./install.sh"; exit 1; }
cd "$(dirname "$0")" || exit 1

echo "Installing dependencies..."
apt-get update -qq
apt-get install -y -qq clevis clevis-luks clevis-tpm2 clevis-initramfs tpm2-tools

echo "Installing agent..."
mkdir -p /opt/luksmith
cp agent/luksmith.py /opt/luksmith/luksmith.py
printf '#!/bin/sh\nexec python3 /opt/luksmith/luksmith.py "$@"\n' > /usr/local/bin/luksmith
chmod 755 /usr/local/bin/luksmith

echo "Installing post-boot verify timer..."
cp packaging/luksmith-verify.service packaging/luksmith-verify.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now luksmith-verify.timer

echo
echo "Installed. Next:"
echo "  sudo luksmith enroll --server https://YOUR-PORTAL:8443 \\"
echo "       --org-pubkey /etc/luksmith/org_public.pem --enroll-secret YOUR-SECRET"
