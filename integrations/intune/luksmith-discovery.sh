#!/bin/sh
# luksmith - Microsoft Intune custom-compliance discovery script for Linux.
#
# Runs in USER context (Intune does not run discovery scripts as root), so it
# only reads the non-secret status file the luksmith agent maintains at
# /var/lib/luksmith/compliance.json (mode 0644). Output: one line of JSON,
# consumed by the rules in luksmith-compliance-rules.json.
#
# Upload this script in Intune: Devices > Compliance > Scripts (Linux), then
# reference it from a custom-compliance policy with the rules file.

STATUS=/var/lib/luksmith/compliance.json

if [ ! -r "$STATUS" ]; then
    echo '{"luksmith_present": false, "recovery_key_escrowed": false, "tpm_bound": false, "boot_healthy": false}'
    exit 0
fi

get() {
    # Minimal JSON bool/string extractor - the file is machine-written, flat,
    # and trusted; no jq dependency in user context.
    sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\([^,}]*\).*/\1/p" "$STATUS" \
        | head -n1 | tr -d '"'
}

ESCROWED=$(get recovery_key_escrowed)
TPM=$(get tpm_bound)
BOOT=$(get last_boot_class)

[ "$ESCROWED" = "true" ] || ESCROWED=false
[ "$TPM" = "true" ] || TPM=false
if [ "$BOOT" = "tpm_unlock_ok" ] || [ "$BOOT" = "no_tpm_binding" ]; then
    HEALTHY=true
else
    HEALTHY=false
fi

echo "{\"luksmith_present\": true, \"recovery_key_escrowed\": $ESCROWED, \"tpm_bound\": $TPM, \"boot_healthy\": $HEALTHY}"
