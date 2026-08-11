#!/bin/bash

# This script triggers Trivy and ignores:
# cifs, smb3, nfs, nfs4 and tmpfs filesystems.
#
# To check what actually gets ignored:
# findmnt -rn -t cifs,smb3,nfs,nfs4,tmpfs -o TARGET
#
# The result will be stored in:
# /var/lib/trivy/results/rootfs.json

RESULT_DIR="/var/lib/trivy/results"
RESULT_FILE="${RESULT_DIR}/rootfs.json"

mkdir -p "$RESULT_DIR"

SKIP_ARGS=()

while IFS= read -r mountpoint; do
    SKIP_ARGS+=(--skip-dirs "$mountpoint")
done < <(findmnt -rn -t cifs,smb3,nfs,nfs4,tmpfs -o TARGET)

trivy rootfs \
    --scanners vuln \
    --timeout 30m \
    --format json \
    --output "$RESULT_FILE" \
    "${SKIP_ARGS[@]}" \
    /