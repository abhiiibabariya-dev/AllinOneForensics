#!/usr/bin/env sh
set -eu

volume="${AIOF_VOLUME:-allinoneforensicswork_aiof-production-cases}"
out="${1:-aiof-backup-$(date -u +%Y%m%dT%H%M%SZ).tar.gz}"

docker run --rm \
  -v "${volume}:/source:ro" \
  -v "$PWD:/backup" \
  alpine:3.20 \
  tar -czf "/backup/${out}" -C /source .

echo "Created ${out}"
