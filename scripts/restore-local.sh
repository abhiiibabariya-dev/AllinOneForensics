#!/usr/bin/env sh
set -eu

archive="${1:?Usage: restore-local.sh backup.tar.gz [volume]}"
volume="${2:-allinoneforensicswork_aiof-production-cases}"

docker run --rm \
  -v "${volume}:/target" \
  -v "$PWD:/backup:ro" \
  alpine:3.20 \
  sh -c 'find /target -mindepth 1 -delete && tar -xzf "/backup/$1" -C /target' sh "$(basename "$archive")"

echo "Restored ${archive} into ${volume}"
