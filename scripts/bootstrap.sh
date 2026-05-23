#!/usr/bin/env bash
set -euo pipefail

cp -n .env.example .env || true
echo "Environment initialized. Run: make up"
