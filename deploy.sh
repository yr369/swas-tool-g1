#!/bin/bash
# deploy.sh - run this ON THE OCI SERVER (not your local PC) to update SWAS.
#
# What it does, step by step:
#   1. Pulls the latest code from GitHub
#   2. Rebuilds any Docker images that changed
#   3. Restarts the containers with the new code
#   4. Shows you the status so you can confirm it's healthy
#
# Usage:  ./deploy.sh

set -e  # stop immediately if any command fails, instead of continuing blindly

echo "=== SWAS deploy: pulling latest code ==="
git pull origin main

echo "=== SWAS deploy: rebuilding changed images ==="
docker compose build

echo "=== SWAS deploy: restarting services ==="
docker compose up -d

echo "=== SWAS deploy: current status ==="
docker compose ps

echo ""
echo "Deploy finished. Check the status above - all services should say"
echo "'running' or 'healthy'. If something says 'restarting' repeatedly,"
echo "run: docker compose logs <service_name>   to see what went wrong."
