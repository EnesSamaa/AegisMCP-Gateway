#!/usr/bin/env bash
# ==============================================================================
# AegisMCP-Gateway Container Verification Script
# Validates multi-stage Docker build, distroless image size, and binary execution.
# ==============================================================================

set -euo pipefail

IMAGE_TAG="aegismcp-gateway:test"

echo "=== 1. Building Production Docker Image (${IMAGE_TAG}) ==="
docker build -t "${IMAGE_TAG}" -f Dockerfile .

echo "=== 2. Inspecting Image Metadata & Size ==="
docker images "${IMAGE_TAG}"

echo "=== 3. Starting Test Container Instance ==="
CONTAINER_ID=$(docker run -d -p 8080:8080 -e RUST_LOG=debug "${IMAGE_TAG}")

cleanup() {
    echo "=== Cleaning Up Test Container ==="
    docker rm -f "${CONTAINER_ID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== 4. Waiting for Gateway Health Endpoint ==="
sleep 3

# Query /health
HEALTH_RESP=$(curl -s http://127.0.0.1:8080/health || true)
echo "Health Response: ${HEALTH_RESP}"

if [[ "${HEALTH_RESP}" == *"status"*"ok"* ]]; then
    echo "✅ Health check passed!"
else
    echo "❌ Health check failed!"
    docker logs "${CONTAINER_ID}"
    exit 1
fi

# Query /metrics
METRICS_RESP=$(curl -s http://127.0.0.1:8080/metrics || true)
if [[ "${METRICS_RESP}" == *"aegis_"* || "${METRICS_RESP}" == *"# "* ]]; then
    echo "✅ Metrics endpoint passed!"
else
    echo "❌ Metrics endpoint failed!"
    exit 1
fi

echo "=== All Container Verifications Passed Successfully ==="
