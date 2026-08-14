# ==============================================================================
# AegisMCP-Gateway Windows Container Verification Script
# ==============================================================================

$ImageTag = "aegismcp-gateway:test"

Write-Host "=== 1. Building Production Docker Image ($ImageTag) ===" -ForegroundColor Cyan
docker build -t $ImageTag -f Dockerfile .
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker build failed"
    exit 1
}

Write-Host "=== 2. Starting Container Instance ===" -ForegroundColor Cyan
$ContainerId = docker run -d -p 8080:8080 -e RUST_LOG=debug $ImageTag

try {
    Write-Host "=== 3. Probing Gateway Health Endpoint ===" -ForegroundColor Cyan
    Start-Sleep -Seconds 3

    $HealthResp = Invoke-RestMethod -Uri "http://127.0.0.1:8080/health" -Method Get -TimeoutSec 5
    Write-Host "Health Response: $($HealthResp | ConvertTo-Json -Compress)"

    if ($HealthResp.status -eq "ok") {
        Write-Host "✅ Health check passed!" -ForegroundColor Green
    } else {
        throw "Health check returned unexpected payload"
    }

    $MetricsResp = Invoke-WebRequest -Uri "http://127.0.0.1:8080/metrics" -Method Get -TimeoutSec 5
    if ($MetricsResp.Content.Length -gt 0) {
        Write-Host "✅ Metrics endpoint passed!" -ForegroundColor Green
    } else {
        throw "Metrics endpoint returned empty payload"
    }

    Write-Host "=== All Container Verifications Passed! ===" -ForegroundColor Green
} finally {
    Write-Host "=== Cleaning Up Test Container ===" -ForegroundColor Yellow
    docker rm -f $ContainerId | Out-Null
}
