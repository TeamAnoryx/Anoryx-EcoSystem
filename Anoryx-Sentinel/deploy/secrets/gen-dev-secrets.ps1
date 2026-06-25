# gen-dev-secrets.ps1 — Generate dev-only Docker secret files for Anoryx Sentinel.
#
# Run from the Anoryx-Sentinel directory:
#   .\deploy\secrets\gen-dev-secrets.ps1
#
# Idempotent: existing non-empty files are NEVER overwritten (re-run is safe).
# DO NOT use these values in production. See deploy/secrets/README.md.
#
# Files created in deploy/secrets/:
#   postgres_password  — "sentinel" (matches postgres service default)
#   redis_password     — (empty)    — bundled Redis has no auth
#   sentinel_key_secret — random 48-byte base64 HMAC key
#   admin_token        — random 48-byte url-safe base64 break-glass token
#   session_secret     — random 32-byte base64 session HMAC key

$ErrorActionPreference = "Stop"

$SecretsDir = Join-Path $PSScriptRoot ""

function Write-SecretIfAbsent {
    param([string]$File, [string]$Value)
    if ((Test-Path $File) -and (Get-Item $File).Length -gt 0) {
        Write-Host "gen-dev-secrets: $File already exists — skipped"
    } else {
        [System.IO.File]::WriteAllText($File, $Value, [System.Text.Encoding]::ASCII)
        Write-Host "gen-dev-secrets: $File created"
    }
}

function Write-EmptyIfAbsent {
    param([string]$File)
    if (Test-Path $File) {
        Write-Host "gen-dev-secrets: $File already exists — skipped"
    } else {
        New-Item -ItemType File -Force $File | Out-Null
        Write-Host "gen-dev-secrets: $File created (empty)"
    }
}

function New-RandomBase64 {
    param([int]$Bytes)
    $rand = New-Object byte[] $Bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($rand)
    return [Convert]::ToBase64String($rand) -replace "`r`n", ""
}

# 1. postgres_password — must match POSTGRES_PASSWORD default ("sentinel").
Write-SecretIfAbsent (Join-Path $SecretsDir "postgres_password") "sentinel"

# 2. redis_password — empty (bundled Redis has no requirepass).
Write-EmptyIfAbsent (Join-Path $SecretsDir "redis_password")

# 3. sentinel_key_secret — random 48-byte base64 HMAC key.
$f = Join-Path $SecretsDir "sentinel_key_secret"
if (-not (Test-Path $f) -or (Get-Item $f).Length -eq 0) {
    $v = New-RandomBase64 48
    [System.IO.File]::WriteAllText($f, $v, [System.Text.Encoding]::ASCII)
    Write-Host "gen-dev-secrets: $f created"
} else {
    Write-Host "gen-dev-secrets: $f already exists — skipped"
}

# 4. admin_token — random 48-byte break-glass token for /admin/* auth.
$f = Join-Path $SecretsDir "admin_token"
if (-not (Test-Path $f) -or (Get-Item $f).Length -eq 0) {
    $v = New-RandomBase64 48
    [System.IO.File]::WriteAllText($f, $v, [System.Text.Encoding]::ASCII)
    Write-Host "gen-dev-secrets: $f created"
} else {
    Write-Host "gen-dev-secrets: $f already exists — skipped"
}

# 5. session_secret — random 32-byte HMAC key for session cookie.
$f = Join-Path $SecretsDir "session_secret"
if (-not (Test-Path $f) -or (Get-Item $f).Length -eq 0) {
    $v = New-RandomBase64 32
    [System.IO.File]::WriteAllText($f, $v, [System.Text.Encoding]::ASCII)
    Write-Host "gen-dev-secrets: $f created"
} else {
    Write-Host "gen-dev-secrets: $f already exists — skipped"
}

Write-Host ""
Write-Host "gen-dev-secrets: done. Files in ${SecretsDir}:"
Write-Host "  postgres_password   redis_password   sentinel_key_secret   admin_token   session_secret"
Write-Host ""
Write-Host "CHANGE IN PROD: use strong random passwords for postgres_password and a"
Write-Host "dedicated secret manager (Vault / AWS-SM) for admin_token + session_secret."
