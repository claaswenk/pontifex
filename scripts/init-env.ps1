# Windows counterpart of init-env.sh (for the dev system only; production is Linux).
# Creates .env from .env.example with a random value for every empty secret.
# Refuses to overwrite an existing .env, so running secrets are never replaced.

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if (Test-Path '.env') {
    Write-Error '.env already exists. Delete it first if you really want new secrets.'
}

$secretKeys = 'INITIAL_API_KEY', 'JWT_SECRET', 'BACKEND_FRONTEND_SECRET', 'BACKEND_DATABASE_SECRET'

function New-Secret {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    -join ($bytes | ForEach-Object { $_.ToString('x2') })
}

$lines = foreach ($line in Get-Content '.env.example') {
    $key = $line.TrimEnd('=')
    if ($line.EndsWith('=') -and $secretKeys -contains $key) { "$key=$(New-Secret)" } else { $line }
}

$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines((Join-Path (Get-Location) '.env'), [string[]]$lines, $utf8)

Write-Host '[OK] .env created. Next: build the local images (see README, "Build from the local sources")'
Write-Host '[INFO] INITIAL_API_KEY is needed once to create the first admin:'
Select-String -Path '.env' -Pattern '^INITIAL_API_KEY=' | ForEach-Object { $_.Line }
