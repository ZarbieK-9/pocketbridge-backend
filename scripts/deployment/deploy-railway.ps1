# PocketBridge Backend - Railway CLI Deployment Script (PowerShell)
# This script automates the Railway deployment process

$ErrorActionPreference = "Stop"

Write-Host "🚂 PocketBridge Backend - Railway Deployment" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

# Check if Railway CLI is installed
try {
    $null = railway --version 2>&1
    Write-Host "✅ Railway CLI found" -ForegroundColor Green
} catch {
    Write-Host "❌ Railway CLI is not installed" -ForegroundColor Red
    Write-Host "Install it with: npm install -g @railway/cli" -ForegroundColor Yellow
    Write-Host "Or visit: https://railway.app/cli" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# Check if logged in
try {
    $null = railway whoami 2>&1
    Write-Host "✅ Logged in to Railway" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Not logged in to Railway" -ForegroundColor Yellow
    Write-Host "Logging in..."
    railway login
}

Write-Host ""

# Generate keys if they don't exist
if (-not (Test-Path ".env") -or -not (Select-String -Path ".env" -Pattern "SERVER_PUBLIC_KEY" -Quiet)) {
    Write-Host "⚠️  Server keys not found" -ForegroundColor Yellow
    Write-Host "Generating server keys..."
    node generate-keys.js
    Write-Host ""
    Write-Host "⚠️  Please copy the keys above and set them as Railway variables" -ForegroundColor Yellow
    Write-Host "You can do this with: railway variables set SERVER_PUBLIC_KEY=`"...`"" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to continue after setting the keys"
}

# Initialize Railway project if not already linked
if (-not (Test-Path ".railway")) {
    Write-Host "Initializing Railway project..."
    railway init
} else {
    Write-Host "✅ Railway project already linked" -ForegroundColor Green
}

# Check for PostgreSQL service
try {
    $services = railway service list 2>&1
    if ($services -notmatch "postgresql") {
        Write-Host "Adding PostgreSQL database..."
        railway add postgresql
    } else {
        Write-Host "✅ PostgreSQL already added" -ForegroundColor Green
    }
} catch {
    Write-Host "Adding PostgreSQL database..."
    railway add postgresql
}

# Check for Redis service
try {
    $services = railway service list 2>&1
    if ($services -notmatch "redis") {
        Write-Host "Adding Redis..."
        railway add redis
    } else {
        Write-Host "✅ Redis already added" -ForegroundColor Green
    }
} catch {
    Write-Host "Adding Redis..."
    railway add redis
}

Write-Host ""
Write-Host "Setting environment variables..."

# Set required variables (with defaults if not set)
try {
    railway variables set NODE_ENV=production 2>&1 | Out-Null
} catch {}

try {
    railway variables set LOG_LEVEL=info 2>&1 | Out-Null
} catch {}

Write-Host ""
Write-Host "⚠️  Don't forget to set these variables:" -ForegroundColor Yellow
Write-Host "  - SERVER_PUBLIC_KEY"
Write-Host "  - SERVER_PRIVATE_KEY"
Write-Host "  - SERVER_PUBLIC_KEY_HEX"
Write-Host "  - CORS_ORIGIN (your frontend URL)"
Write-Host ""
Write-Host "Set them with: railway variables set KEY=`"value`"" -ForegroundColor Yellow
Write-Host ""

Read-Host "Press Enter to deploy after setting all variables"

# Deploy
Write-Host ""
Write-Host "🚀 Deploying to Railway..." -ForegroundColor Cyan
railway up

Write-Host ""
Write-Host "✅ Deployment complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Get your domain: railway domain"
Write-Host "2. View logs: railway logs"
Write-Host "3. Check status: railway status"
Write-Host ""

