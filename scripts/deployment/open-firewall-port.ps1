# PowerShell script to open Windows Firewall port for PocketBridge backend
# Run this as Administrator

Write-Host "Opening Windows Firewall port 3001 for PocketBridge backend..." -ForegroundColor Cyan

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Remove existing rule if it exists
$existingRule = Get-NetFirewallRule -DisplayName "PocketBridge Backend Port 3001" -ErrorAction SilentlyContinue
if ($existingRule) {
    Write-Host "Removing existing firewall rule..." -ForegroundColor Yellow
    Remove-NetFirewallRule -DisplayName "PocketBridge Backend Port 3001"
}

# Add new firewall rule
try {
    New-NetFirewallRule -DisplayName "PocketBridge Backend Port 3001" -Direction Inbound -LocalPort 3001 -Protocol TCP -Action Allow -Profile Domain,Private,Public -Description "Allows PocketBridge backend server to accept connections on port 3001"
    
    Write-Host "[SUCCESS] Firewall rule added successfully!" -ForegroundColor Green
    Write-Host "Port 3001 is now open for incoming connections." -ForegroundColor Green
    Write-Host ""
    Write-Host "You can now access the backend from other devices on your network:" -ForegroundColor Cyan
    Write-Host "  http://192.168.18.8:3001/health" -ForegroundColor White
} catch {
    Write-Host "ERROR: Failed to add firewall rule: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

