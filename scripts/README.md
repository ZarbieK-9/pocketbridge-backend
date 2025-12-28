# Backend Scripts

## Deployment Scripts
- `deployment/deploy-railway.sh` - Deploy to Railway (Linux/Mac)
- `deployment/deploy-railway.ps1` - Deploy to Railway (Windows)
- `deployment/open-firewall-port.bat` - Open firewall port (Windows)
- `deployment/open-firewall-port.ps1` - Open firewall port (PowerShell)

## Utility Scripts
- `check-db.ts` - Database connection checker

## Usage

### Deploy to Railway
```bash
# Linux/Mac
./scripts/deployment/deploy-railway.sh

# Windows
.\scripts\deployment\deploy-railway.ps1
```

### Check Database
```bash
npm run check-db
# or
npx tsx scripts/check-db.ts
```

