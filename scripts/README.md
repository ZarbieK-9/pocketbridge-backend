# PocketBridge Test Scripts

## 🧪 Comprehensive Test Suite

### Main Test: `pocketbridge-test-suite.js`

Complete end-to-end test suite validating all PocketBridge functionality:

**Features Tested:**
- ✅ Device Authentication & Handshake (ECDH + Ed25519)
- ✅ 6-Digit Code Pairing (Apple-like)
- ✅ Real-Time Clipboard Sync (Bidirectional)
- ✅ Real-Time File Sharing (Bidirectional)
- ✅ Multi-Device Sync
- ✅ Session Management
- ✅ Security & Validation

### Running Tests

```bash
# From backend directory
npm run test

# Or directly
node scripts/pocketbridge-test-suite.js

# With custom backend URL
BACKEND_URL=ws://localhost:3000 node scripts/pocketbridge-test-suite.js
```

### Expected Output

```
╔═══════════════════════════════════════════════════════════════════════╗
║           PocketBridge - Comprehensive Test Suite                    ║
╚═══════════════════════════════════════════════════════════════════════╝

✅ ✅ Device 1 Authenticated
✅ ✅ Device 2 Authenticated
✅ ✅ Devices Paired via Code
✅ ✅ Same User ID After Pairing
✅ ✅ Clipboard Synced (D1→D2)
✅ ✅ Clipboard Synced (D2→D1)
✅ ✅ Files Synced (D1→D2)
✅ ✅ Files Synced (D2→D1)

🎉 ALL 8/8 TESTS PASSED!
🎉 ALL TESTS PASSED! PocketBridge is production-ready! ✨
```

## Utility Scripts

- `check-db.ts` - Database connection checker
- `simulate-devices.ts` - Device simulation for development

### Check Database
```bash
npm run check-db
# or
npx tsx scripts/check-db.ts
```

## Deployment Scripts

Located in `deployment/` folder:
- `deploy-railway.sh` - Deploy to Railway (Linux/Mac)
- `deploy-railway.ps1` - Deploy to Railway (Windows)
- `open-firewall-port.bat` - Open firewall port (Windows)
- `open-firewall-port.ps1` - Open firewall port (PowerShell)

### Deploy to Railway
```bash
# Linux/Mac
./scripts/deployment/deploy-railway.sh

# Windows
.\scripts\deployment\deploy-railway.ps1
```

## Test Configuration

### Environment Variables

```bash
# Backend WebSocket URL (default: ws://localhost:3000)
BACKEND_URL=ws://your-backend.com

# Test timeout (default: 120 seconds)
TEST_TIMEOUT=120
```

### Prerequisites

1. PostgreSQL database running
2. Redis server running
3. Backend server running

```bash
cd backend
npm run dev
```

## Troubleshooting

**Connection Refused:**
- Start backend server first: `npm run dev`

**Test Timeout:**
- Check backend logs
- Verify database and Redis are running

**Pairing Failed:**
- Check backend logs for errors
- Verify Redis is working correctly

