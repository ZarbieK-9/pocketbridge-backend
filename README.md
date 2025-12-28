# PocketBridge Backend

Express.js backend server with WebSocket support for secure cross-device synchronization.

## Quick Start

```bash
# Install dependencies
npm install

# Run migrations
npm run migrate

# Start development server
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

## Project Structure

```
backend/
├── src/              # Source code
│   ├── gateway/     # WebSocket gateway
│   ├── routes/      # REST API routes
│   ├── services/    # Business logic
│   ├── middleware/  # Express middleware
│   ├── db/          # Database utilities
│   └── crypto/      # Cryptographic utilities
├── migrations/       # Database migrations
├── tests/            # Test files
├── docs/             # Documentation
│   ├── analysis/    # Gap analysis & planning
│   ├── implementation/ # Implementation docs
│   └── testing/     # Testing documentation
├── scripts/          # Utility scripts
│   └── deployment/  # Deployment scripts
└── dist/            # Compiled output
```

## Configuration

See `CONFIG.md` for configuration details.

## Documentation

- **Roadmap:** `docs/NEXT_STEPS_ROADMAP.md`
- **Production Readiness:** `docs/analysis/PRODUCTION_GAP_ANALYSIS.md`
- **Remaining Work:** `docs/analysis/REMAINING_GAPS_ANALYSIS.md`
- **Test Status:** `docs/testing/TEST_SUMMARY.md`

See `docs/README.md` for complete documentation index.

## Scripts

- **Deploy:** `scripts/deployment/deploy-railway.sh`
- **Check DB:** `npm run check-db`

See `scripts/README.md` for all available scripts.

## Features

- ✅ Multi-device WebSocket support
- ✅ End-to-end encryption
- ✅ Device management
- ✅ Event relay system
- ✅ User isolation
- ✅ Rate limiting
- ✅ Circuit breakers
- ✅ Prometheus metrics

## Testing

```bash
# Run unit tests
npm test

# Run with coverage
npm run test:coverage
```

## Deployment

See `scripts/deployment/` for deployment scripts.

