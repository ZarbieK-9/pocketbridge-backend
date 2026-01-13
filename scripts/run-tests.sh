#!/bin/bash

###############################################################################
# PocketBridge Test Runner
###############################################################################
# 
# Starts backend server and runs comprehensive test suite
#
# Usage:
#   ./scripts/run-tests.sh
#   
# Requirements:
#   - PostgreSQL running
#   - Redis running
#   - Node.js installed
###############################################################################

set -e

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                       ║"
echo "║              PocketBridge - Automated Test Runner                    ║"
echo "║                                                                       ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check prerequisites
echo "📋 Checking prerequisites..."
echo ""

# Check PostgreSQL
if ! command -v psql &> /dev/null; then
    echo -e "${YELLOW}⚠️  PostgreSQL client not found (test will try to connect anyway)${NC}"
else
    echo -e "${GREEN}✅ PostgreSQL client installed${NC}"
fi

# Check Redis
if ! command -v redis-cli &> /dev/null; then
    echo -e "${YELLOW}⚠️  Redis client not found (test will try to connect anyway)${NC}"
else
    echo -e "${GREEN}✅ Redis client installed${NC}"
fi

echo ""
echo "🚀 Starting backend server..."
echo ""

# Start backend in background
npm run dev &
BACKEND_PID=$!

# Wait for backend to be ready
echo "⏳ Waiting for backend to start..."
sleep 5

echo ""
echo "🧪 Running test suite..."
echo ""

# Run tests
if npm run test; then
    echo ""
    echo -e "${GREEN}✅ All tests passed!${NC}"
    RESULT=0
else
    echo ""
    echo -e "${RED}❌ Tests failed${NC}"
    RESULT=1
fi

# Cleanup
echo ""
echo "🧹 Cleaning up..."
kill $BACKEND_PID 2>/dev/null || true

echo ""
echo "Done!"
echo ""

exit $RESULT
