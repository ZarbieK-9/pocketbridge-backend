#!/bin/bash

# PocketBridge Backend - Railway CLI Deployment Script
# This script automates the Railway deployment process

set -e  # Exit on error

echo "🚂 PocketBridge Backend - Railway Deployment"
echo "=============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Railway CLI is installed
if ! command -v railway &> /dev/null; then
    echo -e "${RED}❌ Railway CLI is not installed${NC}"
    echo "Install it with: npm install -g @railway/cli"
    echo "Or visit: https://railway.app/cli"
    exit 1
fi

echo -e "${GREEN}✅ Railway CLI found${NC}"
echo ""

# Check if logged in
if ! railway whoami &> /dev/null; then
    echo -e "${YELLOW}⚠️  Not logged in to Railway${NC}"
    echo "Logging in..."
    railway login
fi

echo -e "${GREEN}✅ Logged in to Railway${NC}"
echo ""

# Generate keys if they don't exist
if [ ! -f ".env" ] || ! grep -q "SERVER_PUBLIC_KEY" .env 2>/dev/null; then
    echo -e "${YELLOW}⚠️  Server keys not found${NC}"
    echo "Generating server keys..."
    node generate-keys.js
    echo ""
    echo -e "${YELLOW}⚠️  Please copy the keys above and set them as Railway variables${NC}"
    echo "You can do this with: railway variables set SERVER_PUBLIC_KEY=\"...\""
    echo ""
    read -p "Press Enter to continue after setting the keys..."
fi

# Initialize Railway project if not already linked
if [ ! -d ".railway" ]; then
    echo "Initializing Railway project..."
    railway init
else
    echo -e "${GREEN}✅ Railway project already linked${NC}"
fi

# Check for PostgreSQL service
if ! railway service list 2>/dev/null | grep -q "postgresql"; then
    echo "Adding PostgreSQL database..."
    railway add postgresql
else
    echo -e "${GREEN}✅ PostgreSQL already added${NC}"
fi

# Check for Redis service
if ! railway service list 2>/dev/null | grep -q "redis"; then
    echo "Adding Redis..."
    railway add redis
else
    echo -e "${GREEN}✅ Redis already added${NC}"
fi

echo ""
echo "Setting environment variables..."

# Set required variables (with defaults if not set)
railway variables set NODE_ENV=production 2>/dev/null || true
railway variables set LOG_LEVEL=info 2>/dev/null || true

echo ""
echo -e "${YELLOW}⚠️  Don't forget to set these variables:${NC}"
echo "  - SERVER_PUBLIC_KEY"
echo "  - SERVER_PRIVATE_KEY"
echo "  - SERVER_PUBLIC_KEY_HEX"
echo "  - CORS_ORIGIN (your frontend URL)"
echo ""
echo "Set them with: railway variables set KEY=\"value\""
echo ""

read -p "Press Enter to deploy after setting all variables..."

# Deploy
echo ""
echo "🚀 Deploying to Railway..."
railway up

echo ""
echo -e "${GREEN}✅ Deployment complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Get your domain: railway domain"
echo "2. View logs: railway logs"
echo "3. Check status: railway status"
echo ""

