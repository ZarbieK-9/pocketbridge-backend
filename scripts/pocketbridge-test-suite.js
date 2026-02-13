/**
 * PocketBridge Test Suite
 * 
 * Runs comprehensive tests for the PocketBridge backend
 * Usage: node scripts/pocketbridge-test-suite.js
 */

import { execSync } from 'child_process';
import { existsSync } from 'fs';

const testsDir = './tests';
const e2eDir = './tests/e2e';
const routesDir = './tests/routes';
const integrationDir = './tests/integration';

// Color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function logHeader(text) {
  log(`\n${colors.bright}${colors.blue}${'='.repeat(60)}${colors.reset}`, colors.blue);
  log(`${colors.bright}${colors.blue}${text}${colors.reset}`, colors.blue);
  log(`${colors.bright}${colors.blue}${'='.repeat(60)}${colors.reset}\n`, colors.blue);
}

function logSection(text) {
  log(`\n${colors.cyan}${text}${colors.reset}`, colors.cyan);
}

function runCommand(command, description) {
  log(`Running: ${description}...`, colors.yellow);
  try {
    execSync(command, { stdio: 'inherit', cwd: process.cwd() });
    log(`✓ ${description} passed`, colors.green);
    return true;
  } catch (error) {
    log(`✗ ${description} failed`, colors.red);
    return false;
  }
}

function checkDirectoryExists(dir, name) {
  if (existsSync(dir)) {
    log(`✓ ${name} directory exists`, colors.green);
    return true;
  } else {
    log(`✗ ${name} directory not found at ${dir}`, colors.red);
    return false;
  }
}

// Main test runner
async function main() {
  logHeader('PocketBridge Test Suite');
  
  log('Starting PocketBridge backend tests...\n');
  
  let allPassed = true;
  
  // Check test directories exist
  logSection('Checking test structure...');
  
  const dirsExist = [
    checkDirectoryExists(testsDir, 'Tests'),
    checkDirectoryExists(e2eDir, 'E2E Tests'),
    checkDirectoryExists(routesDir, 'Route Tests'),
    checkDirectoryExists(integrationDir, 'Integration Tests'),
  ];
  
  if (dirsExist.includes(false)) {
    log('\n✗ Test directory structure is incomplete', colors.red);
    process.exit(1);
  }
  
  // Run unit tests with vitest
  logSection('Running Unit Tests');
  if (!runCommand('npx vitest run --reporter=verbose', 'Unit Tests')) {
    allPassed = false;
  }
  
  // Run specific test categories
  logSection('Running Circuit Breaker Tests');
  if (!runCommand('npx vitest run tests/circuit-breaker.test.ts', 'Circuit Breaker')) {
    allPassed = false;
  }
  
  logSection('Running Crypto Tests');
  if (!runCommand('npx vitest run tests/crypto.utils.test.ts', 'Crypto Utils')) {
    allPassed = false;
  }
  
  logSection('Running Session Tests');
  if (!runCommand('npx vitest run tests/session-rotation.test.ts tests/multi-device-sessions.test.ts', 'Session Tests')) {
    allPassed = false;
  }
  
  logSection('Running Device Tests');
  if (!runCommand('npx vitest run tests/device-relay.test.ts tests/device-revocation.test.ts', 'Device Tests')) {
    allPassed = false;
  }
  
  logSection('Running Event Handler Tests');
  if (!runCommand('npx vitest run tests/event-handler.test.ts tests/event-ordering.test.ts', 'Event Handler Tests')) {
    allPassed = false;
  }
  
  logSection('Running Handshake Tests');
  if (!runCommand('npx vitest run tests/handshake.test.ts', 'Handshake')) {
    allPassed = false;
  }
  
  logSection('Running Rate Limiting Tests');
  if (!runCommand('npx vitest run tests/rate-limiting.test.ts', 'Rate Limiting')) {
    allPassed = false;
  }
  
  logSection('Running Auth Tests');
  if (!runCommand('npx vitest run tests/jwt-auth.test.ts', 'JWT Auth')) {
    allPassed = false;
  }
  
  // Run route tests
  logSection('Running Route Tests');
  const routeTests = ['auth', 'devices', 'pairing', 'status'];
  for (const route of routeTests) {
    const testFile = `tests/routes/${route}.test.ts`;
    if (existsSync(testFile)) {
      if (!runCommand(`npx vitest run ${testFile}`, `${route} routes`)) {
        allPassed = false;
      }
    }
  }
  
  // Run integration tests
  logSection('Running Integration Tests');
  if (!runCommand('npx vitest run tests/integration/', 'Integration Tests')) {
    allPassed = false;
  }
  
  // Run E2E tests
  logSection('Running E2E Tests');
  if (!runCommand('npx vitest run tests/e2e/', 'E2E Tests')) {
    allPassed = false;
  }
  
  // Print summary
  logHeader('Test Summary');
  
  if (allPassed) {
    log('✓ All tests passed!', colors.green);
    log('\n🎉 PocketBridge backend is working correctly!\n', colors.green);
    process.exit(0);
  } else {
    log('✗ Some tests failed. Please review the output above.', colors.red);
    log('\n💡 Common fixes:\n', colors.yellow);
    log('  - Run "npm run migrate" to set up the database', colors.yellow);
    log('  - Run "npm run dev" to start the development server', colors.yellow);
    log('  - Check that PostgreSQL and Redis are running', colors.yellow);
    log('  - Review .env.example and create a .env file\n', colors.yellow);
    process.exit(1);
  }
}

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  log(`\n✗ Uncaught exception: ${error.message}`, colors.red);
  console.error(error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  log(`\n✗ Unhandled rejection: ${reason}`, colors.red);
  console.error(reason);
  process.exit(1);
});

main().catch((error) => {
  log(`\n✗ Test suite error: ${error.message}`, colors.red);
  console.error(error);
  process.exit(1);
});
