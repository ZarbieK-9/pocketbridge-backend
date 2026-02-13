/**
 * Database Health Check Script
 * 
 * Checks the health of PostgreSQL and Redis connections
 * Usage: tsx scripts/check-db.ts
 */

import 'dotenv/config';
import pg from 'pg';
import { createClient, RedisClientType } from 'redis';
import { config } from '../src/config.js';

const { Pool } = pg;

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

function log(message: string, color: string = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function logHeader(text: string) {
  log(`\n${colors.bright}${colors.blue}${'='.repeat(60)}${colors.reset}`, colors.blue);
  log(`${colors.bright}${colors.blue}${text}${colors.reset}`, colors.blue);
  log(`${colors.bright}${colors.blue}${'='.repeat(60)}${colors.reset}\n`, colors.blue);
}

interface CheckResult {
  name: string;
  status: 'ok' | 'error' | 'warning';
  message: string;
  details?: Record<string, unknown>;
}

const results: CheckResult[] = [];

/**
 * Check PostgreSQL connection
 */
async function checkPostgres(): Promise<void> {
  log('Checking PostgreSQL...', colors.cyan);
  
  const pool = new Pool({
    host: config.postgres.host,
    port: config.postgres.port,
    database: config.postgres.database,
    user: config.postgres.user,
    password: config.postgres.password,
    connectionTimeoutMillis: 5000,
  });

  try {
    // Test connection
    const client = await pool.connect();
    const result = await client.query('SELECT version()');
    client.release();

    log(`✓ PostgreSQL connected`, colors.green);
    log(`  Version: ${result.rows[0].version.split(' ')[0]} ${result.rows[0].version.split(' ')[1]}`, colors.reset);

    // Check tables exist
    const tablesResult = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);
    
    const tables = tablesResult.rows.map((row: any) => row.table_name);
    log(`  Tables: ${tables.length} found`, colors.reset);
    
    if (tables.length === 0) {
      results.push({
        name: 'PostgreSQL',
        status: 'warning',
        message: 'No tables found. Run migrations.',
      });
    } else {
      results.push({
        name: 'PostgreSQL',
        status: 'ok',
        message: `Connected. ${tables.length} tables found.`,
        details: { tables },
      });
    }

    // Check for required tables
    const requiredTables = ['users', 'user_devices', 'events', 'pairing_codes', 'schema_migrations'];
    const missingTables = requiredTables.filter(t => !tables.includes(t));
    
    if (missingTables.length > 0) {
      log(`  ⚠ Missing tables: ${missingTables.join(', ')}`, colors.yellow);
      results.push({
        name: 'Required Tables',
        status: 'warning',
        message: `Missing tables: ${missingTables.join(', ')}. Run migrations.`,
      });
    } else {
      log(`  ✓ All required tables present`, colors.green);
    }

    // Check migrations
    try {
      const migrationResult = await pool.query('SELECT version, name FROM schema_migrations ORDER BY version');
      log(`  Migrations: ${migrationResult.rows.length} applied`, colors.reset);
      
      if (migrationResult.rows.length === 0) {
        results.push({
          name: 'Migrations',
          status: 'warning',
          message: 'No migrations applied. Run npm run migrate.',
        });
      }
    } catch {
      log(`  ⚠ schema_migrations table not found`, colors.yellow);
    }

    // Check user count
    const userCountResult = await pool.query('SELECT COUNT(*) as count FROM users');
    log(`  Users: ${userCountResult.rows[0].count}`, colors.reset);
    
    // Check device count
    const deviceCountResult = await pool.query('SELECT COUNT(*) as count FROM user_devices');
    log(`  Devices: ${deviceCountResult.rows[0].count}`, colors.reset);

    await pool.end();
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    log(`✗ PostgreSQL connection failed: ${errorMessage}`, colors.red);
    results.push({
      name: 'PostgreSQL',
      status: 'error',
      message: errorMessage,
    });
    await pool.end();
  }
}

/**
 * Check Redis connection
 */
async function checkRedis(): Promise<void> {
  log('\nChecking Redis...', colors.cyan);
  
  const client: RedisClientType = createClient({
    socket: {
      host: config.redis.host,
      port: config.redis.port,
    },
    password: config.redis.password,
  });

  client.on('error', (err) => log(`✗ Redis error: ${err}`, colors.red));

  try {
    await client.connect();
    
    // Test connection
    await client.ping();
    log(`✓ Redis connected`, colors.green);

    // Check server info
    const info = await client.info('server');
    const versionMatch = info.match(/redis_version:(.+)/);
    if (versionMatch) {
      log(`  Version: ${versionMatch[1].trim()}`, colors.reset);
    }

    // Check keys
    const dbInfo = await client.info('keyspace');
    const dbMatch = dbInfo.match(/db(\d+):keys=(\d+)/);
    if (dbMatch) {
      log(`  Keys: ${dbMatch[2]}`, colors.reset);
    }

    results.push({
      name: 'Redis',
      status: 'ok',
      message: 'Connected successfully',
      details: { version: versionMatch?.[1]?.trim() },
    });

    await client.quit();
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    log(`✗ Redis connection failed: ${errorMessage}`, colors.red);
    results.push({
      name: 'Redis',
      status: 'error',
      message: errorMessage,
    });
    await client.quit().catch(() => {});
  }
}

/**
 * Check environment configuration
 */
function checkConfig(): void {
  log('\nChecking Configuration...', colors.cyan);
  
  const checks = [
    { name: 'Port', value: config.port, required: true },
    { name: 'Node Env', value: config.nodeEnv, required: true },
    { name: 'PostgreSQL Host', value: config.postgres.host, required: true },
    { name: 'PostgreSQL Port', value: config.postgres.port, required: true },
    { name: 'PostgreSQL Database', value: config.postgres.database, required: true },
    { name: 'Redis Host', value: config.redis.host, required: true },
    { name: 'Redis Port', value: config.redis.port, required: true },
    { name: 'Server Public Key', value: config.serverIdentity.publicKeyHex ? 'Set' : 'Missing', required: true },
    { name: 'CORS Origin', value: Array.isArray(config.cors.origin) ? config.cors.origin.join(', ') : config.cors.origin, required: false },
  ];

  let configOk = true;
  
  for (const check of checks) {
    const isSet = check.value !== undefined && check.value !== '' && check.value !== null;
    const status = isSet || !check.required ? '✓' : '⚠';
    const color = isSet || !check.required ? colors.green : colors.yellow;
    log(`  ${status} ${check.name}: ${check.value || '(not set)'}`, color);
    
    if (!isSet && check.required) {
      configOk = false;
    }
  }

  results.push({
    name: 'Configuration',
    status: configOk ? 'ok' : 'warning',
    message: configOk ? 'All required configuration present' : 'Some required configuration missing',
  });
}

/**
 * Print summary
 */
function printSummary(): void {
  logHeader('Summary');
  
  const ok = results.filter(r => r.status === 'ok').length;
  const warnings = results.filter(r => r.status === 'warning').length;
  const errors = results.filter(r => r.status === 'error').length;

  for (const result of results) {
    const icon = result.status === 'ok' ? '✓' : result.status === 'warning' ? '⚠' : '✗';
    const color = result.status === 'ok' ? colors.green : result.status === 'warning' ? colors.yellow : colors.red;
    log(`${icon} ${result.name}: ${result.message}`, color);
  }

  log(`\n${colors.bright}Total: ${ok} OK, ${warnings} warnings, ${errors} errors${colors.reset}`);

  if (errors > 0) {
    log('\n✗ Database check failed. Please fix the errors above.\n', colors.red);
    process.exit(1);
  } else if (warnings > 0) {
    log('\n⚠ Database check completed with warnings.\n', colors.yellow);
  } else {
    log('\n✓ Database check passed!\n', colors.green);
    process.exit(0);
  }
}

/**
 * Main function
 */
async function main() {
  logHeader('PocketBridge Database Health Check');
  
  log(`Environment: ${config.nodeEnv}`);
  log(`Time: ${new Date().toISOString()}\n`);

  // Check configuration
  checkConfig();

  // Check PostgreSQL
  await checkPostgres();

  // Check Redis
  await checkRedis();

  // Print summary
  printSummary();
}

// Handle errors
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
  log(`\n✗ Check failed: ${error.message}`, colors.red);
  console.error(error);
  process.exit(1);
});
