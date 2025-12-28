/**
 * Database Migration System
 *
 * Manages database schema migrations with versioning and rollback support
 */

import type { Database } from './postgres.js';
import { logger } from '../utils/logger.js';
import { readFileSync, readdirSync, existsSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface Migration {
  version: number;
  name: string;
  up: string;
  down?: string;
}

/**
 * Get all migration files
 */
function getMigrations(): Migration[] {
  const migrations: Migration[] = [];
  
  // Try multiple possible paths for migrations directory
  const possiblePaths = [
    join(process.cwd(), 'migrations'),              // From backend directory (when running npm script)
    join(process.cwd(), 'backend/migrations'),      // From workspace root
    join(__dirname, '../../migrations'),           // From dist/db (compiled)
    join(__dirname, '../../../migrations'),        // Alternative compiled path
  ];
  
  let migrationsDir: string | null = null;
  for (const path of possiblePaths) {
    try {
      if (existsSync(path) && statSync(path).isDirectory()) {
        migrationsDir = path;
        break;
      }
    } catch {
      // Continue to next path
    }
  }
  
  if (!migrationsDir) {
    logger.warn('Could not find migrations directory', { 
      triedPaths: possiblePaths,
      cwd: process.cwd(),
      __dirname: __dirname 
    });
    return [];
  }
  
  logger.debug('Found migrations directory', { path: migrationsDir });

  // Read migration files
  try {
    const files = readdirSync(migrationsDir).filter((f: string) => f.endsWith('.sql'));

    for (const file of files) {
      const match = file.match(/^(\d+)-(.+)\.sql$/);
      if (match) {
        const version = parseInt(match[1], 10);
        const name = match[2];
        const content = readFileSync(join(migrationsDir, file), 'utf-8');

        // Split into up and down migrations
        const parts = content.split(/^--\s*DOWN\s*$/m);
        const up = parts[0].replace(/^--\s*UP\s*$/m, '').trim();
        const down = parts[1]?.trim() || '';

        migrations.push({ version, name, up, down });
      }
    }
  } catch (error) {
    logger.warn('Could not read migrations directory', { error });
  }

  return migrations.sort((a, b) => a.version - b.version);
}

/**
 * Create migrations table if it doesn't exist
 */
async function ensureMigrationsTable(db: Database): Promise<void> {
  await db.pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
}

/**
 * Get applied migrations
 */
async function getAppliedMigrations(db: Database): Promise<number[]> {
  const result = await db.pool.query('SELECT version FROM schema_migrations ORDER BY version');
  return result.rows.map((row: any) => row.version);
}

/**
 * Apply a migration
 */
async function applyMigration(db: Database, migration: Migration): Promise<void> {
  logger.info(`Applying migration ${migration.version}: ${migration.name}`);

  // Start transaction
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');

    // Execute migration
    await client.query(migration.up);

    // Record migration
    await client.query('INSERT INTO schema_migrations (version, name) VALUES ($1, $2)', [
      migration.version,
      migration.name,
    ]);

    await client.query('COMMIT');
    logger.info(`Migration ${migration.version} applied successfully`);
  } catch (error) {
    await client.query('ROLLBACK');
    logger.error(`Migration ${migration.version} failed`, {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Rollback a migration
 */
async function rollbackMigration(db: Database, migration: Migration): Promise<void> {
  if (!migration.down) {
    throw new Error(`Migration ${migration.version} has no rollback script`);
  }

  logger.info(`Rolling back migration ${migration.version}: ${migration.name}`);

  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');

    // Execute rollback
    await client.query(migration.down);

    // Remove migration record
    await client.query('DELETE FROM schema_migrations WHERE version = $1', [migration.version]);

    await client.query('COMMIT');
    logger.info(`Migration ${migration.version} rolled back successfully`);
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Run all pending migrations
 */
export async function runMigrations(db: Database): Promise<void> {
  logger.info('Checking for pending migrations...');

  // Ensure migrations table exists
  await ensureMigrationsTable(db);

  // Get all migrations and applied migrations
  const allMigrations = getMigrations();
  const appliedMigrations = await getAppliedMigrations(db);

  // Find pending migrations
  const pendingMigrations = allMigrations.filter(m => !appliedMigrations.includes(m.version));

  if (pendingMigrations.length === 0) {
    logger.info('No pending migrations');
    return;
  }

  logger.info(`Found ${pendingMigrations.length} pending migration(s)`);

  // Apply pending migrations in order
  for (const migration of pendingMigrations) {
    await applyMigration(db, migration);
  }

  logger.info('All migrations applied successfully');
}

/**
 * Rollback last migration
 */
export async function rollbackLastMigration(db: Database): Promise<void> {
  await ensureMigrationsTable(db);

  const allMigrations = getMigrations();
  const appliedMigrations = await getAppliedMigrations(db);

  if (appliedMigrations.length === 0) {
    throw new Error('No migrations to rollback');
  }

  const lastVersion = appliedMigrations[appliedMigrations.length - 1];
  const migration = allMigrations.find(m => m.version === lastVersion);

  if (!migration) {
    throw new Error(`Migration ${lastVersion} not found`);
  }

  await rollbackMigration(db, migration);
}

/**
 * Get migration status
 */
export async function getMigrationStatus(db: Database): Promise<{
  applied: number[];
  pending: number[];
  total: number;
}> {
  await ensureMigrationsTable(db);

  const allMigrations = getMigrations();
  const appliedMigrations = await getAppliedMigrations(db);
  const pendingMigrations = allMigrations
    .filter(m => !appliedMigrations.includes(m.version))
    .map(m => m.version);

  return {
    applied: appliedMigrations,
    pending: pendingMigrations,
    total: allMigrations.length,
  };
}
