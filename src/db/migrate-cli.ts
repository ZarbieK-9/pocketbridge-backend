/**
 * Migration CLI
 *
 * Command-line interface for running migrations
 */

import { initDatabase } from './postgres.js';
import { runMigrations, rollbackLastMigration, getMigrationStatus } from './migrations.js';
import { logger } from '../utils/logger.js';

async function main() {
  const command = process.argv[2] || 'up';

  try {
    const db = await initDatabase();

    switch (command) {
      case 'up':
        await runMigrations(db);
        break;

      case 'rollback':
        await rollbackLastMigration(db);
        logger.info('Last migration rolled back');
        break;

      case 'status':
        const status = await getMigrationStatus(db);
        console.log('\nMigration Status:');
        console.log(`Total migrations: ${status.total}`);
        console.log(`Applied: ${status.applied.length} (${status.applied.join(', ') || 'none'})`);
        console.log(`Pending: ${status.pending.length} (${status.pending.join(', ') || 'none'})`);
        break;

      default:
        console.error(`Unknown command: ${command}`);
        console.error('Usage: npm run migrate [up|rollback|status]');
        process.exit(1);
    }

    await db.end();
    process.exit(0);
  } catch (error) {
    logger.error('Migration failed', {}, error instanceof Error ? error : new Error(String(error)));
    process.exit(1);
  }
}

main();
