/**
 * Database Check Script
 * Queries the database to check table structure and data
 */

import 'dotenv/config';
import { initDatabase } from '../src/db/postgres.js';
import { logger } from '../src/utils/logger.js';

async function checkDatabase() {
  try {
    const db = await initDatabase();
    logger.info('Database connected');

    // Check if user_devices table exists
    const tableCheck = await db.pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'user_devices'
      );
    `);

    console.log('\n=== Table Existence Check ===');
    console.log('user_devices table exists:', tableCheck.rows[0].exists);

    if (tableCheck.rows[0].exists) {
      // Get table structure
      const structure = await db.pool.query(`
        SELECT 
          column_name, 
          data_type, 
          is_nullable,
          column_default
        FROM information_schema.columns
        WHERE table_name = 'user_devices'
        ORDER BY ordinal_position;
      `);

      console.log('\n=== user_devices Table Structure ===');
      structure.rows.forEach((row: any) => {
        console.log(`  ${row.column_name}: ${row.data_type} (nullable: ${row.is_nullable})`);
      });

      // Check if there's any data
      const count = await db.pool.query('SELECT COUNT(*) FROM user_devices');
      console.log('\n=== Data Count ===');
      console.log(`Total devices: ${count.rows[0].count}`);

      // Check what user_ids exist in user_devices
      const deviceUsers = await db.pool.query('SELECT DISTINCT user_id FROM user_devices LIMIT 5');
      console.log('\n=== User IDs in user_devices ===');
      if (deviceUsers.rows.length > 0) {
        deviceUsers.rows.forEach((row: any, idx: number) => {
          console.log(`${idx + 1}. ${row.user_id.substring(0, 32)}... (length: ${row.user_id.length})`);
        });
        
        // Test with a user_id that has devices
        const testUserId = deviceUsers.rows[0].user_id;
        console.log(`\n=== Testing Query (with user_id that has devices) ===`);
        console.log(`Using user_id: ${testUserId.substring(0, 32)}...`);
        try {
          const result = await db.pool.query(`
            SELECT 
              device_id, device_name, device_type, device_os,
              last_seen, registered_at, ip_address
            FROM user_devices
            WHERE user_id = $1
            ORDER BY last_seen DESC
          `, [testUserId]);
          console.log(`Query succeeded, returned ${result.rows.length} rows`);
          
          if (result.rows.length > 0) {
            console.log('\n=== Sample Row ===');
            const row = result.rows[0];
            console.log('device_id:', row.device_id, typeof row.device_id);
            console.log('device_name:', row.device_name);
            console.log('last_seen:', row.last_seen, typeof row.last_seen);
            
            // Test the mapping logic
            try {
              const deviceIdStr = typeof row.device_id === 'string' 
                ? row.device_id 
                : row.device_id?.toString() || String(row.device_id);
              const lastSeenTimestamp = row.last_seen 
                ? new Date(row.last_seen).getTime() 
                : Date.now();
              console.log('\n=== Mapping Test ===');
              console.log('device_id as string:', deviceIdStr);
              console.log('last_seen as timestamp:', lastSeenTimestamp);
              console.log('Mapping succeeded!');
            } catch (mapError) {
              console.error('Mapping failed:', mapError instanceof Error ? mapError.message : String(mapError));
            }
          }
        } catch (error) {
          console.error('Query failed:', error instanceof Error ? error.message : String(error));
          if (error instanceof Error && error.stack) {
            console.error('Stack:', error.stack);
          }
        }
      } else {
        console.log('No devices found in user_devices table');
      }
    }

    // Check users table
    const usersCheck = await db.pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'users'
      );
    `);
    console.log('\n=== Users Table ===');
    console.log('users table exists:', usersCheck.rows[0].exists);

    if (usersCheck.rows[0].exists) {
      const usersCount = await db.pool.query('SELECT COUNT(*) FROM users');
      console.log(`Total users: ${usersCount.rows[0].count}`);
    }

    await db.end();
    logger.info('Database check complete');
  } catch (error) {
    logger.error('Database check failed', {}, error instanceof Error ? error : new Error(String(error)));
    console.error('Error:', error);
    process.exit(1);
  }
}

checkDatabase();

