import express from 'express';
import request from 'supertest';
import devicesRouter, { setDatabase as setDevicesDatabase, setSessionsMap as setDevicesSessionsMap } from '../src/routes/devices.ts';
import statusRouter, { setSessionsMap as setStatusSessionsMap } from '../src/routes/status.ts';

class FakeDB {
  constructor() {
    this.pool = {
      query: async (sql, params) => {
        const q = String(sql).replace(/\s+/g, ' ').trim().toLowerCase();
        const userId = params[0];
        if (q.startsWith('select') && q.includes('from user_devices') && q.includes('where user_id = $1')) {
          return {
            rows: [
              {
                device_id: '11111111-1111-1111-1111-111111111111',
                device_name: 'Web Client',
                device_type: 'web',
                device_os: 'windows',
                last_seen: new Date(),
                registered_at: new Date(),
                ip_address: '127.0.0.1',
                user_id: userId,
              },
              {
                device_id: '22222222-2222-2222-2222-222222222222',
                device_name: 'Mobile',
                device_type: 'mobile',
                device_os: 'android',
                last_seen: new Date(),
                registered_at: new Date(),
                ip_address: '127.0.0.1',
                user_id: userId,
              },
            ],
          };
        }
        if (q.startsWith('select') && q.includes('from user_devices') && q.includes('where device_id = $1::uuid and user_id = $2')) {
          return {
            rows: [
              {
                device_id: params[0],
                device_name: 'Web Client',
                device_type: 'web',
                device_os: 'windows',
                last_seen: new Date(),
                registered_at: new Date(),
                ip_address: '127.0.0.1',
                user_id: params[1],
              },
            ],
          };
        }
        if (q.startsWith('update user_devices set device_name = $1')) {
          return { rows: [{ device_id: params[1], device_name: params[0] }] };
        }
        if (q.startsWith('delete from user_devices')) {
          return { rows: [] };
        }
        if (q.startsWith('update user_devices set is_online')) {
          return { rows: [] };
        }
        return { rows: [] };
      },
    };
  }
}

function buildApp(sessions) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    const userId = req.get('X-User-ID') || req.query.userId;
    if (userId) req.userId = userId;
    next();
  });

  const db = new FakeDB();
  setDevicesDatabase(db);
  setDevicesSessionsMap(sessions);
  setStatusSessionsMap(sessions);

  app.use('/api', devicesRouter);
  app.use('/api', statusRouter);
  return app;
}

describe('Devices & Presence API (multi-schema)', () => {
  const userId = 'ed25519pubhex-abcdef1234567890';
  const onlineDeviceId = '11111111-1111-1111-1111-111111111111';
  let app;

  beforeAll(() => {
    const sessions = new Map();
    sessions.set(onlineDeviceId, {
      userId,
      deviceId: onlineDeviceId,
      sessionKeys: { clientKey: Buffer.from('a'), serverKey: Buffer.from('b') },
      lastAckDeviceSeq: 0,
      createdAt: Date.now(),
    });
    app = buildApp(sessions);
  });

  it('GET /api/devices returns devices with is_online computed', async () => {
    const res = await request(app)
      .get('/api/devices')
      .set('X-User-ID', userId)
      .expect(200);

    expect(res.body).toHaveProperty('devices');
    expect(res.body.devices.length).toBe(2);
    const online = res.body.devices.find((d) => d.device_id === onlineDeviceId);
    const offline = res.body.devices.find((d) => d.device_id !== onlineDeviceId);
    expect(online.is_online).toBe(true);
    expect(offline.is_online).toBe(false);
  });

  it('GET /api/presence returns counts reflecting sessions', async () => {
    const res = await request(app)
      .get('/api/presence')
      .set('X-User-ID', userId)
      .expect(200);

    expect(res.body).toHaveProperty('devices');
    expect(res.body.total_count).toBe(2);
    expect(res.body.online_count).toBe(1);
  });
});
