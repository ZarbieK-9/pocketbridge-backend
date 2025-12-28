# Backend Next Steps Roadmap

**Last Updated:** After Critical Fixes Implementation  
**Current Status:** ~85% Production Ready  
**Critical Fixes:** ✅ All Completed

---

## 🎯 Immediate Next Steps (This Week)

### 1. Device Revocation Check ⚠️ **HIGH PRIORITY**
**Status:** Not Implemented  
**Impact:** Security - Revoked devices can continue sessions  
**Effort:** 2-3 hours

**What to do:**
- Add revocation check in `handleEvent` function
- Check revocation status before processing each message
- Close WebSocket if device is revoked

**Files to modify:**
- `backend/src/gateway/event-handler.ts`
- `backend/src/gateway/websocket.ts`

**Implementation:**
```typescript
// In handleEvent or message handler
const isRevoked = await isDeviceRevoked(db, sessionState.deviceId);
if (isRevoked) {
  ws.close(1008, 'Device has been revoked');
  throw new ValidationError('Device has been revoked');
}
```

---

### 2. Error Message Sanitization ⚠️ **HIGH PRIORITY**
**Status:** Not Implemented  
**Impact:** Security - May leak internal details  
**Effort:** 1-2 hours

**What to do:**
- Sanitize error messages in production
- Hide stack traces in production
- Keep detailed errors in development

**Files to modify:**
- `backend/src/utils/errors.ts`
- All error handlers

**Implementation:**
```typescript
// In error handler
const sanitizedError = process.env.NODE_ENV === 'production'
  ? 'Internal server error'
  : error.message;
```

---

### 3. Device Name Uniqueness ⚠️ **MEDIUM PRIORITY**
**Status:** Not Enforced  
**Impact:** UX - Multiple devices can have same name  
**Effort:** 1 hour

**What to do:**
- Add unique constraint per user for device names
- Update validation in rename endpoint

**Files to modify:**
- `backend/migrations/003-device-name-uniqueness.sql` (new)
- `backend/src/routes/devices.ts`

---

## 📋 High Priority Items (Next 2 Weeks)

### 4. User Account Deletion Endpoint
**Status:** Not Implemented  
**Impact:** GDPR Compliance  
**Effort:** 4-6 hours

**What to do:**
- Create DELETE `/api/user` endpoint
- Cascade delete all user data
- Close all active sessions
- Return confirmation

**Files to create/modify:**
- `backend/src/routes/user.ts` (new)
- `backend/src/index.ts`

---

### 5. Request ID Tracking Enhancement
**Status:** ✅ Already Implemented  
**Verification:** Check if it's working correctly

---

### 6. Replay Pagination
**Status:** Not Implemented  
**Impact:** Performance - Large replays may timeout  
**Effort:** 3-4 hours

**What to do:**
- Add pagination to replay response
- Limit events per response (e.g., 100)
- Add continuation token

**Files to modify:**
- `backend/src/gateway/websocket.ts` (replay handler)

---

### 7. Clock Skew Tolerance
**Status:** Not Implemented  
**Impact:** Edge case - TTL validation may fail  
**Effort:** 2-3 hours

**What to do:**
- Add ±5 minute tolerance for TTL validation
- Update event validation logic

**Files to modify:**
- `backend/src/gateway/event-handler.ts`

---

## 🧪 Testing (Critical - 2-3 Weeks)

### 8. Unit Tests
**Current Coverage:** ~10-15%  
**Target:** 80%+  
**Effort:** 2-3 weeks

**Priority Order:**
1. **Handshake Logic** (`src/gateway/handshake.ts`)
   - Client Hello processing
   - Server Hello generation
   - Client Auth verification
   - Signature verification
   - State transitions

2. **Event Handler** (`src/gateway/event-handler.ts`)
   - Event validation
   - Stream sequence assignment
   - Conflict resolution
   - Relay logic

3. **Device Relay** (`src/services/device-relay.ts`)
   - User isolation
   - Event routing
   - Access verification

4. **Validation Functions** (`src/utils/validation.ts`)
   - All validation edge cases

5. **Crypto Utils** (`src/crypto/utils.ts`)
   - Already started, complete coverage

---

### 9. Integration Tests
**Status:** Not Implemented  
**Effort:** 1 week

**Test Scenarios:**
- Full WebSocket handshake flow
- Event relay between devices
- Multi-device scenarios
- Error recovery
- Reconnection handling

---

### 10. E2E Tests
**Status:** Not Implemented  
**Effort:** 1 week

**Test Scenarios:**
- Complete user journey
- Device pairing
- Event synchronization
- Error scenarios

---

## 📚 Documentation (1-2 Weeks)

### 11. API Documentation
**Status:** Not Implemented  
**Effort:** 3-5 days

**What to do:**
- Generate OpenAPI/Swagger spec
- Document all endpoints
- Include request/response examples
- Add authentication details

**Tools:** Swagger/OpenAPI

---

### 12. Deployment Guide
**Status:** Basic scripts exist  
**Effort:** 3-5 days

**What to do:**
- Step-by-step deployment instructions
- Environment setup guide
- Database migration guide
- Troubleshooting guide
- Rollback procedures

---

## 🚀 Infrastructure (1-2 Weeks)

### 13. CI/CD Pipeline
**Status:** Not Implemented  
**Effort:** 1 week

**What to do:**
- GitHub Actions workflows
- Automated testing
- Automated deployment
- Dependency scanning

**Files to create:**
- `.github/workflows/ci.yml`
- `.github/workflows/deploy.yml`
- `.github/dependabot.yml`

---

### 14. Database Backup Strategy
**Status:** Not Documented  
**Effort:** 2-3 days

**What to do:**
- Document backup strategy
- Configure automated backups (if using managed DB)
- Backup verification process
- Restore procedure documentation

---

### 15. Performance Testing
**Status:** Not Performed  
**Effort:** 1-2 weeks

**What to do:**
- Establish performance baselines
- Load testing (k6, Artillery, or Locust)
- Stress testing
- Performance monitoring
- Optimize slow operations

---

## 📊 Monitoring & Observability (1 Week)

### 16. Alerting System
**Status:** Metrics exist, no alerts  
**Effort:** 1 week

**What to do:**
- Set up Prometheus Alertmanager
- Define alert rules:
  - High error rate
  - High latency
  - Service down
  - Database/Redis failures
- Configure notifications

---

### 17. Distributed Tracing
**Status:** Request IDs exist, no tracing  
**Effort:** 1 week

**What to do:**
- Integrate OpenTelemetry
- Add span instrumentation
- Export traces to backend
- Trace visualization

---

## 🎯 Recommended Order

### Week 1: Security & Quick Wins
1. ✅ Device revocation check (2-3 hours)
2. ✅ Error message sanitization (1-2 hours)
3. ✅ Device name uniqueness (1 hour)
4. ✅ Clock skew tolerance (2-3 hours)
5. Start: Unit tests for handshake

### Week 2-3: Testing Focus
1. Complete handshake unit tests
2. Event handler unit tests
3. Device relay unit tests
4. Integration tests
5. E2E tests

### Week 4: Documentation & Infrastructure
1. API documentation
2. Deployment guide
3. CI/CD pipeline
4. Database backup strategy

### Week 5: Performance & Monitoring
1. Performance testing
2. Alerting system
3. Distributed tracing

---

## 📈 Progress Tracking

### Completed ✅
- [x] Empty state handling
- [x] Device offline detection
- [x] Health check endpoint
- [x] Graceful shutdown
- [x] Multi-device support
- [x] User isolation
- [x] Rate limiting
- [x] Metrics collection
- [x] Circuit breakers

### In Progress 🟡
- [ ] Device revocation check
- [ ] Error sanitization
- [ ] Unit tests

### Pending ⚠️
- [ ] User account deletion
- [ ] Replay pagination
- [ ] Integration tests
- [ ] E2E tests
- [ ] API documentation
- [ ] CI/CD pipeline
- [ ] Performance testing
- [ ] Alerting system

---

## 🎯 Current Focus: Security & Testing

**Immediate Priority:**
1. **Device Revocation Check** - Security critical
2. **Error Sanitization** - Security critical
3. **Unit Tests** - Quality assurance

**Next Sprint:**
1. Integration tests
2. API documentation
3. CI/CD pipeline

---

## 💡 Quick Wins (Can Do Today)

1. **Device Revocation Check** - 2-3 hours
2. **Error Sanitization** - 1-2 hours
3. **Device Name Uniqueness** - 1 hour
4. **Clock Skew Tolerance** - 2-3 hours

**Total:** ~6-9 hours of work for significant improvements

---

## 📝 Notes

- **Production Readiness:** Currently ~85%
- **Critical Path:** Security fixes → Testing → Documentation
- **Estimated Time to 95% Ready:** 4-6 weeks
- **Estimated Time to 100% Ready:** 8-11 weeks

**Recommendation:** Focus on security fixes and testing first, then documentation and infrastructure.

