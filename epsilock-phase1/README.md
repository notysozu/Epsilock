# EPSILOCK Phase 3 (Single Main Node + Backup Recovery Node)

EPSILOCK now includes:
- Phase 1: secure single-node bidirectional room chat (`/ws`)
- Phase 2: anomaly detection, room/session freeze, token revocation, incident logging
- Phase 3: backup-assisted secure recovery and clean reconnection

## Architecture

### Main Node (port 4000)
- Main app (admin + user dashboards)
- Main websocket endpoint `/ws`
- Incident detection and emergency freeze logic
- Recovery orchestration with Backup Node

### Backup Recovery Node (port 5000)
- Handles recovery request verification
- Issues short-lived single-use recovery tokens
- Completes recovery by producing clean replacement room metadata
- Stores recovery metadata only, no chat content

No sender/receiver split nodes are used.

## Phase 3 Goal

When a suspicious incident freezes a room/session, recovery creates a new clean session path:
- old compromised room/session is not trusted
- old chat history is not restored
- users re-authenticate before joining recovered room

## Security Rules Enforced

- HTTPS/WSS used for both nodes
- Main→Backup requests are signed with HMAC (`BACKUP_NODE_SECRET`)
- Backup verifies request signature and timestamp
- Recovery tokens are short-lived and single-use (`jti` tracked)
- Plain passwords are never stored
- Credentials are never forwarded to backup node
- Old JWT/session is never automatically trusted for recovered room

## Why Credentials Are Never Shared

User password verification is done on Main Node only (against local bcrypt hash). The Backup Node only receives a signed assertion (`verifiedByMain`) and never receives raw credentials.

## Why Old Sessions Are Not Reused

Suspicious sessions/tokens are revoked and frozen. Recovery creates a clean room with a new security context. This reduces chance of session fixation or replay from compromised state.

## Why Users Must Re-authenticate

Recovery requires identity re-verification because incident context is untrusted. Re-auth creates confidence that new session belongs to legitimate user.

## Data Models Added/Updated

### New
- `RecoveryRequest`
- `RecoveryToken`

### Updated
- `Room`
  - `replacedByRoomId`
  - `recoveredFromRoomId`
  - `recoveryStatus`
- `Incident`
  - `recoveryId`
  - `recoveryStatus`
  - `resolvedByRecovery`

## Project Additions

- `backup-node/server.js`
- `backup-node/routes/recovery.js`
- `backup-node/services/recoveryService.js`
- `backup-node/services/signatureVerifier.js`
- `backup-node/services/tokenService.js`
- `services/requestSigner.js`
- `services/backupClient.js`
- `services/recoveryManager.js`
- `routes/recovery.js`
- `views/recovery.ejs`
- `views/recovery_status.ejs`

## Main Recovery Routes

- `POST /admin/incidents/:incidentId/start-recovery`
- `GET /recovery/:recoveryId`
- `POST /recovery/:recoveryId/verify`
- `POST /recovery/:recoveryId/complete`
- `POST /recovery/:recoveryId/join-new-room`
- `GET /admin/recovery/:recoveryId/status`

## Backup Recovery Routes

- `POST /backup/recovery/request`
- `GET /backup/recovery/:recoveryId/status`
- `POST /backup/recovery/:recoveryId/verify-user`
- `POST /backup/recovery/:recoveryId/complete`

## WebSocket Recovery Events

- `RECOVERY_STARTED`
- `RECOVERY_REQUIRED`
- `RECOVERY_VERIFIED`
- `RECOVERY_COMPLETED`
- `RECOVERY_FAILED`
- `JOIN_RECOVERED_ROOM`

## Setup

1. Install deps
```bash
cd epsilock-phase1
npm install
```

2. Create env
```bash
cp .env.example .env
```

3. Start MongoDB and set `MONGO_URI`

4. Generate TLS certs
```bash
./scripts/generate-certs.sh
```

5. Seed admin
```bash
npm run seed:admin
```

Admin:
- username: `admin`
- password: `admin123`

6. Run Main + Backup nodes
```bash
npm run start:main
npm run start:backup
```

## Phase 3 Recovery Flow

1. Suspicious activity detected (Phase 2)
2. Room/session frozen, token revoked
3. Admin starts recovery from incident page
4. Main Node sends signed recovery request to Backup Node
5. Backup creates `RecoveryRequest`
6. Affected users open recovery page and re-authenticate on Main Node
7. Main asks Backup to issue single-use recovery token for verified user
8. Admin completes recovery (all users if configured)
9. Backup returns clean new room ID
10. Main creates new room and closes old room
11. Users join new room using verified recovery flow
12. Incident marked recovered/resolved

## Manual Testing (Phase 3)

1. Trigger a Phase 2 incident (e.g. message flood)
2. Confirm room freezes and old room is blocked
3. Open incident detail as admin
4. Click **Start Recovery**
5. Confirm backup request exists via `/admin/recovery/:recoveryId/status`
6. As affected user, open `/recovery/:recoveryId`
7. Re-authenticate with password (on Main Node)
8. As admin, complete recovery
9. User clicks **Join New Secure Room**
10. Confirm old room remains frozen/closed
11. Confirm new room chat works and old messages are not restored

## Hackathon Demo Script

1. User A + User B chat normally
2. Trigger suspicious activity
3. Room freezes and users are blocked
4. Admin sees incident + starts recovery
5. Users verify identity again
6. Admin completes recovery
7. New secure room opens
8. Chat resumes safely in recovered room

