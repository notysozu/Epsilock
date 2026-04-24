const { Schema, model } = require('mongoose');

const sessionSchema = new Schema(
  {
    sessionId: { type: String, required: true, unique: true },
    roomId: { type: String, required: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    socketId: { type: String, required: true },
    connectedAt: { type: Date, required: true },
    disconnectedAt: { type: Date, default: null },
    lastActivityAt: { type: Date, required: true },
    status: { type: String, enum: ['online', 'offline'], default: 'online' },
    suspicious: { type: Boolean, default: false },
    frozen: { type: Boolean, default: false },
    revokedAt: { type: Date, default: null },
    disconnectReason: { type: String, default: null },
    lastSecurityEventAt: { type: Date, default: null }
  },
  { timestamps: false }
);

module.exports = model('SessionLog', sessionSchema);
