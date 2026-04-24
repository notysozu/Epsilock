const { Schema, model } = require('mongoose');

const incidentSchema = new Schema(
  {
    incidentId: { type: String, required: true, unique: true },
    roomId: { type: String, default: null },
    userId: { type: Schema.Types.ObjectId, ref: 'User', default: null },
    socketId: { type: String, default: null },
    type: { type: String, required: true },
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      required: true
    },
    reason: { type: String, required: true },
    sourceIp: { type: String, default: null },
    sourceGeo: {
      country: { type: String, default: null },
      region: { type: String, default: null },
      city: { type: String, default: null },
      latitude: { type: Number, default: null },
      longitude: { type: Number, default: null },
      isp: { type: String, default: null },
      org: { type: String, default: null }
    },
    userAgent: { type: String, default: null },
    origin: { type: String, default: null },
    actionTaken: { type: String, required: true },
    recoveryId: { type: String, default: null },
    recoveryStatus: {
      type: String,
      enum: ['not_started', 'pending', 'verified', 'completed', 'failed'],
      default: 'not_started'
    },
    resolvedByRecovery: { type: Boolean, default: false },
    status: {
      type: String,
      enum: ['open', 'reviewed', 'resolved'],
      default: 'open'
    },
    createdAt: { type: Date, default: Date.now },
    resolvedAt: { type: Date, default: null }
  },
  { timestamps: false }
);

module.exports = model('Incident', incidentSchema);
