const { Schema, model } = require('mongoose');

const roomSchema = new Schema(
  {
    roomId: { type: String, required: true, unique: true },
    name: { type: String, required: true, trim: true },
    createdByAdminId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    participantUserIds: [{ type: Schema.Types.ObjectId, ref: 'User' }],
    status: { type: String, enum: ['active', 'closed'], default: 'active' },
    frozen: { type: Boolean, default: false },
    frozenReason: { type: String, default: null },
    frozenAt: { type: Date, default: null },
    frozenBy: { type: String, default: null },
    replacedByRoomId: { type: String, default: null },
    recoveredFromRoomId: { type: String, default: null },
    recoveryStatus: {
      type: String,
      enum: ['none', 'required', 'in_progress', 'completed', 'failed'],
      default: 'none'
    }
  },
  {
    timestamps: true
  }
);

module.exports = model('Room', roomSchema);
