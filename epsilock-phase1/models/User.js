const { Schema, model } = require('mongoose');

const userSchema = new Schema(
  {
    username: { type: String, required: true, unique: true, trim: true, minlength: 3 },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user'], default: 'user' },
    tokenVersion: { type: Number, default: 0 },
    requirePasswordReset: { type: Boolean, default: false },
    blocked: { type: Boolean, default: false },
    blockedUntil: { type: Date, default: null },
    blockReason: { type: String, default: null }
  },
  {
    timestamps: { createdAt: true, updatedAt: false }
  }
);

module.exports = model('User', userSchema);
