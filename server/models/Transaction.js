const mongoose = require("mongoose");

const transactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  type: {
    type: String,
    enum: ["deposit", "withdrawal", "transfer", "payment"],
    required: true
  },
  amount: {
    type: Number,
    required: true,
    min: 0
  },
  status: {
    type: String,
    enum: ["pending", "completed", "failed", "cancelled"],
    default: "pending",
    required: true
  },
  reference: {
    type: String,
    required: true,
    unique: true
  },
  description: String,
  recipientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },
  recipientPhone: String,
  paymentGateway: String,
  gatewayReference: String,
  fee: { type: Number, default: 0 },
  netAmount: Number,
  failureReason: String,
  metadata: mongoose.Schema.Types.Mixed
}, { timestamps: true });

// Indexes for performance
transactionSchema.index({ userId: 1, createdAt: -1 });
transactionSchema.index({ reference: 1 });
transactionSchema.index({ status: 1 });
transactionSchema.index({ paymentGateway: 1 });

module.exports = mongoose.model("Transaction", transactionSchema);