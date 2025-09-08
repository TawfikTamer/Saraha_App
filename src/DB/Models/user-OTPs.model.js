import mongoose from "mongoose";

const userOTPsSchema = mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "users",
  },
  confirm: {
    type: String,
  },
  recovery: {
    type: String,
  },
  expiration: {
    type: Date,
  },
  attemptNumber: {
    type: Number,
  },
  lastEmailAttempt: {
    type: Date,
  },
});

export const userOTPs = mongoose.model("userOTPs", userOTPsSchema);
