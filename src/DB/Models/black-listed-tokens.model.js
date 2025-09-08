import mongoose from "mongoose";

const blackListTokenSchema = mongoose.Schema({
  accsessTokenId: {
    type: String,
    required: true,
    index: { name: "idx_accsessToken" },
  },
  refreshTokenId: {
    type: String,
    required: true,
    index: { name: "idx_refreshToken" },
  },
  expirationDate: {
    type: Date,
    required: true,
  },
});

export const blackListTokens = mongoose.model("Black listed token", blackListTokenSchema);
