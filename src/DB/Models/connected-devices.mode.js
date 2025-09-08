import mongoose from "mongoose";

const connectedDevicesSchema = mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "users",
  },
  jti: { type: String, required: true },
  exp: { type: Date, required: true },
});

export const connectedDevices = mongoose.model("connectedDevices", connectedDevicesSchema);
