import mongoose from "mongoose";
import { messagePrivicyEnum } from "../../Common/Enums/index.js";

const messagesSchema = mongoose.Schema(
  {
    content: {
      type: String,
      required: true,
    },
    receiverId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
    },
    status: {
      type: String,
      enmu: Object.values(messagePrivicyEnum),
      default: messagePrivicyEnum.PRIVATE,
    },
  },
  {
    timestamps: true,
  }
);

export const messages = mongoose.model("messages", messagesSchema);
