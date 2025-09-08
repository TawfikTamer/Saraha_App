import mongoose from "mongoose";
import { genderEnum, providerEnum } from "../../Common/Enums/index.js";

const usersSchema = mongoose.Schema(
  {
    firstName: {
      type: String,
      required: true,
      minLength: [3, "Name must be at least 3 characters"],
      maxLength: 10,
    },
    lastName: {
      type: String,
      required: true,
      minLength: [3, "Name must be at least 3 characters"],
      maxLength: 10,
    },
    email: {
      type: String,
      required: true,
      index: { name: "idx_userEmail" },
      unique: true,
    },
    phoneNumber: {
      type: String,
    },
    password: {
      type: String,
      required: true,
    },
    gneder: {
      type: String,
      enum: Object.values(genderEnum),
      default: genderEnum.MALE,
    },
    profilePic: {
      type: String,
    },
    isConfirmed: {
      type: Boolean,
      default: false,
    },
    googleSub: String,
    providers: {
      type: String,
      enum: Object.values(providerEnum),
      default: providerEnum.LOCAL,
    },
  },
  {
    timestamps: true,
    method: {
      getFullName() {
        return this.firstName + this.lastName;
      },
    },
    virtuals: {
      fullName: {
        get() {
          return this.firstName + " " + this.lastName;
        },
      },
    },
    toObject: { virtuals: true },
    toJSON: { virtuals: true },
    id: false,
  }
);

export const users = mongoose.model("users", usersSchema);
