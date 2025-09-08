import { userOTPs } from "../DB/Models/index.js";

export const deleteOTP = async (user) => {
  await userOTPs.deleteOne({ userId: user._id });
};
