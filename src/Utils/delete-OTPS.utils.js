import { userOTPs } from "../DB/Models/index.js";

export const deleteOTP = async (user) => {
  await userOTPs.delete({ userId: user._id });
};
