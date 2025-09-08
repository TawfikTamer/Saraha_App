import mongoose from "mongoose";

export const dbConnection = async () => {
  try {
    await mongoose.connect(process.env.DATABASE_URL);
    console.log(`DB Connected`);
  } catch {
    console.log(`error Connectin the DB`);
  }
};
