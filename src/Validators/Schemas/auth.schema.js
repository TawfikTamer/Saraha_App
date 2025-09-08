import Joi from "joi";
import { GeneralRules } from "./index.js";
import { genderEnum } from "../../Common/Enums/index.js";

export const registerationSchema = {
  body: Joi.object({
    firstName: Joi.string().required().min(3).max(10),
    lastName: Joi.string().required().min(3).max(10),
    email: GeneralRules.email.required(),
    phoneNumber: Joi.string().required(),
    password: GeneralRules.password,
    gender: Joi.string().valid(...Object.values(genderEnum)),
  }),
};

export const confirmSchema = {
  body: Joi.object({
    otp: Joi.number(),
  }),
};

export const loginSchema = {
  body: Joi.object({
    email: GeneralRules.email,
    password: GeneralRules.password,
  }),
};

export const forgetPasswordSchema = {
  body: Joi.object({
    email: GeneralRules.email,
  }),
};

export const resetPasswordSchema = {
  body: Joi.object({
    newPassword: GeneralRules.password,
    otp: Joi.number(),
  }),
};

export const updatePasswordSchema = {
  body: Joi.object({
    currentPassword: GeneralRules.password,
    newPassword: GeneralRules.password,
    confirmPassword: Joi.string().valid(Joi.ref("newPassword")).required().messages({ "any.only": "Passwords must match" }),
  }),
};
