import Joi from "joi";
import { GeneralRules } from "./index.js";
import { messagePrivicyEnum, genderEnum } from "../../Common/Enums/index.js";

export const profileDataSchema = {
  params: Joi.object({
    id: GeneralRules.objectId,
  }),
};

export const messgaeStatusSchema = {
  body: Joi.object({
    messageState: Joi.string()
      .valid(...Object.values(messagePrivicyEnum))
      .required(),
  }),
  params: Joi.object({
    messageId: GeneralRules.objectId,
  }),
};

export const updateSchema = {
  body: Joi.object({
    firstName: Joi.string().min(3).max(10),
    lastName: Joi.string().min(3).max(10),
    email: GeneralRules.email,
    gender: Joi.string().valid(...Object.values(genderEnum)),
  }),
};
