import Joi from "joi";
import { GeneralRules } from "./index.js";

export const sendMessageSchema = {
  body: Joi.object({
    content: Joi.string().required(),
  }),
  params: Joi.object({
    receiverId: GeneralRules.objectId,
  }),
};
