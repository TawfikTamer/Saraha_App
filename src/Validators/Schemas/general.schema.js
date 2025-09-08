import Joi from "joi";
import { isValidObjectId } from "mongoose";

export const objectIdRule = (val, helper) => (isValidObjectId(val) ? true : helper.message("Invalid object id"));

export const GeneralRules = {
  email: Joi.string().email(),
  password: Joi.string()
    .required()
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*])[A-Za-z\d@$!%*]{8,}$/),
  objectId: Joi.custom(objectIdRule),
};
