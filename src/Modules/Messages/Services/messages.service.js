import { messagePrivicyEnum } from "../../../Common/Enums/index.js";
import { users, messages } from "../../../DB/Models/index.js";

export const sendMessageServices = async (req, res) => {
  // get message content from body and the user from the params
  const { receiverId } = req.params;
  const { content } = req.body;

  // check if the user is exist and confirmed
  const user = await users.findOne({ _id: receiverId, isConfirmed: true });
  if (!user) {
    return res.status(400).json({ msg: `user not found` });
  }

  // send the message
  messages.create({ content, receiverId });

  res.status(201).json({ msg: `message has been send` });
};

export const publicMessagesService = async (req, res) => {
  // get the user id from params
  const { userId } = req.params;

  // find if the user exist
  const user = await users.findById(userId);
  if (!user) {
    return res.status(404).json({ msg: `user is not found` });
  }

  // get the public messages of this user
  const publicMessage = await messages.find({ status: messagePrivicyEnum.PUBLIC, receiverId: userId }, "-_id content");

  res.status(200).json(publicMessage);
};
