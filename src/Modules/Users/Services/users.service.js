import mongoose from "mongoose";
import { users, messages } from "../../../DB/Models/index.js";
import fs from "node:fs";

export const updateService = async (req, res) => {
  const {
    user: { _id },
  } = req.loggedData;
  const { firstName, lastName, email, gender } = req.body;

  // check if ths email is already exist
  if (email) {
    const duplicatedUser = await users.findOne({ email });
    if (duplicatedUser._id.toString() != _id.toString()) {
      return res.status(400).json({ msg: `this email is already exist` });
    }
  }

  // update the user
  const updatedUser = await users.findByIdAndUpdate({ _id }, { firstName, lastName, email, gender }, { new: true }).select("firstName lastName email gender -_id");

  res.status(200).json({ msg: `updated successfully`, newData: updatedUser });
};

export const deleteService = async (req, res) => {
  // get the authenticated user
  const {
    user: { _id, profilePic },
  } = req.loggedData;

  // start session
  const session = await mongoose.startSession();
  // send the session to the req to be catch if there is an error
  req.session = session;

  // start Transaction
  session.startTransaction();

  // delete the photo from storage
  if (profilePic) {
    fs.unlinkSync(profilePic);
  }

  // delete the user
  const deletedUser = await users.findByIdAndDelete({ _id }, { session });
  if (!deletedUser) {
    return req.status(400).json({ msh: `user is not Found` });
  }

  //delete the messages of the user
  await messages.deleteMany({ receiverId: _id }, { session });

  // commit the transaction
  await session.commitTransaction();
  // end the session
  session.endSession();

  res.status(200).json({ msg: `user has been deleted` });
};

export const listUsersServices = async (req, res) => {
  // get all users

  const listedUsers = await users.find({ isConfirmed: true }).select("-password -phoneNumber -otps");

  res.status(200).json(listedUsers);
};

export const getProfileDataServices = async (req, res) => {
  // get userId from params
  const { id } = req.params;

  // check if the user is exist and confirmed
  const user = await users.findOne({ _id: id, isConfirmed: true }, "firstName lastName -_id").lean({ virsual: false });

  if (user.length == 0) {
    return res.status(404).json({ msg: `user not found` });
  }

  // return the user
  res.status(200).json(...user);
};

export const getUserMessagesService = async (req, res) => {
  // get the user Id from params
  const { user } = req.loggedData;

  // get the messages of the user
  const userMessages = await messages.find({ receiverId: user._id }, "content status");

  res.status(200).json(userMessages);
};

export const messagePrivacyService = async (req, res) => {
  // get the user data form the token
  const { user } = req.loggedData;
  // get the message id from the params
  const { messageId } = req.params;
  // get the message status from the body
  const { messageState } = req.body;

  // check if this message is for the logged in user
  const message = await messages.findOne({ _id: messageId, receiverId: user._id });
  if (!message) {
    return res.status(400).json({ msg: `no such message for this user` });
  }

  // change the state of the message
  message.status = messageState;
  message.save();

  res.status(200).json({ msg: `message status has been changed to ${messageState}` });
};

export const deleteMessageService = async (req, res) => {
  // get user id from the token
  const { user } = req.loggedData;
  // get the message id from params
  const { messageId } = req.params;

  // check if this message is for the logged in user
  const message = await messages.findOne({ _id: messageId, receiverId: user._id });
  if (!message) {
    return res.status(400).json({ msg: `no such message for this user` });
  }

  // delete the message
  await messages.deleteOne({ _id: messageId });

  res.status(200).json({ msg: `message has been deleted` });
};

export const uploadProfilePictureService = async (req, res) => {
  const { user } = req.loggedData;

  // upload the profile pic
  if (!req.file) {
    return res.status(400).json({ msg: `You must upload a photo` });
  }
  user.profilePic = req.file.path;
  await user.save();

  res.status(200).json({ msg: `Profile pic added successfully`, file: req.file });
};

export const deleteProfilePictureService = async (req, res) => {
  const { user } = req.loggedData;

  if (!user.profilePic) {
    return res.status(400).json({ msg: `there is no profile pic` });
  }
  // delete the photo from storage
  fs.unlinkSync(user.profilePic);

  // delete the photo path from db
  user.profilePic = undefined;
  await user.save();

  res.status(200).json({ msg: `Profile pic deleted successfully` });
};
