import { Router } from "express";
import * as services from "../Services/users.service.js";
import { authenticationMiddleware, localUpload, validationMiddleware } from "../../../Middlewares/index.js";
import { messgaeStatusSchema, updateSchema, profileDataSchema } from "../../../Validators/Schemas/index.js";

const userRouter = Router();

userRouter.patch("/message-privacy/:messageId", authenticationMiddleware, validationMiddleware(messgaeStatusSchema), services.messagePrivacyService);

userRouter.put("/update", authenticationMiddleware, validationMiddleware(updateSchema), services.updateService);

userRouter.patch(
  "/Upload-Profile-Picture",
  authenticationMiddleware,
  localUpload({ path: `Profile-Pic`, limits: { files: 1, fileSize: 1024 * 1024 } }).single("avatar"),
  services.uploadProfilePictureService
);

userRouter.delete("/delete-user", authenticationMiddleware, services.deleteService);
userRouter.delete("/delete-message/:messageId", authenticationMiddleware, services.deleteMessageService);
userRouter.delete("/Delete-Profile-Picture", authenticationMiddleware, services.deleteProfilePictureService);

userRouter.get("/list-users", services.listUsersServices);
userRouter.get("/user-data/:id", validationMiddleware(profileDataSchema), services.getProfileDataServices);
userRouter.get("/user-messages", authenticationMiddleware, services.getUserMessagesService);

export { userRouter };
