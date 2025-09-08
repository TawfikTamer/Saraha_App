import { Router } from "express";
import * as services from "../Services/auth.service.js";
import { authenticationMiddleware, validationMiddleware, verifyRefreshTokenMiddleware } from "../../../Middlewares/index.js";
import { registerationSchema, loginSchema, forgetPasswordSchema, confirmSchema, resetPasswordSchema, updatePasswordSchema } from "../../../Validators/Schemas/index.js";

const authRouter = Router();

authRouter.post("/register", validationMiddleware(registerationSchema), services.registerServices);
authRouter.post("/auth-gmail", services.gmailAuthService);
authRouter.post("/login", validationMiddleware(loginSchema), services.loginService);
authRouter.post("/logout", authenticationMiddleware, verifyRefreshTokenMiddleware, services.logoutService);
authRouter.post("/forget-Password", validationMiddleware(forgetPasswordSchema), services.forgetPasswordService);
authRouter.post("/refresh-token", verifyRefreshTokenMiddleware, services.refreshTokenServices);
authRouter.post("/resend-email", authenticationMiddleware, services.resendEmailService);

authRouter.patch("/confirm", authenticationMiddleware, validationMiddleware(confirmSchema), services.confirmService);
authRouter.patch("/Reset-Password", authenticationMiddleware, validationMiddleware(resetPasswordSchema), services.resetPasswordService);
authRouter.patch("/update-password", authenticationMiddleware, verifyRefreshTokenMiddleware, validationMiddleware(updatePasswordSchema), services.updatePasswordServices);

export { authRouter };
