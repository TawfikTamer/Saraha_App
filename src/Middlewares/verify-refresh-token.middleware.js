import { verifyToken } from "../Utils/index.js";
import { blackListTokens } from "../DB/Models/index.js";

export const verifyRefreshTokenMiddleware = async (req, res, next) => {
  // get the token from the header
  const { refreshtoken } = req.headers;
  // get the accsess token from the auth middleware
  req.loggedData = req.loggedData || {}; // incase we send only this middleware
  const { tokenData } = req.loggedData;

  // check if the token is not send
  if (!refreshtoken) {
    return res.status(400).json({ msg: `insert A refresh token` });
  }

  // verify the token
  let refreshTokenData;

  refreshTokenData = verifyToken(refreshtoken, process.env.JWT_REFRESH_KEY);
  if (!refreshTokenData.jti) {
    return res.status(400).json({ msg: `invalid refresh token` });
  }

  // check if the token is not revoked
  const revokedToken = await blackListTokens.findOne({ refreshTokenId: refreshTokenData.jti });
  if (revokedToken) {
    return res.status(400).json({ msg: `token is revoked` });
  }

  // check if the access and refresh token belongs to the same user
  if (tokenData) {
    if (refreshTokenData.jti != tokenData.refreshTokenId) return res.status(400).json({ msg: `access and refresh tokens does not match for the same user` });
  }

  req.loggedData.refreshTokenData = refreshTokenData;

  next();
};
