import "./config.js";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import { dbConnection } from "./DB/db.connection.js";
import { userRouter, authRouter, messagesRouter } from "./Modules/controllers.index.js";
import { limit } from "./Middlewares/index.js";
import { disconnectDevicesCronJob, revokeTokenCronJob } from "./Utils/index.js";

const app = express();

// connect to the database
dbConnection();

// Handle CORS
const whitelist = process.env.WHITELIST;
const corsOptions = {
  origin: function (origin, callback) {
    if (whitelist.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
};

// start cron jobs
disconnectDevicesCronJob();
revokeTokenCronJob();

// parse the request body
app.use(express.json());

// serve static files
app.use("/users/Uploads", express.static("Uploads"));

// handle the security middlewares [ cors - helmet - rate limiter ]
app.use(
  cors(corsOptions),
  helmet({
    contentSecurityPolicy: {
      directives: {
        "script-src": ["'self'", "'unsafe-inline'"],
      },
    },
  }),
  limit
);

// Handle the controllers
app.use("/users", userRouter, authRouter);
app.use("/messages", messagesRouter);

// Handle in-valid controllers
app.use((req, res) => {
  res.status(404).json({ msg: "Route not found" });
});

// Global error handler
app.use((err, req, res, next) => {
  console.log(err);

  // abort the transaction if it is in progress
  if (req.session?.inTransaction()) {
    req.session.abortTransaction();
    req.session.endSession();
    res.status(500).json({ msg: `transaction has aborted`, error: err });
  }
  res.status(500).json({ msg: `Server Error`, error: err });
});

app.listen(process.env.PORT, () => {
  console.log(`Server connect at port ${process.env.PORT}`);
});
