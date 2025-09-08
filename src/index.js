import "./config.js";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import { dbConnection } from "./DB/db.connection.js";
import { userRouter, authRouter, messagesRouter } from "./Modules/controllers.index.js";
import { limit } from "./Middlewares/index.js";
import { startCronJobs } from "./Utils/index.js";

const app = express();
dbConnection();

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

startCronJobs();

app.use(express.json());
app.use("/users/Uploads", express.static("Uploads"));
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

app.use("/users", userRouter, authRouter);
app.use("/messages", messagesRouter);

app.use((req, res) => {
  res.status(404).json({ msg: "Route not found" });
});

app.use((err, req, res, next) => {
  console.log(err);

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
