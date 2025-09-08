import cron from "node-cron";
import { blackListTokens, connectedDevices, users } from "../DB/Models/index.js";

export const revokeTokenCronJob = async () => {
  if (process.env.RUN_REVOKE_TOKEN_CRON_JOB == "ON") {
    console.log(`The revoke token cron Job is running`);

    // check every 24 hours if there are any revoked token that has been expired
    cron.schedule("* */24 * * *", async () => {
      await blackListTokens.deleteMany({ expirationDate: { $lt: Date.now() } });
    });
  } else console.log(`The revoke token cron Job is STOPPED`);
};

export const disconnectDevicesCronJob = async () => {
  if (process.env.RUN_DISCONNECT_CRON_JOB == "ON") {
    console.log(`The disconnect cron job is running`);

    // check every 10 min to disconnect the devices with expired token
    cron.schedule("*/10 * * * *", async () => {
      // get the users that are alredy connect their devices
      const loggedInUsers = await connectedDevices.find({ devices: { $exists: true, $ne: [] } });

      // loop on each user
      for (const user of loggedInUsers) {
        const originalLength = user.devices.length;
        user.devices = user.devices.filter((device) => new Date(device.exp) > new Date());

        // check if the user already had and expired token, to not wait for saving every user
        if (user.devices.length < originalLength) {
          if (user.devices.length == 0) {
            // to delete the field
            user.devices = undefined;
          }
          await user.save();
        }
      }
    });
  } else console.log(`The disconnect cron job is STOPPED`);
};
