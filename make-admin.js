// Make a user an admin directly in the database (no ADMIN_EMAILS needed).
//
// Usage (in the backend folder, with MONGO_URI in .env):
//   node make-admin.js you@example.com           → make admin
//   node make-admin.js you@example.com --remove  → remove admin
//   node make-admin.js --list                    → list all users and roles

import mongoose from "mongoose";
import dotenv from "dotenv";
import { User } from "./models.js";

dotenv.config();

const [arg, flag] = process.argv.slice(2);
if (!process.env.MONGO_URI) {
  console.error("MONGO_URI is not set. Run this in the backend folder that has your .env file.");
  process.exit(1);
}
if (!arg) {
  console.error("Usage: node make-admin.js you@example.com [--remove]   |   node make-admin.js --list");
  process.exit(1);
}

await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 15000 });

try {
  if (arg === "--list") {
    const users = await User.find().sort({ createdAt: 1 }).lean();
    if (!users.length) console.log("No users yet. Register in the app first.");
    for (const u of users) console.log(`${(u.role || "user").padEnd(6)}  ${u.email}  (${u.name})`);
  } else {
    const email = arg.trim().toLowerCase();
    const user = await User.findOne({ email });
    if (!user) {
      console.error(`No user with email "${email}". Register in the app first, or run with --list to see emails.`);
      process.exitCode = 1;
    } else {
      user.role = flag === "--remove" ? "user" : "admin";
      await user.save();
      console.log(`${user.email} is now: ${user.role}`);
      console.log("Reload the app (or log out and in) to see the Admin panel button.");
    }
  }
} finally {
  await mongoose.disconnect();
}
