import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { User, Sale, Purchase, PRODUCTS } from "./models.js";

dotenv.config();

/* =========================== CONFIG =========================== */
// Secrets come ONLY from environment variables (.env locally, Render → Environment in production).
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 5000;
// Comma-separated list, e.g. "https://my-site.netlify.app,http://localhost:5173"
const FRONTEND_URL = process.env.FRONTEND_URL || "";
// Comma-separated emails that are always admins, e.g. "owner@gmail.com"
// (quotes and spaces are ignored, so ADMIN_EMAILS="a@x.com, b@y.com" also works)
// Main admin login for the "Admin" tab on the login screen.
// Set both on the server (Render → Environment). No need to register first.
const clean = (v) => String(v || "").replace(/^["'\s]+|["'\s]+$/g, "");
const ADMIN_EMAIL = clean(process.env.ADMIN_EMAIL).toLowerCase();
const ADMIN_PASSWORD = clean(process.env.ADMIN_PASSWORD);

const ADMIN_EMAILS = [
  ...(process.env.ADMIN_EMAILS || "").replace(/["']/g, "").split(/[,;\s]+/),
  ADMIN_EMAIL,
]
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

if (!MONGO_URI || !JWT_SECRET) {
  console.error("Missing env vars: MONGO_URI and JWT_SECRET must both be set.");
  process.exit(1);
}

const app = express();
app.use(express.json());

/* =========================== CORS =========================== */
const allowed = FRONTEND_URL.split(",")
  .map((s) => s.trim().replace(/\/$/, ""))
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      // no Origin (curl, server-to-server, Netlify proxy) or no list set = allow
      // also always allow any *.netlify.app site and localhost, so a typo in FRONTEND_URL can't block login.
      // (Safe: login uses a Bearer token, not cookies.)
      const ok =
        !origin ||
        allowed.length === 0 ||
        allowed.includes(origin) ||
        /^https:\/\/[a-z0-9-]+\.netlify\.app$/i.test(origin) ||
        /^http:\/\/localhost(:\d+)?$/.test(origin);
      if (!ok) console.warn(`CORS blocked "${origin}". Add it to FRONTEND_URL.`);
      cb(null, ok);
    },
  })
);

// wraps async routes so any error is returned as JSON instead of an empty response
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.get("/", (_req, res) => res.json({ ok: true, service: "token-tracker-server" }));
app.get("/api/health", (_req, res) =>
  res.json({
    ok: true,
    db: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    adminFeature: true, // if this is missing, the new server.js is not deployed yet
    adminEmailsSet: ADMIN_EMAILS.length, // 0 = no admin email set on this server
    adminLoginReady: Boolean(ADMIN_EMAIL && ADMIN_PASSWORD), // false = set ADMIN_EMAIL + ADMIN_PASSWORD
  })
);

/* =========================== AUTH =========================== */
const makeToken = (user) => jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
const isAdmin = (u) => u.role === "admin" || ADMIN_EMAILS.includes(String(u.email).toLowerCase());
const publicUser = (u) => ({ id: u._id, name: u.name, email: u.email, isAdmin: isAdmin(u) });

// Code needed to create an ADMIN account from the sign-up page.
// Uses ADMIN_SIGNUP_CODE, or ADMIN_PASSWORD if that is not set.
const ADMIN_SIGNUP_CODE = clean(process.env.ADMIN_SIGNUP_CODE) || ADMIN_PASSWORD;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

app.post("/api/auth/register", wrap(async (req, res) => {
  const { name, email, password, role = "user", adminCode } = req.body || {};
  if (!name?.trim() || !email?.trim() || !password)
    return res.status(400).json({ error: "Name, email and password are required" });
  if (!EMAIL_RE.test(email.trim()))
    return res.status(400).json({ error: "Enter a valid email address (e.g. name@gmail.com)" });
  if (password.length < 6)
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  if (!["user", "admin"].includes(role))
    return res.status(400).json({ error: "Choose Sales executive or Admin" });

  // Admin accounts need the secret admin code
  if (role === "admin") {
    if (!ADMIN_SIGNUP_CODE)
      return res.status(403).json({ error: "Admin sign-up is turned off. Ask the owner to set ADMIN_SIGNUP_CODE." });
    if (!adminCode || !sameSecret(adminCode, ADMIN_SIGNUP_CODE))
      return res.status(403).json({ error: "Wrong admin code" });
  }

  const cleanEmail = email.toLowerCase().trim();
  const exists = await User.findOne({ email: cleanEmail });
  if (exists) return res.status(400).json({ error: "An account with this email already exists" });

  const user = await User.create({
    name: name.trim(),
    email: cleanEmail,
    passwordHash: await bcrypt.hash(password, 10),
    role,
  });
  res.status(201).json({ token: makeToken(user), user: publicUser(user) });
}));

app.post("/api/auth/login", wrap(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email and password are required" });

  const user = await User.findOne({ email: email.toLowerCase().trim() });
  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: "Invalid email or password" });

  res.json({ token: makeToken(user), user: publicUser(user) });
}));

// Admin tab on the login screen
const sameSecret = (a, b) => {
  const x = crypto.createHash("sha256").update(String(a)).digest();
  const y = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
};

app.post("/api/auth/admin-login", wrap(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email and password are required" });
  const cleanEmail = email.toLowerCase().trim();

  // 1) Main admin from ADMIN_EMAIL + ADMIN_PASSWORD (account is created automatically)
  if (ADMIN_EMAIL && ADMIN_PASSWORD && cleanEmail === ADMIN_EMAIL) {
    if (!sameSecret(password, ADMIN_PASSWORD))
      return res.status(401).json({ error: "Invalid admin email or password" });

    let user = await User.findOne({ email: ADMIN_EMAIL });
    if (!user) {
      user = await User.create({
        name: "Admin",
        email: ADMIN_EMAIL,
        passwordHash: await bcrypt.hash(ADMIN_PASSWORD, 10),
        role: "admin",
      });
    } else if (user.role !== "admin") {
      user.role = "admin";
      await user.save();
    }
    return res.json({ token: makeToken(user), user: publicUser(user) });
  }

  // 2) Any other admin account (made admin from the Admin panel) with its own password
  const user = await User.findOne({ email: cleanEmail });
  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: "Invalid admin email or password" });
  if (!isAdmin(user)) return res.status(403).json({ error: "This account is not an admin" });

  res.json({ token: makeToken(user), user: publicUser(user) });
}));

// protect everything below
const auth = wrap(async (req, res, next) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Please log in" });

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: "Session expired, please log in again" });
  }
  const user = await User.findById(payload.id);
  if (!user) return res.status(401).json({ error: "Please log in" });
  req.user = user;
  next();
});

app.get("/api/auth/me", auth, (req, res) => res.json({ user: publicUser(req.user) }));

// admins only (use after `auth`)
const adminOnly = (req, res, next) => {
  if (!isAdmin(req.user)) return res.status(403).json({ error: "Admins only" });
  next();
};

/* =========================== HELPERS =========================== */
async function stockByProduct(userId) {
  const match = { $match: { user: new mongoose.Types.ObjectId(userId) } };
  const [bought, sold] = await Promise.all([
    Purchase.aggregate([match, { $group: { _id: "$product", qty: { $sum: "$quantity" }, cost: { $sum: "$amount" } } }]),
    Sale.aggregate([match, { $group: { _id: "$product", qty: { $sum: "$quantity" }, revenue: { $sum: "$amount" } } }]),
  ]);
  return PRODUCTS.map((p) => {
    const b = bought.find((x) => x._id === p) || { qty: 0, cost: 0 };
    const s = sold.find((x) => x._id === p) || { qty: 0, revenue: 0 };
    return {
      product: p,
      boughtQty: b.qty,
      soldQty: s.qty,
      inStock: b.qty - s.qty,
      stockCost: b.cost,
      sales: s.revenue,
    };
  });
}

const stockOf = async (userId, product) =>
  (await stockByProduct(userId)).find((s) => s.product === product);

function readEntry(body, priceField) {
  const quantity = Number(body.quantity);
  const price = Number(body[priceField]);
  if (!body.date || Number.isNaN(new Date(body.date).getTime())) return { error: "Enter a valid date" };
  if (!Number.isInteger(quantity) || quantity < 1) return { error: "Quantity must be at least 1" };
  if (!PRODUCTS.includes(body.product)) return { error: "Select a valid token / product" };
  if (body[priceField] === "" || body[priceField] == null || !(price >= 0))
    return { error: "Enter a valid price" };
  return { quantity, price, amount: quantity * price };
}

const badId = (id) => !mongoose.isValidObjectId(id);

/* =========================== SALES =========================== */
app.get("/api/sales", auth, wrap(async (req, res) => {
  res.json(await Sale.find({ user: req.user._id }).sort({ date: -1, createdAt: -1 }));
}));

app.post("/api/sales", auth, wrap(async (req, res) => {
  const body = req.body || {};
  const e = readEntry(body, "sellingPrice");
  if (e.error) return res.status(400).json({ error: e.error });

  const stock = await stockOf(req.user._id, body.product);
  if (e.quantity > stock.inStock)
    return res.status(400).json({ error: `Only ${stock.inStock} × ${body.product} in stock` });

  const sale = await Sale.create({
    user: req.user._id,
    date: body.date,
    quantity: e.quantity,
    product: body.product,
    sellingPrice: e.price,
    customerName: (body.customerName || "").trim(),
    amount: e.amount,
  });
  res.status(201).json(sale);
}));

// EDIT a sale
app.put("/api/sales/:id", auth, wrap(async (req, res) => {
  if (badId(req.params.id)) return res.status(404).json({ error: "Sale not found" });
  const body = req.body || {};
  const e = readEntry(body, "sellingPrice");
  if (e.error) return res.status(400).json({ error: e.error });

  const sale = await Sale.findOne({ _id: req.params.id, user: req.user._id });
  if (!sale) return res.status(404).json({ error: "Sale not found" });

  // This sale's own quantity is already counted as sold, so add it back
  // when the product stays the same.
  const stock = await stockOf(req.user._id, body.product);
  const available = stock.inStock + (sale.product === body.product ? sale.quantity : 0);
  if (e.quantity > available)
    return res.status(400).json({ error: `Only ${available} × ${body.product} in stock` });

  sale.date = body.date;
  sale.quantity = e.quantity;
  sale.product = body.product;
  sale.sellingPrice = e.price;
  sale.customerName = (body.customerName || "").trim();
  sale.amount = e.amount;
  await sale.save();
  res.json(sale);
}));

app.delete("/api/sales/:id", auth, wrap(async (req, res) => {
  if (badId(req.params.id)) return res.status(404).json({ error: "Sale not found" });
  await Sale.deleteOne({ _id: req.params.id, user: req.user._id });
  res.json({ ok: true });
}));

/* =========================== STOCK PURCHASES =========================== */
app.get("/api/purchases", auth, wrap(async (req, res) => {
  res.json(await Purchase.find({ user: req.user._id }).sort({ date: -1, createdAt: -1 }));
}));

app.post("/api/purchases", auth, wrap(async (req, res) => {
  const body = req.body || {};
  const e = readEntry(body, "costPrice");
  if (e.error) return res.status(400).json({ error: e.error });

  const purchase = await Purchase.create({
    user: req.user._id,
    date: body.date,
    quantity: e.quantity,
    product: body.product,
    costPrice: e.price,
    supplierName: (body.supplierName || "").trim(),
    amount: e.amount,
  });
  res.status(201).json(purchase);
}));

// EDIT a stock purchase
app.put("/api/purchases/:id", auth, wrap(async (req, res) => {
  if (badId(req.params.id)) return res.status(404).json({ error: "Purchase not found" });
  const body = req.body || {};
  const e = readEntry(body, "costPrice");
  if (e.error) return res.status(400).json({ error: e.error });

  const p = await Purchase.findOne({ _id: req.params.id, user: req.user._id });
  if (!p) return res.status(404).json({ error: "Purchase not found" });

  // Stock of the ORIGINAL product must not go below zero after the change
  // (i.e. you can't reduce/move tokens that are already sold).
  const oldStock = await stockOf(req.user._id, p.product);
  const removed = p.product === body.product ? p.quantity - e.quantity : p.quantity;
  if (oldStock.inStock - removed < 0) {
    const minQty = p.quantity - oldStock.inStock;
    return res.status(400).json({
      error:
        p.product === body.product
          ? `Can't reduce below ${minQty}: those tokens are already sold`
          : `Can't change product: some ${p.product} from this purchase are already sold`,
    });
  }

  p.date = body.date;
  p.quantity = e.quantity;
  p.product = body.product;
  p.costPrice = e.price;
  p.supplierName = (body.supplierName || "").trim();
  p.amount = e.amount;
  await p.save();
  res.json(p);
}));

app.delete("/api/purchases/:id", auth, wrap(async (req, res) => {
  if (badId(req.params.id)) return res.status(404).json({ error: "Purchase not found" });
  const p = await Purchase.findOne({ _id: req.params.id, user: req.user._id });
  if (!p) return res.json({ ok: true });

  const stock = await stockOf(req.user._id, p.product);
  if (stock.inStock - p.quantity < 0)
    return res.status(400).json({ error: "Can't delete: some of these tokens are already sold" });

  await p.deleteOne();
  res.json({ ok: true });
}));

/* =========================== SUMMARY =========================== */
async function buildSummary(userId) {
  const products = await stockByProduct(userId);
  const sum = (k) => products.reduce((a, p) => a + p[k], 0);
  const totalSales = sum("sales");
  const stockCost = sum("stockCost");
  return {
    totalSales,
    soldQty: sum("soldQty"),
    stockCost,
    boughtQty: sum("boughtQty"),
    profit: totalSales - stockCost, // sales minus stock cost
    tokensInStock: sum("inStock"),
    products,
  };
}

app.get("/api/summary", auth, wrap(async (req, res) => {
  res.json(await buildSummary(req.user._id));
}));

/* =========================== ADMIN =========================== */
const groupByUser = (Model) =>
  Model.aggregate([
    {
      $group: {
        _id: "$user",
        qty: { $sum: "$quantity" },
        amount: { $sum: "$amount" },
        count: { $sum: 1 },
        last: { $max: "$date" },
      },
    },
  ]);

// Totals across all users + one row per user
app.get("/api/admin/users", auth, adminOnly, wrap(async (_req, res) => {
  const [users, sold, bought] = await Promise.all([
    User.find().sort({ createdAt: -1 }).lean(),
    groupByUser(Sale),
    groupByUser(Purchase),
  ]);
  const byId = (rows) => Object.fromEntries(rows.map((r) => [String(r._id), r]));
  const s = byId(sold);
  const b = byId(bought);
  const empty = { qty: 0, amount: 0, count: 0, last: null };

  const rows = users.map((u) => {
    const us = s[String(u._id)] || empty;
    const ub = b[String(u._id)] || empty;
    const lastActive = [us.last, ub.last].filter(Boolean).sort().pop() || null;
    return {
      id: u._id,
      name: u.name,
      email: u.email,
      isAdmin: isAdmin(u),
      fixedAdmin: ADMIN_EMAILS.includes(u.email), // set via ADMIN_EMAILS, can't be removed in the app
      createdAt: u.createdAt,
      lastActive,
      entries: us.count + ub.count,
      totalSales: us.amount,
      soldQty: us.qty,
      stockCost: ub.amount,
      boughtQty: ub.qty,
      profit: us.amount - ub.amount,
      tokensInStock: ub.qty - us.qty,
    };
  });

  const total = (k) => rows.reduce((a, r) => a + r[k], 0);
  res.json({
    stats: {
      users: rows.length,
      admins: rows.filter((r) => r.isAdmin).length,
      totalSales: total("totalSales"),
      stockCost: total("stockCost"),
      profit: total("profit"),
      tokensInStock: total("tokensInStock"),
      soldQty: total("soldQty"),
      boughtQty: total("boughtQty"),
    },
    users: rows,
  });
}));

// One user's full data
app.get("/api/admin/users/:id", auth, adminOnly, wrap(async (req, res) => {
  if (badId(req.params.id)) return res.status(404).json({ error: "User not found" });
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });

  const [summary, sales, purchases] = await Promise.all([
    buildSummary(user._id),
    Sale.find({ user: user._id }).sort({ date: -1, createdAt: -1 }),
    Purchase.find({ user: user._id }).sort({ date: -1, createdAt: -1 }),
  ]);
  res.json({ user: { ...publicUser(user), createdAt: user.createdAt }, summary, sales, purchases });
}));

// Make admin / remove admin
app.put("/api/admin/users/:id/role", auth, adminOnly, wrap(async (req, res) => {
  if (badId(req.params.id)) return res.status(404).json({ error: "User not found" });
  const role = req.body?.role;
  if (!["user", "admin"].includes(role)) return res.status(400).json({ error: "Role must be 'user' or 'admin'" });
  if (String(req.params.id) === String(req.user._id))
    return res.status(400).json({ error: "You can't change your own role" });

  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  if (role === "user" && ADMIN_EMAILS.includes(user.email))
    return res.status(400).json({ error: "This admin is set in ADMIN_EMAILS on the server and can't be removed here" });

  user.role = role;
  await user.save();
  res.json({ user: publicUser(user) });
}));

// Delete a user and all their entries
app.delete("/api/admin/users/:id", auth, adminOnly, wrap(async (req, res) => {
  if (badId(req.params.id)) return res.status(404).json({ error: "User not found" });
  if (String(req.params.id) === String(req.user._id))
    return res.status(400).json({ error: "You can't delete your own account" });

  const user = await User.findById(req.params.id);
  if (!user) return res.json({ ok: true });
  if (ADMIN_EMAILS.includes(user.email))
    return res.status(400).json({ error: "This admin is set in ADMIN_EMAILS on the server and can't be deleted here" });

  await Promise.all([Sale.deleteMany({ user: user._id }), Purchase.deleteMany({ user: user._id })]);
  await user.deleteOne();
  res.json({ ok: true });
}));

app.get("/api/products", (_req, res) => res.json(PRODUCTS));

/* =========================== ERRORS =========================== */
app.use("/api", (_req, res) => res.status(404).json({ error: "API route not found" }));
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: err.message || "Server error" });
});

/* =========================== START =========================== */
console.log("Allowed frontend origins:", allowed.length ? allowed.join(", ") : "ALL");
console.log("Admin emails:", ADMIN_EMAILS.length ? ADMIN_EMAILS.join(", ") : "none (set ADMIN_EMAIL)");
console.log("Admin login tab:", ADMIN_EMAIL && ADMIN_PASSWORD ? "ready" : "not set (set ADMIN_EMAIL and ADMIN_PASSWORD)");

mongoose
  .connect(MONGO_URI, { serverSelectionTimeoutMS: 15000 })
  .then(() => {
    console.log("MongoDB connected");
    app.listen(PORT, () => console.log(`API running on port ${PORT}`));
  })
  .catch((err) => {
    console.error(
      "MongoDB connection error:", err.message,
      "\n→ Check MONGO_URI (user/password) and Atlas → Network Access (allow 0.0.0.0/0)."
    );
    process.exit(1);
  });
