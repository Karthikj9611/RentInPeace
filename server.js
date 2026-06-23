require('dotenv').config();
// Required .env variables:
// MONGODB_URI        - MongoDB Atlas connection string
// ADMIN_API_KEY      - Strong random secret for admin API access
// BREVO_API_KEY      - Brevo (Sendinblue) email API key
// RAZORPAY_KEY_ID    - Razorpay key ID
// RAZORPAY_KEY_SECRET- Razorpay key secret
// ALLOWED_ORIGIN     - Frontend URL for CORS (e.g. https://yourdomain.com). REQUIRED in production.
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const path = require("path");
const crypto = require("crypto");
const Razorpay = require("razorpay");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const sharp  = require("sharp");
const compression = require("compression");

// ── Fail loudly if critical env vars are missing ──
if (!process.env.MONGODB_URI)    throw new Error("MONGODB_URI env var is required");
if (!process.env.ADMIN_API_KEY)  throw new Error("ADMIN_API_KEY env var is required");
if (!process.env.ALLOWED_ORIGIN) {
  if (process.env.NODE_ENV === 'production') throw new Error("ALLOWED_ORIGIN env var is required in production");
  console.warn("⚠️  ALLOWED_ORIGIN not set — defaulting to * (development only)");
}

const app = express();
app.use(compression());
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
// Reduced body limit — images should be stored externally (S3/R2), not as base64 in MongoDB.
// Raise this limit only if you are still migrating to external image storage.
app.use(express.json({ limit: '2mb' }));
app.use(express.static("public", { maxAge: '7d', etag: true }));

// ── RATE LIMITERS ──
const otpLimiter      = rateLimit({ windowMs: 15*60*1000, max: 5,   standardHeaders: true, legacyHeaders: false, message: { success: false, message: "Too many OTP requests. Please wait 15 minutes and try again." } });
const verifyOtpLimiter= rateLimit({ windowMs: 15*60*1000, max: 10,  standardHeaders: true, legacyHeaders: false, message: { success: false, message: "Too many OTP attempts. Please wait 15 minutes." } });
const loginLimiter    = rateLimit({ windowMs: 15*60*1000, max: 10,  standardHeaders: true, legacyHeaders: false, message: { message: "Too many login attempts. Please wait 15 minutes and try again." } });
const registerLimiter = rateLimit({ windowMs: 60*60*1000, max: 10,  standardHeaders: true, legacyHeaders: false, message: { message: "Too many registrations from this IP. Please try again later." } });
const reviewLimiter   = rateLimit({ windowMs: 60*60*1000, max: 5,   standardHeaders: true, legacyHeaders: false, message: { message: "Too many review submissions. Please try again later." } });
const siteVisitLimiter= rateLimit({ windowMs: 60*1000,   max: 10,  standardHeaders: true, legacyHeaders: false, message: { success: false } });
const paymentLimiter  = rateLimit({ windowMs: 60*60*1000, max: 20,  standardHeaders: true, legacyHeaders: false, message: { message: "Too many payment requests. Please try again later." } });
const heatmapLimiter  = rateLimit({ windowMs: 60*1000,   max: 120, standardHeaders: true, legacyHeaders: false, message: { ok: false } });

// ── IMAGE UPLOAD ──
// Images are received as multipart/form-data, compressed with sharp, saved as WebP,
// and served from /public/uploads/. The returned URL is stored in Property.images[].

const UPLOAD_DIR = path.join(__dirname, "public", "uploads");
// Ensure the upload directory exists at startup
const fs = require("fs");
// sync is fine here — runs once at startup before any requests are served
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// multer keeps files in memory so sharp can process them without touching the disk twice
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20 MB raw upload cap
  fileFilter(req, file, cb) {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Only image files are allowed"), false);
    }
    cb(null, true);
  }
});

const imageUploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Too many upload requests. Please wait a minute." }
});

// ── Shared image processing helper ──
async function processAndSaveImage(buffer) {
  const filename = `${Date.now()}-${crypto.randomBytes(8).toString("hex")}.webp`;
  const outPath  = path.join(UPLOAD_DIR, filename);
  await sharp(buffer)
    .rotate()                       // auto-orient from EXIF
    .resize({
      width: 1600,
      height: 1200,
      fit: "inside",
      withoutEnlargement: true      // never upscale small images
    })
    .webp({ quality: 78 })          // ~78 q is a good size/quality balance
    .toFile(outPath);
  return `/uploads/${filename}`;
}

// POST /api/upload-image
// Auth: userAuth (any logged-in user) — admin routes pass the admin key separately
// Body: multipart/form-data, field name "image" (single file)
// Returns: { success: true, url: "/uploads/<filename>.webp" }
app.post(
  "/api/upload-image",
  imageUploadLimiter,
  userAuth,
  upload.single("image"),
  async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ success: false, message: "No image file provided." });
      const url = await processAndSaveImage(req.file.buffer);
      res.json({ success: true, url });
    } catch (err) {
      console.error("Image upload error:", err);
      res.status(500).json({ success: false, message: "Image processing failed." });
    }
  }
);

// POST /api/upload-image/admin — same as above but authenticated by admin key
// Lets the admin panel upload images without needing a user session token
app.post(
  "/api/upload-image/admin",
  imageUploadLimiter,
  adminAuth,
  upload.single("image"),
  async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ success: false, message: "No image file provided." });
      const url = await processAndSaveImage(req.file.buffer);
      res.json({ success: true, url });
    } catch (err) {
      console.error("Admin image upload error:", err);
      res.status(500).json({ success: false, message: "Image processing failed." });
    }
  }
);

// DELETE /api/upload-image — admin can remove a stored image file
app.delete("/api/upload-image", adminAuth, async (req, res) => {
  try {
    const { url } = req.body;           // e.g. "/uploads/1718123456789-abc.webp"
    if (!url || !url.startsWith("/uploads/")) {
      return res.status(400).json({ success: false, message: "Invalid image URL." });
    }
    // Prevent path traversal: only allow the filename component
    const basename = path.basename(url);
    const filePath = path.join(UPLOAD_DIR, basename);
    if (!filePath.startsWith(UPLOAD_DIR)) {
      return res.status(400).json({ success: false, message: "Invalid path." });
    }
    try {
      await fs.promises.unlink(filePath);
    } catch (unlinkErr) {
      if (unlinkErr.code !== 'ENOENT') throw unlinkErr; // ignore "file not found", rethrow others
    }
    res.json({ success: true });
  } catch (err) {
    console.error("Image delete error:", err);
    res.status(500).json({ success: false, message: "Could not delete image." });
  }
});

// ── MongoDB ──
mongoose.connect("mongodb://127.0.0.1:27017/kr_realestate")
//mongoose.connect(process.env.MONGODB_URI)
  .then(async () => { console.log("✅ MongoDB Connected"); await seedAdmin(); })
  .catch(err => console.log("❌ MongoDB error:", err));

// ── SCHEMAS ──
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName:  { type: String, default: "" },
  email:     { type: String, unique: true, required: true },
  mobile:    { type: String, default: "" },
  password:  { type: String },
  role:      { type: String, default: "user", enum: ["user","admin"] },
  remarks: [
  {
    remark: { type: String, default: "" },
    date: { type: Date, default: Date.now }
  }
],
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model("User", UserSchema);

const PropertySchema = new mongoose.Schema({
  title:        { type: String, required: true },
  loc:          { type: String, required: true },
  city:         { type: String, default: "Bengaluru" },
  price:        { type: Number, required: true },
  displayPrice: { type: String, required: true },
  bhk: { type: Number, default: null },
  area:         String,
  status:       { type: String, enum: ["For Sale","For Rent","New Launch","Sold","Booked","Lease","PG"], default: "For Sale" },
  furnishing:   { type: String, default: "Unfurnished" },
  floor: String, floorLevel: String, age: String, facing: String,
  carparking: String, bikeparking: String, toilet: String,
  amenities: [String], images: [String], desc: String, color: String, icon: String,
  deposit:    { type: Number, default: null },
  latitude:   { type: Number, default: null },
  longitude:  { type: Number, default: null },
  pgGender:    { type: String, default: null },
  pgRoomType:  { type: String, default: null },
  pgMeals:     { type: String, default: null },
  pgOccupancy: { type: Number, default: null },
  pgNotice:    { type: String, default: null },
  pgBathroom:  { type: String, default: null },
  // ── PG extra fields ──
  pgMealsCost:      { type: Number, default: null },
  pgTotalBeds:      { type: String, default: null },
  pgRoomFurnishing: { type: String, default: null },
  pgFoodType:       { type: String, default: null },
  pgKitchenAccess:  { type: String, default: null },
  pgAvailableFrom:  { type: String, default: null },
  pgVisitorPolicy:  { type: String, default: null },
  pgGateTime:       { type: String, default: null },
  pgNonVeg:         { type: String, default: null },
  pgPets:           { type: String, default: null },
  // ── For Rent extra fields ──
  availableFrom:  { type: String, default: null },
  noticePeriod:   { type: String, default: null },
  leaseDuration:  { type: String, default: null },
  tenantPref:     { type: String, default: null },
  maintenance:    { type: Number, default: null },
  petsAllowed:    { type: String, default: null },
  nonVegAllowed:  { type: String, default: null },
  pipedGas:       { type: String, default: null },
  // ── Lease extra fields ──
  leaseAmount:      { type: Number, default: null },
  leaseMonthlyRent: { type: Number, default: null },
  leaseMaintenance: { type: Number, default: null },
  leaseDurationVal: { type: String, default: null },
  leaseType:        { type: String, default: null },
  lockInPeriod:     { type: String, default: null },
  leaseAvailFrom:   { type: String, default: null },
  leaseNotice:      { type: String, default: null },
  rentEscalation:   { type: String, default: null },
  leasePets:        { type: String, default: null },
  leaseNonVeg:      { type: String, default: null },
  // ── New form fields ──
  propertyType:        { type: String, default: null },
  societyName:         { type: String, default: "" },
  totalFloors:         { type: Number, default: null },
  electricityIncluded: { type: String, default: null },
  waterCharge:         { type: String, default: null },
  escalation:          { type: Number, default: null },
  listedBy:            { type: String, default: "Owner" },
  googleMapsLink:      { type: String, default: "" },
  videoUrl:            { type: String, default: "" },
  // Amenity checkboxes
  amenityWifi:     { type: Boolean, default: false },
  amenityAc:       { type: Boolean, default: false },
  acUnits:         { type: Number,  default: null },
  amenityWashing:  { type: Boolean, default: false },
  amenityFridge:   { type: Boolean, default: false },
  amenityMicrowave:{ type: Boolean, default: false },
  amenityGeyser:   { type: Boolean, default: false },
  amenityWardrobe: { type: Boolean, default: false },
  amenityBed:      { type: Boolean, default: false },
  amenitySofa:     { type: Boolean, default: false },
  amenityLift:     { type: Boolean, default: false },
  amenityCctv:     { type: Boolean, default: false },
  amenityBalcony:  { type: Boolean, default: false },
  amenityGym:      { type: Boolean, default: false },
  amenityPipedGas: { type: Boolean, default: false },
  amenityRo:       { type: Boolean, default: false },
  // ── Owner Details ──
  ownerName:    { type: String, default: "" },
  ownerNumber:  { type: String, default: "" },
  ownerEmail:   { type: String, default: "" },
  ownerAltPhone:{ type: String, default: "" },
  ownerAddress: { type: String, default: "" },
  contactTime:  { type: String, default: "" },
  fullAddress:  { type: String, default: "" },
  remarks: [
    {
      remark: { type: String, default: "" },
      date:   { type: Date,   default: Date.now }
    }
  ],
  createdAt:        { type: Date,    default: Date.now },
  promoted:         { type: Boolean, default: false },
  promotedPos:      { type: String,  default: 'top-right' },
  promotedPriority: { type: Number,  default: 3 },
  views:            { type: Number,  default: 0 },
  negotiable:       { type: Boolean, default: false },
  submittedBy:      { type: String, default: "" }   // email of the logged-in user who listed this
});
PropertySchema.index({ createdAt: -1 });
PropertySchema.index({ promoted: 1, promotedPriority: 1 });
PropertySchema.index({ status: 1, createdAt: -1 });
PropertySchema.index({ city: 1, status: 1 });
const Property = mongoose.model("Property", PropertySchema);

const ReviewSchema = new mongoose.Schema({
  name: String, role: String, comment: String,
  email: { type: String, default: "" },
  rating: { type: Number, min:1, max:5, required:true },
  createdAt: { type: Date, default: Date.now }
});
ReviewSchema.index({ email: 1 });
const Review = mongoose.model("Review", ReviewSchema);

// ── CLICK HEATMAP SCHEMA ──
const ClickEventSchema = new mongoose.Schema({
  page:       { type: String, default: 'home' },
  target:     { type: String, required: true },
  label:      { type: String, default: '' },
  propertyId: { type: String, default: '' },
  xPct:       { type: Number, default: 0 },
  yPct:       { type: Number, default: 0 },
  ua:         { type: String, default: '' },
  createdAt:  { type: Date,   default: Date.now }
});
ClickEventSchema.index({ createdAt: -1, page: 1 });
const ClickEvent = mongoose.model('ClickEvent', ClickEventSchema);

// ── APPOINTMENT SCHEMA ──
const AppointmentSchema = new mongoose.Schema({
  name:       { type: String, required: true },
  email:      { type: String, required: true },
  mobile:     { type: String, required: true },
  altMobile:  { type: String, default: "" },
  purpose:    { type: String, required: true },     // "For Rent" | "For Sale" | "Lease" | "PG" | "General Enquiry"
  propertyId: { type: String, default: "" },
  date:       { type: String, required: true },     // YYYY-MM-DD
  timeSlot:   { type: String, required: true },     // "Morning" | "Afternoon" | "Evening"
  message:    { type: String, default: "" },
  status:     { type: String, enum: ["pending", "confirmed", "cancelled", "completed"], default: "pending" },
  submittedBy: { type: String, default: "" },   // email of the logged-in user who booked
  remarks: [
    {
      remark: { type: String, default: "" },
      date:   { type: Date,   default: Date.now }
    }
  ],
  createdAt:  { type: Date, default: Date.now }
});
AppointmentSchema.index({ createdAt: -1 });
AppointmentSchema.index({ date: 1, timeSlot: 1, purpose: 1, status: 1 }); // used by duplicate-booking check
const Appointment = mongoose.model("Appointment", AppointmentSchema);

// ── REAL-TIME ADMIN NOTIFICATION (SSE) ──
// Map of res objects for all connected admin SSE clients
const sseAdminClients = new Set();

function emitAppointmentNotification(appt) {
  console.log('[SSE] Emitting to', sseAdminClients.size, 'admin client(s)');
  const payload = JSON.stringify({
    type: 'new_appointment',
    appointment: {
      _id:      appt._id,
      name:     appt.name,
      mobile:   appt.mobile,
      purpose:  appt.purpose,
      date:     appt.date,
      timeSlot: appt.timeSlot,
      status:   appt.status,
      createdAt: appt.createdAt
    }
  });
  for (const client of sseAdminClients) {
    try { client.write(`data: ${payload}\n\n`); } catch(e) { sseAdminClients.delete(client); }
  }
}

// SSE endpoint — admin browser connects here to receive live pushes
// EventSource can't send headers, so we also accept the key as ?key= query param
function sseAdminAuth(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.key;
  if (!key || key !== process.env.ADMIN_API_KEY) {
    return res.status(403).end('Forbidden');
  }
  next();
}
app.get('/api/appointments/sse', sseAdminAuth, (req, res) => {
  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',    'keep-alive');
  res.flushHeaders();

  // Keep-alive ping every 20 s so proxies don't drop the connection
  const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch(e) {} }, 20000);

  sseAdminClients.add(res);
  console.log('[SSE] Admin connected. Total clients:', sseAdminClients.size);
  req.on('close', () => { clearInterval(ping); sseAdminClients.delete(res); console.log('[SSE] Admin disconnected. Remaining:', sseAdminClients.size); });
});

if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
  if (process.env.NODE_ENV === 'production') throw new Error("RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET are required in production");
  console.warn("⚠️  RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET not set — payment routes will fail at runtime");
}

// ── RAZORPAY ──
const razorpay = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// ── PAYMENT SCHEMA ──
const PaymentSchema = new mongoose.Schema({
  orderId:        { type: String, required: true, unique: true },
  paymentId:      { type: String, default: "" },
  signature:      { type: String, default: "" },
  type:           { type: String, enum: ["listing","token","membership","consultation"], required: true },
  amount:         { type: Number, required: true },   // in paise
  currency:       { type: String, default: "INR" },
  status:         { type: String, enum: ["created","paid","failed"], default: "created" },
  name:           { type: String, default: "" },
  email:          { type: String, default: "" },
  mobile:         { type: String, default: "" },
  propertyId:     { type: String, default: "" },
  propertyTitle:  { type: String, default: "" },
  plan:           { type: String, default: "" },
  notes:          { type: String, default: "" },
  createdAt:      { type: Date, default: Date.now }
});
const Payment = mongoose.model("Payment", PaymentSchema);
const SiteVisitSchema = new mongoose.Schema({
  date:  { type: String, required: true, unique: true },
  count: { type: Number, default: 0 },
  ips:   [{ type: String }]   // one entry per unique IP per day
});
const SiteVisit = mongoose.model("SiteVisit", SiteVisitSchema);

// ── OTP STORE (MongoDB-backed, TTL-indexed) ──
// Using MongoDB instead of in-memory so OTPs survive restarts and work across multiple instances.
const OtpSchema = new mongoose.Schema({
  email:    { type: String, required: true, unique: true },
  otp:      { type: String, required: true },
  attempts: { type: Number, default: 0 },
  expiresAt:{ type: Date,   required: true }
});
OtpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // MongoDB auto-deletes expired docs
const OtpRecord = mongoose.model('OtpRecord', OtpSchema);

// ── SESSION STORE (MongoDB-backed, TTL-indexed) ──
// Using MongoDB instead of an in-memory Map so sessions survive restarts
// and work correctly across multiple server instances.
const SessionSchema = new mongoose.Schema({
  email:     { type: String, required: true, unique: true },
  token:     { type: String, required: true },
  expiresAt: { type: Date,   required: true }
});
SessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // MongoDB auto-purges expired sessions
const Session = mongoose.model('Session', SessionSchema);




// ── HTML escape helper for email templates ──
function escHtml(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ── EMAIL ──
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const BREVO_SENDER_EMAIL = "karthik.j@enhancesys.com";
const BREVO_SENDER_NAME = "KR Real Estate";

async function sendEmailWithBrevo(to, subject, htmlContent) {
  try {
    const response = await axios.post(
      "https://api.brevo.com/v3/smtp/email",
      {
        sender: { email: BREVO_SENDER_EMAIL, name: BREVO_SENDER_NAME },
        to: [{ email: to, name: to.split('@')[0] }],
        subject: subject,
        htmlContent: htmlContent
      },
      {
        headers: {
          "Content-Type": "application/json",
          "api-key": BREVO_API_KEY
        }
      }
    );
    return { success: true, data: response.data };
  } catch (error) {
    console.error("Brevo email error:", error.response?.data || error.message);
    return { success: false, error: error.response?.data || error.message };
  }
}

// ── SEED ADMIN ──
// ── SEED ADMINS ──
// SECURITY: Admin credentials are read from environment variables, NOT hardcoded here.
// Set SEED_ADMIN_EMAIL_1 / SEED_ADMIN_PASSWORD_1 (and _2, _3) in your .env to seed admin accounts.
// Example .env entries:
//   SEED_ADMIN_EMAIL_1=admin@yourdomain.com
//   SEED_ADMIN_PASSWORD_1=StrongPassword@1
//   SEED_ADMIN_FIRSTNAME_1=Karthik
function buildAdminAccounts() {
  const accounts = [];
  for (let i = 1; i <= 3; i++) {
    const email     = process.env[`SEED_ADMIN_EMAIL_${i}`];
    const password  = process.env[`SEED_ADMIN_PASSWORD_${i}`];
    const firstName = process.env[`SEED_ADMIN_FIRSTNAME_${i}`] || `Admin${i}`;
    const mobile    = process.env[`SEED_ADMIN_MOBILE_${i}`]    || "0000000000";
    if (email && password) accounts.push({ firstName, lastName: "", email, mobile, password });
  }
  return accounts;
}
const ADMIN_ACCOUNTS = buildAdminAccounts();

async function seedAdmin() {
  try {
    for (const acc of ADMIN_ACCOUNTS) {
      const exists = await User.findOne({ email: acc.email });
      if (!exists) {
        const hashed = await bcrypt.hash(acc.password, 10);
        await new User({
          firstName: acc.firstName,
          lastName:  acc.lastName,
          email:     acc.email,
          mobile:    acc.mobile,
          password:  hashed,
          role:      "admin"
        }).save();
        console.log(`✅ Admin seeded: ${acc.email}`);
      }
    }
  } catch(e) { console.log("Admin seed skipped:", e.message); }
}

// ══════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════

// SEND OTP
app.post("/send-otp", otpLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success:false, message:"Email required" });

    const emailKey = email.trim().toLowerCase();
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await OtpRecord.findOneAndUpdate(
      { email: emailKey },
      { otp, attempts: 0, expiresAt: new Date(Date.now() + 5 * 60 * 1000) },
      { upsert: true }
    );

    const emailHtml = `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #e0e0e0">
    <div style="background:linear-gradient(135deg,#1b3a2d,#2e7d5a);padding:22px 24px;text-align:center">
      <h2 style="margin:0;color:#fff;font-size:1.4rem">KR Real Estate</h2>
      <p style="margin:4px 0 0;color:rgba(255,255,255,0.6);font-size:0.8rem">Email Verification</p>
    </div>
    <div style="padding:28px 24px;text-align:center">
      <p style="color:#555;margin-bottom:18px">Your One-Time Password:</p>
      <div style="font-size:2.4rem;font-weight:800;letter-spacing:10px;background:#f0f9f4;padding:16px 20px;border-radius:10px;display:inline-block;color:#1b3a2d;border:2px dashed #2e7d5a">${otp}</div>
      <p style="color:#999;font-size:0.8rem;margin-top:16px">Valid for <strong>5 minutes</strong>. Do not share this OTP.</p>
    </div>
    <div style="background:#f9f9f9;padding:12px;text-align:center;font-size:0.72rem;color:#bbb">
      © ${new Date().getFullYear()} KR Real Estate
    </div>
  </div>`;

    const result = await sendEmailWithBrevo(email.trim(), "Your OTP — KR Real Estate", emailHtml);
    if (result.success) {
      res.json({ success: true });
    } else {
      console.error("Brevo send error:", result.error);
      res.json({ success: false, message: "Failed to send email. Please try again later." });
    }
  } catch(err) {
    console.error("Send OTP error:", err);
    res.status(500).json({ success: false, message: "Server error. Please try again." });
  }
});

// VERIFY OTP
app.post("/verify-otp", verifyOtpLimiter, async (req, res) => {
  try {
    const { email, otp } = req.body;
    const emailKey = (email || "").trim().toLowerCase();
    const record = await OtpRecord.findOne({ email: emailKey });
    if (!record) return res.json({ success:false, message:"No OTP found. Please request again." });
    if (new Date() > record.expiresAt) {
      await OtpRecord.deleteOne({ email: emailKey });
      return res.json({ success:false, message:"OTP expired." });
    }
    // Lock out after 5 failed attempts to prevent brute-force
    record.attempts = (record.attempts || 0) + 1;
    if (record.attempts > 5) {
      await OtpRecord.deleteOne({ email: emailKey });
      return res.json({ success:false, message:"Too many incorrect attempts. Please request a new OTP." });
    }
    if (record.otp !== String(otp)) {
      await record.save();
      return res.json({ success:false, message:"Incorrect OTP." });
    }
    await OtpRecord.deleteOne({ email: emailKey });
    res.json({ success: true });
  } catch(err) {
    console.error("Verify OTP error:", err);
    res.status(500).json({ success: false, message: "Server error. Please try again." });
  }
});

// REGISTER
app.post("/submit", registerLimiter, async (req, res) => {
  try {
    const { firstName, lastName, email, mobile, password } = req.body;
    if (!firstName || !lastName || !email || !mobile) return res.status(400).json({ message:"All fields are required." });
    if (!password || password.length < 6) return res.status(400).json({ message:"Password must be at least 6 characters." });
    const exists = await User.findOne({ email: email.trim().toLowerCase() });
    if (exists) return res.status(400).json({ message:"An account with this email already exists. Please sign in." });
    const hashed = await bcrypt.hash(password, 10);
    const user = await new User({
      firstName: firstName.trim(),
      lastName:  lastName.trim(),
      email:     email.trim().toLowerCase(),
      mobile:    mobile.trim(),
      password:  hashed,
      role:      "user"
    }).save();
    res.json({ message:"Account created! Welcome to KR Real-Estate.", firstName:user.firstName, lastName:user.lastName });
  } catch(err) {
    console.error("Register error:", err);
    res.status(500).json({ message:"Server error. Please try again." });
  }
});

// LOGIN
app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message:"Email and password are required." });
    const emailLower = email.trim().toLowerCase();
    // NOTE: The old hardcoded "admin"/"admin" bypass has been intentionally removed.
    // All admin accounts live in the database and are seeded via SEED_ADMIN_* env vars.
    const user = await User.findOne({ email: emailLower });
    if (!user) return res.status(401).json({ message:"No account found with this email. Please register first." });
    if (!user.password) return res.status(401).json({ message:"Password not set. Please register again." });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message:"Incorrect password. Please try again." });
    const isAdminUser = user.role === "admin";
    // Issue a session token so the frontend can authenticate user-only routes
    const sessionToken = crypto.randomBytes(32).toString('hex');
    const sessionExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await Session.findOneAndUpdate(
      { email: user.email },
      { token: sessionToken, expiresAt: sessionExpiry },
      { upsert: true }
    );
    res.json({ firstName:user.firstName, lastName:user.lastName||"", isAdmin:isAdminUser, role:user.role, sessionToken, email:user.email });
  } catch(err) {
    console.error("Login error:", err);
    res.status(500).json({ message:"Server error." });
  }
});

// LOGOUT — invalidates the server-side session token
app.post("/api/logout", async (req, res) => {
  try {
    const email = (req.headers['x-user-email'] || '').trim().toLowerCase();
    if (email) await Session.deleteOne({ email });
    res.json({ success: true });
  } catch(err) {
    console.error("Logout error:", err);
    res.status(500).json({ success: false, message: "Server error." });
  }
});
// USERS
app.get("/api/users", adminAuth, async (req, res) => {
  try { res.json(await User.find({},"-password").sort({createdAt:-1})); }
  catch(err) { res.status(500).json([]); }
});
app.delete("/api/users/:id", adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: "Invalid user ID" });
    const deleted = await User.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ message:"User not found" });
    res.json({ message:"Deleted successfully" });
  } catch(err) { res.status(500).json({ message:"Server error" }); }
});

// PROPERTIES
// Only internal admin remarks are hidden from regular users.
// ownerName, ownerNumber, fullAddress, latitude, longitude are shown to all users.
const ADMIN_ONLY_FIELDS = ['remarks'];

// Admin auth middleware - all admin routes require x-admin-key header
function adminAuth(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key || key !== process.env.ADMIN_API_KEY) {
    return res.status(403).json({ success: false, message: 'Forbidden: admin access required.' });
  }
  next();
}

// User auth middleware — requires a logged-in session token
// The frontend sends x-user-email + x-user-token (session token stored in localStorage after login).
// Sessions are stored in MongoDB (see SessionSchema defined above, near OtpRecord).


async function userAuth(req, res, next) {
  const email = (req.headers['x-user-email'] || '').trim().toLowerCase();
  const token = req.headers['x-user-token'] || '';
  if (!email || !token) {
    return res.status(401).json({ success: false, message: 'Please sign in to continue.' });
  }
  const record = await Session.findOne({ email }).lean();
  if (!record || record.token !== token) {
    return res.status(401).json({ success: false, message: 'Session expired. Please sign in again.' });
  }
  if (record.expiresAt < new Date()) {
    await Session.deleteOne({ email });
    return res.status(401).json({ success: false, message: 'Session expired. Please sign in again.' });
  }
  req.userEmail = email;
  next();
}


app.get("/api/properties", async (req, res) => {
  try {
    const isAdmin = req.headers["x-admin-key"] === process.env.ADMIN_API_KEY;

    // ── Optional server-side filtering (used by admin panel queries) ──
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    if (req.query.city)   filter.city   = req.query.city;

    // ── Field projection: strip internal-only fields from public responses ──
    const projection = isAdmin ? {} : { remarks: 0 };

    const props = await Property.find(filter, projection)
      .sort({ promoted: -1, promotedPriority: 1, createdAt: -1 })
      .lean();

    // Allow browsers/CDN to cache public responses for 60s; admin responses skip cache
    if (!isAdmin) {
      res.set('Cache-Control', 'public, max-age=60, stale-while-revalidate=300');
    } else {
      res.set('Cache-Control', 'no-store');
    }
    res.json(props);
  } catch (err) {
    console.error(err);
    res.status(500).json([]);
  }
});

// PROPERTY_FIELDS: explicit allowlist — prevents mass-assignment of internal fields
// (promoted, promotedPriority, views, createdAt, etc.)
const PROPERTY_FIELDS = [
  'title','loc','city','price','displayPrice','bhk','area','status','furnishing',
  'floor','floorLevel','age','facing','carparking','bikeparking','toilet',
  'amenities','images','desc','color','icon','deposit','latitude','longitude',
  'pgGender','pgRoomType','pgMeals','pgOccupancy','pgNotice','pgBathroom',
  'pgMealsCost','pgTotalBeds','pgRoomFurnishing','pgFoodType','pgKitchenAccess',
  'pgAvailableFrom','pgVisitorPolicy','pgGateTime','pgNonVeg','pgPets',
  'availableFrom','noticePeriod','leaseDuration','tenantPref','maintenance',
  'petsAllowed','nonVegAllowed','pipedGas',
  'leaseAmount','leaseMonthlyRent','leaseMaintenance','leaseDurationVal','leaseType',
  'lockInPeriod','leaseAvailFrom','leaseNotice','rentEscalation','leasePets','leaseNonVeg',
  'propertyType','societyName','totalFloors','electricityIncluded','waterCharge',
  'escalation','listedBy','googleMapsLink','videoUrl',
  'amenityWifi','amenityAc','acUnits','amenityWashing','amenityFridge','amenityMicrowave',
  'amenityGeyser','amenityWardrobe','amenityBed','amenitySofa','amenityLift','amenityCctv',
  'amenityBalcony','amenityGym','amenityPipedGas','amenityRo',
  'ownerName','ownerNumber','ownerEmail','ownerAltPhone','ownerAddress','contactTime',
  'fullAddress','negotiable','submittedBy'
];
function pickPropertyFields(body) {
  return PROPERTY_FIELDS.reduce((acc, k) => { if (k in body) acc[k] = body[k]; return acc; }, {});
}

// ── Property input validation ──
const URL_FIELDS   = ['googleMapsLink', 'videoUrl'];
const MAX_LENGTHS  = { title: 200, desc: 5000, loc: 200, fullAddress: 500, societyName: 200,
                       ownerName: 100, ownerAddress: 300, contactTime: 100 };
const EMAIL_FIELDS = ['ownerEmail'];

function validatePropertyFields(fields) {
  // URL format check
  for (const f of URL_FIELDS) {
    if (fields[f] && fields[f].trim()) {
      try { new URL(fields[f].trim()); } catch {
        return `Invalid URL in field '${f}'.`;
      }
    }
  }
  // Length caps
  for (const [f, max] of Object.entries(MAX_LENGTHS)) {
    if (fields[f] && String(fields[f]).length > max)
      return `Field '${f}' must be at most ${max} characters.`;
  }
  // Basic email format
  for (const f of EMAIL_FIELDS) {
    if (fields[f] && fields[f].trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fields[f].trim()))
      return `Invalid email address in field '${f}'.`;
  }
  return null; // no error
}


app.post("/api/properties", userAuth, async (req, res) => {
  try {
    const fields = pickPropertyFields(req.body);
    const validationError = validatePropertyFields(fields);
    if (validationError) return res.status(400).json({ message: validationError });
    fields.submittedBy = req.userEmail;
    fields.displayPrice = formatPrice(fields.price, fields.status);
    const prop = new Property(fields);
    await prop.save();
    res.json({ message:"Property added successfully!" });
  } catch(err) {
    console.error(err);
    res.status(500).json({ message:"Error saving property: " + err.message });
  }
});

app.put("/api/properties/:id", adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: "Invalid property ID" });

    const fields = pickPropertyFields(req.body);
    const validationError = validatePropertyFields(fields);
    if (validationError) return res.status(400).json({ message: validationError });
    if (fields.price !== undefined || fields.status !== undefined) {
      // We need the current doc to fill in whichever field isn't in the update
      const current = await Property.findById(req.params.id).select('price status').lean();
      if (!current) return res.status(404).json({ message: "Property not found" });
      const num    = fields.price  !== undefined ? fields.price  : current.price;
      const status = fields.status !== undefined ? fields.status : current.status;
      let display  = '';
      if (num >= 10000000)    display = '₹' + (num/10000000).toFixed(2).replace(/\.?0+$/,'') + ' Cr';
      else if (num >= 100000) display = '₹' + (num/100000).toFixed(1).replace(/\.?0+$/,'') + ' L';
      else                    display = '₹' + num.toLocaleString('en-IN');
      if (['For Rent','Lease','PG'].includes(status)) display += '/Month';
      fields.displayPrice = display;
    }

    const updated = await Property.findByIdAndUpdate(req.params.id, fields, { new: true, runValidators: true });
    if (!updated) return res.status(404).json({ message: "Property not found" });
    res.json({ message: "Property updated successfully!", property: updated });
  } catch(err) {
    console.error(err);
    res.status(500).json({ message: "Error updating property: " + err.message });
  }
});

app.delete("/api/properties/:id", adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: "Invalid property ID" });
    const deleted = await Property.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ message: "Property not found" });
    res.json({ message: "Property deleted successfully" });
  } catch(err) {
    console.error(err);
    res.status(500).json({ message: "Error deleting property: " + err.message });
  }
});

// REVIEWS
app.get("/api/reviews", async (req, res) => {
  try { res.json(await Review.find().sort({createdAt:-1})); }
  catch(err) { res.status(500).json([]); }
});
app.post("/api/reviews", reviewLimiter, async (req, res) => {
  try {
    const { name, role, comment, rating, email } = req.body;
    if (!rating || rating < 1 || rating > 5) return res.status(400).json({ message:"Rating must be 1–5" });
    if (!comment || !comment.trim()) return res.status(400).json({ message:"Review comment required" });
    // Email is required to enforce one-review-per-person; anonymous submissions are not allowed.
    if (!email || !email.trim()) return res.status(400).json({ message:"Email is required to submit a review." });
    const emailLower = email.trim().toLowerCase();
    const existing = await Review.findOne({ email: emailLower });
    if (existing) return res.status(400).json({ message:"You have already submitted a review." });
    await new Review({ name, role, comment, rating, email: emailLower }).save();
    res.json({ message:"Review submitted successfully!" });
  } catch(err) {
    console.error(err);
    res.status(500).json({ message:"Error saving review" });
  }
});

app.get("/api/reviews/check/:email", async (req, res) => {
  try {
    const existing = await Review.findOne({ email: decodeURIComponent(req.params.email).toLowerCase() });
    res.json({ hasReviewed: !!existing });
  } catch(err) {
    res.status(500).json({ hasReviewed: false });
  }
});

app.delete("/api/reviews/:id", adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: "Invalid review ID" });
    const deleted = await Review.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ message: "Review not found" });
    res.json({ message: "Review deleted successfully" });
  } catch(err) {
    console.error(err);
    res.status(500).json({ message: "Error deleting review: " + err.message });
  }
});


// ── After the users DELETE route ──
app.patch("/api/users/:id/remarks", adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: "Invalid user ID" });

    const remarkText = (req.body.remarks || "").trim();

    const user = await User.findById(req.params.id);

    if (!user)
      return res.status(404).json({
        message: "User not found"
      });

    if (!Array.isArray(user.remarks)) {
      user.remarks = [];
    }

    user.remarks.push({
      remark: remarkText,
      date: new Date()
    });

    await user.save();

    res.json({
      message: "Remarks updated",
      remarks: user.remarks
    });

  } catch(err) {
    console.error(err);
    res.status(500).json({
      message: "Server error"
    });
  }
});

// ── After the properties DELETE route ──
app.patch("/api/properties/:id/remarks", adminAuth, async (req, res) => {
  try {

    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({
        message: "Invalid property ID"
      });

    const remarkText = (req.body.remarks || "").trim();

    const property = await Property.findById(req.params.id);

    if (!property)
      return res.status(404).json({
        message: "Property not found"
      });

    if (!Array.isArray(property.remarks)) {
      property.remarks = [];
    }

    property.remarks.push({
      remark: remarkText,
      date: new Date()
    });

    await property.save();

    res.json({
      message: "Remarks updated",
      remarks: property.remarks
    });

  } catch(err) {
    console.error(err);
    res.status(500).json({
      message: "Server error"
    });
  }
});


// ── Increment property view count ──
const viewedProps = new Map(); // "ip_propertyId_date" -> date string
// Prune stale entries every hour so the map doesn't grow indefinitely across days
setInterval(() => {
  const today = new Date().toISOString().split('T')[0];
  for (const k of viewedProps.keys()) {
    if (!k.endsWith(today)) viewedProps.delete(k);
  }
}, 60 * 60 * 1000);

app.patch("/api/properties/:id/view", async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: "Invalid property ID" });

    const today = new Date().toISOString().split('T')[0];
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    const key = `${ip}_${req.params.id}_${today}`;

    // Already viewed this property today from this IP — skip the DB read entirely
    if (viewedProps.get(key) === today) {
      return res.json({ skipped: true });
    }

    viewedProps.set(key, today);

    const property = await Property.findByIdAndUpdate(
      req.params.id,
      { $inc: { views: 1 } },
      { new: true, projection: { views: 1 } }
    );
    if (!property) return res.status(404).json({ message: "Property not found" });
    res.json({ views: property.views });
  } catch(err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ── Site visit tracker ──
app.post("/api/site-visit", siteVisitLimiter, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    const { ua = '', sw = '', sh = '' } = req.body || {};

    // Build a unique device key: ip + user-agent + screen size
    const deviceKey = `${ip}|${ua.slice(0, 120)}|${sw}x${sh}`;

    // Check if this device already visited today
    const alreadyVisited = await SiteVisit.findOne({ date: today, ips: deviceKey });
    if (alreadyVisited) {
      return res.json({ success: true, skipped: true });
    }

    // New device for today — increment count and record the device key
    const visit = await SiteVisit.findOneAndUpdate(
      { date: today },
      { $inc: { count: 1 }, $addToSet: { ips: deviceKey } },
      { upsert: true, new: true }
    );
    res.json({ success: true, today: visit.count });
  } catch(err) {
    console.error('Site visit error:', err);
    res.status(500).json({ success: false });
  }
});

app.get("/api/site-visits", adminAuth, async (req, res) => {
  try {
    const visits = await SiteVisit.find().sort({ date: -1 }).limit(30);
    const total = visits.reduce((sum, v) => sum + v.count, 0);
    const clean = visits.map(v => ({ date: v.date, count: v.count }));
    res.json({ visits: clean, total });
  } catch(err) { res.status(500).json({ visits: [], total: 0 }); }
});

// Reset all site visits (admin only)
app.delete("/api/site-visits/reset", adminAuth, async (req, res) => {
  try {
    await SiteVisit.deleteMany({});
    res.json({ success: true });
  } catch(err) { 
    console.error('Reset site visits error:', err);
    res.status(500).json({ success: false, message: err.message }); 
  }
});

// Reset all property views (admin only)
app.delete("/api/properties/views/reset", adminAuth, async (req, res) => {
  try {
    await Property.updateMany({}, { $set: { views: 0 } });
    viewedProps.clear();
    res.json({ success: true });
  } catch(err) { 
    console.error('Reset property views error:', err);
    res.status(500).json({ success: false, message: err.message }); 
  }
});

// ── Change property status (admin) ──
app.patch("/api/properties/:id/status", adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: "Invalid property ID" });

    const validStatuses = ["For Sale","For Rent","New Launch","Sold","Booked","Lease","PG"];
    const { status } = req.body;
    if (!status || !validStatuses.includes(status))
      return res.status(400).json({ message: "Invalid status value" });

    const property = await Property.findByIdAndUpdate(
      req.params.id,
      { $set: { status } },
      { new: true, runValidators: true }
    );
    if (!property) return res.status(404).json({ message: "Property not found" });

    res.json({ success: true, status: property.status, message: "Status updated to " + status });
  } catch (err) {
    console.error("Status patch error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ── Clone property (admin) — creates a copy with a new _id ──
app.post("/api/properties/clone/:id", adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: "Invalid property ID" });

    const original = await Property.findById(req.params.id).lean();
    if (!original) return res.status(404).json({ message: "Property not found" });

    // Strip server-managed fields so Mongoose assigns new ones
    const { _id, __v, createdAt, views, promoted, promotedPos, promotedPriority, submittedBy, ...rest } = original;
    const cloned = new Property({
      ...rest,
      title: original.title + " (Copy)",
      promoted: false,
      promotedPriority: 3,
      views: 0,
      submittedBy: submittedBy || ""
    });
    await cloned.save();
    res.json({ success: true, message: "Property cloned successfully!", property: cloned });
  } catch (err) {
    console.error("Clone error:", err);
    res.status(500).json({ message: "Error cloning property: " + err.message });
  }
});

// ── Toggle promoted status ──
app.patch("/api/properties/:id/promote", adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: "Invalid property ID" });
    const property = await Property.findById(req.params.id);
    if (!property) return res.status(404).json({ message: "Property not found" });
    property.promoted = !property.promoted;
    if (property.promoted) {
      const validPositions = ['top-left', 'top-right', 'bottom-left', 'bottom-right'];
      const pos = req.body && req.body.promotedPos;
      const priority = req.body && req.body.promotedPriority;
      property.promotedPos = validPositions.includes(pos) ? pos : 'top-right';
      property.promotedPriority = [1,2,3].includes(Number(priority)) ? Number(priority) : 3;
    } else {
      property.promotedPos = 'top-right';
      property.promotedPriority = 3;
    }
    await property.save();
    res.json({ message: "Promoted status updated", promoted: property.promoted, promotedPos: property.promotedPos, promotedPriority: property.promotedPriority });
  } catch(err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ══════════════════════════════════════════════
// PAYMENT ROUTES (Razorpay)
// ══════════════════════════════════════════════

// Payment type config
const PAYMENT_CONFIG = {
  listing:      { label: "Property Listing Fee",      amount: 49900  },  // ₹499
  token:        { label: "Token Booking Amount",       amount: 500000 },  // ₹5,000
  membership:   { label: "Premium Membership",         amount: 199900 },  // ₹1,999
  consultation: { label: "Service / Consultation Fee", amount: 99900  }   // ₹999
};

// CREATE ORDER — requires login to prevent anonymous spam orders
app.post("/api/payment/create-order", paymentLimiter, userAuth, async (req, res) => {
  try {
    const { type, name, email, mobile, propertyId, propertyTitle, plan, notes, customAmount } = req.body;
    if (!type || !PAYMENT_CONFIG[type]) return res.status(400).json({ message: "Invalid payment type." });
    if (!name || !email) return res.status(400).json({ message: "Name and email are required." });

    // For token bookings, allow a custom amount (min ₹1,000)
    let amount = PAYMENT_CONFIG[type].amount;
    if (type === "token" && customAmount !== undefined && customAmount !== "") {
      const parsed = Number(customAmount);
      if (!Number.isFinite(parsed) || parsed < 1000)
        return res.status(400).json({ message: "Minimum token amount is ₹1,000." });
      amount = Math.round(parsed * 100); // convert rupees → paise safely
    }

    const options = {
      amount,
      currency: "INR",
      receipt: `rcpt_${Date.now()}`,
      notes: { name, email, mobile: mobile || "", type, propertyTitle: propertyTitle || "" }
    };

    const order = await razorpay.orders.create(options);

    await new Payment({
      orderId: order.id, type, amount, name, email,
      mobile: mobile || "", propertyId: propertyId || "",
      propertyTitle: propertyTitle || "", plan: plan || "",
      notes: notes || "", status: "created"
    }).save();

    res.json({
      success: true,
      orderId: order.id,
      amount:  order.amount,
      currency: order.currency,
      keyId: process.env.RAZORPAY_KEY_ID,
      name, email, mobile: mobile || "",
      description: PAYMENT_CONFIG[type].label
    });
  } catch (err) {
    console.error("Create order error:", err);
    res.status(500).json({ message: "Could not create payment order. Please try again." });
  }
});

// VERIFY PAYMENT
app.post("/api/payment/verify", async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature)
      return res.status(400).json({ success: false, message: "Missing payment details." });

    const hmac = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET);
    hmac.update(`${razorpay_order_id}|${razorpay_payment_id}`);
    const digest = hmac.digest("hex");

    if (digest !== razorpay_signature)
      return res.status(400).json({ success: false, message: "Payment verification failed." });

    await Payment.findOneAndUpdate(
      { orderId: razorpay_order_id },
      { paymentId: razorpay_payment_id, signature: razorpay_signature, status: "paid" }
    );

    res.json({ success: true, message: "Payment verified successfully!" });
  } catch (err) {
    console.error("Verify payment error:", err);
    res.status(500).json({ success: false, message: "Verification error." });
  }
});

// MARK FAILED — requires admin auth; only transitions "created" orders to "failed"
// (prevents unauthenticated callers from sabotaging paid/already-verified orders)
app.post("/api/payment/failed", adminAuth, async (req, res) => {
  try {
    const { orderId } = req.body;
    if (orderId) {
      await Payment.findOneAndUpdate(
        { orderId, status: "created" },  // only cancel orders that haven't been paid yet
        { status: "failed" }
      );
    }
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false }); }
});

// LIST PAYMENTS (admin)
app.get("/api/payments", adminAuth, async (req, res) => {
  try { res.json(await Payment.find().sort({ createdAt: -1 })); }
  catch (err) { res.status(500).json([]); }
});

// DELETE PAYMENT (admin)
app.delete("/api/payments/:id", adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: "Invalid payment ID" });
    const deleted = await Payment.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ message: "Payment not found" });
    res.json({ message: "Payment deleted successfully" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

// NOTE: PATCH /api/properties/:id/status is defined above (line ~972). Duplicate removed.

// ── Reset single property views ──
app.delete("/api/properties/:id/views/reset", adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: "Invalid property ID" });
    const property = await Property.findByIdAndUpdate(
      req.params.id,
      { $set: { views: 0 } },
      { new: true }
    );
    if (!property) return res.status(404).json({ message: "Property not found" });
    res.json({ success: true, views: 0 });
  } catch(err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get("/api/site-visit-public", async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const visits = await SiteVisit.find().sort({ date: -1 }).limit(30);
    const todayVisit = visits.find(v => v.date === today);
    const total = visits.reduce((sum, v) => sum + v.count, 0);
    res.json({ today: todayVisit ? todayVisit.count : 0, total });
  } catch(err) {
    res.status(500).json({ today: 0, total: 0 });
  }
});

// ── APPOINTMENT ROUTES ──

// CREATE Appointment (requires login)
app.post("/api/appointments", userAuth, async (req, res) => {
  try {
    const { name, email, mobile, altMobile, purpose, propertyId, date, timeSlot, message } = req.body;

    if (!name || !email || !mobile || !purpose || !date || !timeSlot)
      return res.status(400).json({ success: false, message: "Please fill all required fields." });

    if (!/^[6-9]\d{9}$/.test(mobile))
      return res.status(400).json({ success: false, message: "Invalid mobile number." });

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ success: false, message: "Invalid email address." });

    const today = new Date().toISOString().split('T')[0];
    if (new Date(date) < new Date(today))
      return res.status(400).json({ success: false, message: "Please select a future date." });

    // Prevent duplicate booking: same date + time slot + purpose combination.
    // Scoped by purpose so a "General Enquiry" doesn't block property visits on the same slot.
    const cleanDate     = (date     || "").trim();
    const cleanTimeSlot = (timeSlot || "").trim();
    const cleanPurpose  = (purpose  || "").trim();
    const existing = await Appointment.findOne({
      date:     cleanDate,
      timeSlot: cleanTimeSlot,
      purpose:  cleanPurpose,
      status:   { $in: ["pending", "confirmed"] }
    });
    if (existing)
      return res.status(409).json({ success: false, message: `The ${cleanTimeSlot} slot on ${cleanDate} for ${cleanPurpose} is already booked. Please choose a different date or time slot.` });

    const appt = await new Appointment({
      name:       name.trim(),
      email:      email.trim(),
      mobile:     mobile.trim(),
      altMobile:  (altMobile  || "").trim(),
      purpose:    purpose.trim(),
      propertyId: (propertyId || "").trim(),
      date:       cleanDate,
      timeSlot:   cleanTimeSlot,
      message:    (message || "").trim(),
      submittedBy: req.userEmail
    }).save();

    // 🔔 Push instant notification to all connected admin browsers
    emitAppointmentNotification(appt);

    res.json({ success: true, message: "Appointment booked successfully!", appointmentId: appt._id });

  } catch (err) {
    console.error("Appointment error:", err);
    res.status(500).json({ success: false, message: "Server error. Please try again." });
  }
});

// UNREAD Appointment count since a given timestamp (admin)
app.get("/api/appointments/unread", adminAuth, async (req, res) => {
  try {
    const since = req.query.since ? new Date(Number(req.query.since)) : new Date(0);
    const count = await Appointment.countDocuments({ createdAt: { $gt: since } });
    const recent = await Appointment.find({ createdAt: { $gt: since } })
      .sort({ createdAt: -1 })
      .limit(10)
      .select('name mobile purpose date timeSlot createdAt status');
    res.json({ count, recent });
  } catch (err) {
    res.status(500).json({ count: 0, recent: [] });
  }
});

// LIST All Appointments (admin)
app.get("/api/appointments", adminAuth, async (req, res) => {
  try {
    const appts = await Appointment.find().sort({ createdAt: -1 });
    res.json(appts);
  } catch (err) {
    res.status(500).json([]);
  }
});

// UPDATE Appointment Status (admin)
app.patch("/api/appointments/:id", adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: "Invalid appointment ID" });

    const validStatuses = ["pending", "confirmed", "cancelled", "completed"];
    const { status } = req.body;
    if (!validStatuses.includes(status))
      return res.status(400).json({ message: "Invalid status" });

    // Fetch existing to check prior status
    const existing = await Appointment.findById(req.params.id);
    if (!existing) return res.status(404).json({ message: "Appointment not found" });

    const appt = await Appointment.findByIdAndUpdate(req.params.id, { status }, { new: true });

    // Send confirmation email only when transitioning TO confirmed
    if (status === 'confirmed' && existing.status !== 'confirmed' && appt.email) {
      const slotIcon = { Morning: '🌅', Afternoon: '☀️', Evening: '🌙' }[appt.timeSlot] || '🕐';
      const emailHtml = `
<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;background:#fff;border-radius:14px;overflow:hidden;border:1px solid #e0e0e0">
  <div style="background:linear-gradient(135deg,#1b3a2d,#2e7d5a);padding:24px;text-align:center">
    <h2 style="margin:0;color:#fff;font-size:1.4rem;font-family:Georgia,serif">KR Real Estate</h2>
    <p style="margin:6px 0 0;color:rgba(255,255,255,0.7);font-size:0.82rem">Appointment Confirmed</p>
  </div>
  <div style="padding:30px 28px">
    <p style="font-size:1rem;color:#222;margin-bottom:6px">Hi <strong>${escHtml(appt.name)}</strong>,</p>
    <p style="color:#555;font-size:0.9rem;line-height:1.6;margin-bottom:24px">
      Your appointment with <strong>KR Real Estate</strong> has been <span style="color:#1a7a5e;font-weight:700">confirmed</span>. Here are your details:
    </p>
    <div style="background:#f4f9f6;border-radius:10px;padding:18px 20px;border:1px solid #d0ece1;margin-bottom:24px">
      <table style="width:100%;border-collapse:collapse;font-size:0.88rem">
        <tr><td style="padding:7px 0;color:#666;width:40%">📅 Date</td><td style="padding:7px 0;font-weight:700;color:#111">${escHtml(appt.date)}</td></tr>
        <tr><td style="padding:7px 0;color:#666">${slotIcon} Time Slot</td><td style="padding:7px 0;font-weight:700;color:#111">${escHtml(appt.timeSlot)}</td></tr>
        <tr><td style="padding:7px 0;color:#666">🏠 Purpose</td><td style="padding:7px 0;font-weight:700;color:#111">${escHtml(appt.purpose)}</td></tr>
        <tr><td style="padding:7px 0;color:#666">📞 Mobile</td><td style="padding:7px 0;font-weight:700;color:#111">${escHtml(appt.mobile)}</td></tr>
        ${appt.message ? `<tr><td style="padding:7px 0;color:#666;vertical-align:top">💬 Message</td><td style="padding:7px 0;color:#333">${escHtml(appt.message)}</td></tr>` : ''}
      </table>
    </div>
    <p style="color:#555;font-size:0.85rem;line-height:1.7;margin-bottom:20px">
      Our team will be in touch if there are any changes. For queries, feel free to reply to this email or call us directly.
    </p>
    <div style="text-align:center">
      <a href="tel:${escHtml(appt.mobile)}" style="display:inline-block;background:#1b3a2d;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-size:0.88rem;font-weight:700">📞 Contact Us</a>
    </div>
  </div>
  <div style="background:#f9f9f9;padding:14px;text-align:center;font-size:0.72rem;color:#aaa">
    © ${new Date().getFullYear()} KR Real Estate · This is an automated message
  </div>
</div>`;
      // Fire-and-forget — don't block the response
      sendEmailWithBrevo(appt.email, 'Your Appointment is Confirmed — KR Real Estate', emailHtml)
        .catch(err => console.error('Appointment confirmation email error:', err));
    }

    res.json({ success: true, appointment: appt });
  } catch (err) {
    console.error('Appointment patch error:', err);
    res.status(500).json({ message: "Server error" });
  }
});

// ADD Remark to Appointment (admin)
app.patch("/api/appointments/:id/remarks", adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: "Invalid appointment ID" });

    const remarkText = (req.body.remarks || "").trim();

    const appt = await Appointment.findById(req.params.id);
    if (!appt) return res.status(404).json({ message: "Appointment not found" });

    if (!Array.isArray(appt.remarks)) appt.remarks = [];

    appt.remarks.push({ remark: remarkText, date: new Date() });
    await appt.save();

    res.json({ message: "Remark added", remarks: appt.remarks });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// DELETE Appointment (admin)
app.delete("/api/appointments/:id", adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: "Invalid appointment ID" });
    const deleted = await Appointment.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ message: "Appointment not found" });
    res.json({ success: true, message: "Appointment deleted" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// FRONTEND
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ══════════════════════════════════════════════════════════════════
// CLICK HEATMAP ROUTES
// ══════════════════════════════════════════════════════════════════

app.post('/api/heatmap', heatmapLimiter, async (req, res) => {
  try {
    const { page = 'home', target, label = '', propertyId = '', xPct, yPct } = req.body;
    if (!target) return res.status(400).json({ ok: false });
    const safeX = (Number.isFinite(Number(xPct)) && Number(xPct) >= 0 && Number(xPct) <= 100) ? Number(xPct) : 0;
    const safeY = (Number.isFinite(Number(yPct)) && Number(yPct) >= 0 && Number(yPct) <= 100) ? Number(yPct) : 0;
    const ua = (req.headers['user-agent'] || '').slice(0, 150);
    await ClickEvent.create({ page, target, label, propertyId, xPct: safeX, yPct: safeY, ua });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false }); }
});

app.get('/api/heatmap', adminAuth, async (req, res) => {
  try {
    const { days = 30, page } = req.query;
    const since = new Date(Date.now() - Number(days) * 86400000);
    const match = { createdAt: { $gt: since } };
    if (page) match.page = page;

    const [byTarget, byProperty, dots, trend, total] = await Promise.all([
      ClickEvent.aggregate([
        { $match: match },
        { $group: { _id: '$target', label: { $first: '$label' }, count: { $sum: 1 } } },
        { $sort: { count: -1 } }, { $limit: 40 }
      ]),
      ClickEvent.aggregate([
        { $match: { ...match, propertyId: { $ne: '' } } },
        { $group: { _id: '$propertyId', count: { $sum: 1 } } },
        { $sort: { count: -1 } }, { $limit: 20 }
      ]),
      ClickEvent.find(match, 'xPct yPct target label propertyId createdAt').sort({ createdAt: -1 }).limit(500).lean(),
      ClickEvent.aggregate([
        { $match: match },
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } }
      ]),
      ClickEvent.countDocuments(match)
    ]);

    res.json({ byTarget, byProperty, dots, trend, total });
  } catch (err) {
    console.error('Heatmap GET error:', err);
    res.status(500).json({ byTarget: [], byProperty: [], dots: [], trend: [], total: 0 });
  }
});


function formatPrice(price, status) {
  const num = Number(price);

  let display = '';

  if (num >= 10000000) {
    display = (num / 10000000).toFixed(2).replace(/\.?0+$/, '') + 'Cr';
  } else if (num >= 100000) {
    display = (num / 100000).toFixed(1).replace(/\.?0+$/, '') + 'L';
  } else if (num >= 1000) {
    display = (num / 1000).toFixed(1).replace(/\.?0+$/, '') + 'K';
  } else {
    display = String(num);
  }

  if (['For Rent', 'Lease', 'PG'].includes(status)) {
    display += '/Month';
  }

  return display;
}

app.delete('/api/heatmap', adminAuth, async (req, res) => {
  try {
    await ClickEvent.deleteMany({});
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false }); }
});

// ── Global error handler ──
// Catches errors thrown by middleware (e.g. multer, JSON parse errors) that reach here
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  const status = err.status || err.statusCode || 500;
  const message = (process.env.NODE_ENV === 'production')
    ? 'An unexpected error occurred.'
    : (err.message || 'An unexpected error occurred.');
  res.status(status).json({ success: false, message });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server on port ${PORT}`);

  // ── Keep-alive self-ping ──
  // Prevents free-tier hosts (Render, Railway) from cold-starting (10–15s delay).
  // Pings /api/properties every 10 minutes so the process never idles down.
  setInterval(() => {
    require('http').get(`http://localhost:${PORT}/api/properties`, (res) => {
      res.resume(); // drain response so the socket closes cleanly
    }).on('error', (err) => {
      console.warn('Keep-alive ping failed:', err.message);
    });
  }, 10 * 60 * 1000); // every 10 minutes
});