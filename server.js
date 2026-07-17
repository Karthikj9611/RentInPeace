require('dotenv').config();

const express    = require('express');
const mongoose   = require('mongoose');
const cors       = require('cors');
const path       = require('path');
const crypto     = require('crypto');
const rateLimit  = require('express-rate-limit');
const bcrypt     = require('bcryptjs');
const multer     = require('multer');
const sharp      = require('sharp');
const { sendEmailWithBrevo, otpEmailTemplate } = require('./mail');

// ── Env checks ──
if (!process.env.MONGODB_URI)   throw new Error('MONGODB_URI env var is required');
if (!process.env.ALLOWED_ORIGIN) {
  if (process.env.NODE_ENV === 'production') throw new Error('ALLOWED_ORIGIN env var is required in production');
  console.warn('⚠️  ALLOWED_ORIGIN not set — defaulting to * (development only)');
}
if (process.env.NODE_ENV === 'production' && (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD)) {
  throw new Error('ADMIN_EMAIL and ADMIN_PASSWORD env vars are required in production (hardcoded admin/admin login is dev-only)');
}
if (!process.env.BREVO_API_KEY) {
  console.warn('⚠️  BREVO_API_KEY not set — signup OTP emails will fail to send');
}

const app = express();
app.set('trust proxy', 1); // we're behind Render's proxy; needed for express-rate-limit to key off the real client IP
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
app.use(express.json({ limit: '10mb' })); // 10mb to allow base64 images
app.use(express.static('public', { maxAge: '7d', etag: true }));

// ────────────────────────────────────────────────────────────────────────────
// ── ADMIN LOGIN ──
// In dev (no ADMIN_EMAIL/ADMIN_PASSWORD set), falls back to admin@admin.com/admin.
// In production, the env check above forces real credentials to be set.
// Sessions are stored in Mongo (not a JS Map) so they survive restarts/deploys —
// important on free-tier hosting where the process restarts/cold-starts often.
// ────────────────────────────────────────────────────────────────────────────
// admin.html logs in with { email, password } and expects { adminKey, firstName } back,
// then sends the key on every request as the 'x-admin-key' header — matched here.
const ADMIN_EMAIL    = (process.env.ADMIN_EMAIL || 'admin@admin.com').toLowerCase();
// Hashed once at startup, never compared as a plain string — closes the timing-attack
// gap a direct `password === ADMIN_PASSWORD` check would have, and means the raw
// password only ever exists in process memory for the comparison itself.
const ADMIN_PASSWORD_HASH = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin', 10);
const ADMIN_NAME     = 'Admin';
const SESSION_TTL_MS = 4 * 60 * 60 * 1000; // 4 hours

const AdminSessionSchema = new mongoose.Schema({
  key:       { type: String, required: true, unique: true, index: true },
  expiresAt: { type: Date, required: true, expires: 0 }, // TTL index: Mongo auto-deletes once expiresAt passes
});
const AdminSession = mongoose.model('AdminSession', AdminSessionSchema);

async function issueAdminSession() {
  const key = crypto.randomBytes(32).toString('hex');
  await AdminSession.create({ key, expiresAt: new Date(Date.now() + SESSION_TTL_MS) });
  return key;
}

async function isValidAdminSession(key) {
  if (!key) return false;
  const session = await AdminSession.findOne({ key, expiresAt: { $gt: new Date() } }).lean();
  return !!session;
}

// Simple rate limiter on the login route to slow down brute-force attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { message: 'Too many login attempts. Please try again later.' }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const emailMatch = String(email || '').toLowerCase() === ADMIN_EMAIL;
    const passwordMatch = typeof password === 'string' && await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
    // Always run bcrypt.compare even when the email doesn't match, so a wrong-email
    // request and a wrong-password request take the same amount of time.
    if (emailMatch && passwordMatch) {
      const adminKey = await issueAdminSession();
      return res.json({ message: 'Login successful', adminKey, firstName: ADMIN_NAME });
    }
    return res.status(401).json({ message: 'Invalid email or password' });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.post('/api/admin/logout', async (req, res) => {
  try {
    const key = (req.headers['x-admin-key'] || '').toString();
    await AdminSession.deleteOne({ key });
    res.json({ message: 'Logged out' });
  } catch (err) {
    console.error('Admin logout error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ── User Schema ──
const RemarkEntrySchema = new mongoose.Schema({
  remark: { type: String, required: true, trim: true, maxlength: 200 },
  date:   { type: Date, default: Date.now },
}, { _id: false });

const UserSchema = new mongoose.Schema({
  name:      { type: String, trim: true }, // derived as `${firstName} ${lastName}`.trim(), kept for backward compat with existing UI code
  firstName: { type: String, trim: true },
  lastName:  { type: String, trim: true },
  email:     { type: String, trim: true, lowercase: true, sparse: true, unique: true },
  mobile:    { type: String, trim: true, sparse: true, unique: true },
  password:  { type: String, required: true },
  remarks:   { type: [RemarkEntrySchema], default: [] },
  // Human-readable unique id, same pattern as Property.propertyId (e.g. USER-000001).
  // This is a *display* identifier, distinct from the Mongo _id. Session docs
  // (UserSession) store this alongside the ObjectId reference — see below.
  userId:    { type: String, unique: true, sparse: true, index: true },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// ────────────────────────────────────────────────────────────────────────────
// ── SIGNUP EMAIL OTP ──
// One doc per email, overwritten on every resend. The OTP itself is bcrypt-hashed
// (same pattern as passwords) so a DB read alone doesn't leak a usable code.
// `verified` flips true once the correct OTP is submitted; /api/user/signup checks
// this flag before creating the account. expiresAt carries a Mongo TTL index so
// stale/unverified docs (and used ones, past their window) clean themselves up —
// no cron job needed.
// ────────────────────────────────────────────────────────────────────────────
const OTP_TTL_MS          = 5  * 60 * 1000; // matches "Valid for 5 minutes" in the email template
const OTP_RESEND_COOLDOWN_MS = 30 * 1000;   // minimum gap between sends for the same email
const OTP_MAX_ATTEMPTS     = 5;             // wrong-code guesses allowed before the code is dead

const EmailOtpSchema = new mongoose.Schema({
  email:      { type: String, required: true, lowercase: true, trim: true, unique: true, index: true },
  otpHash:    { type: String, required: true },
  attempts:   { type: Number, default: 0 },
  verified:   { type: Boolean, default: false },
  lastSentAt: { type: Date, default: Date.now },
  expiresAt:  { type: Date, required: true, index: { expires: 0 } }, // TTL: Mongo auto-deletes once this passes
});
const EmailOtp = mongoose.model('EmailOtp', EmailOtpSchema);

// Rate limiter for the OTP endpoints specifically — tighter than the general
// auth limiter since each hit sends a real email (Brevo has its own quota/cost).
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 8,
  standardHeaders: true, legacyHeaders: false,
  message: { message: 'Too many OTP requests. Please try again later.' }
});

// Rate limiter for user auth
const userAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { message: 'Too many attempts. Please try again later.' }
});

// ────────────────────────────────────────────────────────────────────────────
// ── USER SESSIONS ──
// Same pattern as admin sessions above, also Mongo-backed: a random token
// handed back on login/signup, sent on later requests as 'x-user-key',
// matched here. Survives restarts and cold starts.
// ────────────────────────────────────────────────────────────────────────────
const USER_SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const UserSessionSchema = new mongoose.Schema({
  key:            { type: String, required: true, unique: true, index: true },
  userObjectId:   { type: mongoose.Schema.Types.ObjectId, required: true, index: true }, // Mongo _id — used internally for querying other collections
  userId:         { type: String, default: null, index: true }, // human-readable User.userId (e.g. USER-000001), stored for readability/lookups in the DB
  expiresAt:      { type: Date, required: true, expires: 0 }, // TTL index: Mongo auto-deletes once expiresAt passes
});
const UserSession = mongoose.model('UserSession', UserSessionSchema);

// Takes the full user document so the session can carry both the Mongo _id
// (used internally to query Property/VisitRequest/etc, all of which reference
// users by ObjectId) and the human-readable userId (for admins browsing the
// usersessions collection directly).
async function issueUserSession(user) {
  const key = crypto.randomBytes(32).toString('hex');
  await UserSession.create({
    key,
    userObjectId: user._id,
    userId:       user.userId || null,
    expiresAt:    new Date(Date.now() + USER_SESSION_TTL_MS),
  });
  return key;
}

async function getUserIdFromSession(key) {
  if (!key) return null;
  const session = await UserSession.findOne({ key, expiresAt: { $gt: new Date() } }).lean();
  return session ? String(session.userObjectId) : null;
}

// Same lookup as getUserIdFromSession, but returns both the Mongo _id and the
// human-readable User.userId (e.g. USER-000001) in one query — the session
// doc already stores both (see issueUserSession above), so no extra User
// lookup is needed. Used wherever a created doc should be stamped with both.
async function getSessionUserIds(key) {
  if (!key) return { userId: null, userReadableId: null };
  const session = await UserSession.findOne({ key, expiresAt: { $gt: new Date() } }).lean();
  if (!session) return { userId: null, userReadableId: null };
  return { userId: String(session.userObjectId), userReadableId: session.userId || null };
}

// Middleware to protect routes that require a logged-in user.
// Attaches req.userId (ObjectId string) and req.userReadableId (e.g. USER-000001) when the session is valid.
async function requireUser(req, res, next) {
  try {
    const key = (req.headers['x-user-key'] || '').toString();
    const { userId, userReadableId } = await getSessionUserIds(key);
    if (!userId) return res.status(401).json({ message: 'Please log in to continue' });
    req.userId = userId;
    req.userReadableId = userReadableId;
    next();
  } catch (err) {
    console.error('requireUser error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
}

// Like requireUser, but never blocks the request — just attaches req.userId
// (and req.userReadableId) if a valid session key was sent (null otherwise).
// Used on routes that must still work for guests, e.g. submitting a listing
// while logged out.
async function attachUserIfPresent(req, res, next) {
  try {
    const key = (req.headers['x-user-key'] || '').toString();
    const { userId, userReadableId } = await getSessionUserIds(key);
    req.userId = userId;
    req.userReadableId = userReadableId;
    next();
  } catch (err) {
    console.error('attachUserIfPresent error:', err);
    req.userId = null;
    req.userReadableId = null;
    next();
  }
}

// ── Signup: Step 1 — send email OTP ──
// Called when the person fills in their email on the signup form, before the
// account is actually created. Generates a 6-digit code, bcrypt-hashes it into
// EmailOtp (upsert — a resend just overwrites the previous code), and emails it
// via Brevo. Doesn't require the account to exist yet (it doesn't, at this point).
app.post('/api/user/signup/send-otp', otpLimiter, async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email || !String(email).trim()) return res.status(400).json({ message: 'Email is required' });
    const cleanEmail = String(email).toLowerCase().trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) return res.status(400).json({ message: 'Please enter a valid email address' });

    const existingUser = await User.findOne({ email: cleanEmail });
    if (existingUser) return res.status(409).json({ message: 'Account already exists for this email. Please log in.' });

    // Cheap resend-spam guard on top of the IP-based otpLimiter above — stops
    // someone from hammering "resend" for one target email from many IPs.
    const existingOtp = await EmailOtp.findOne({ email: cleanEmail }).lean();
    if (existingOtp && (Date.now() - new Date(existingOtp.lastSentAt).getTime()) < OTP_RESEND_COOLDOWN_MS) {
      return res.status(429).json({ message: 'Please wait a few seconds before requesting another code.' });
    }

    const otp = String(crypto.randomInt(100000, 1000000)); // 6-digit, zero can't lead since randomInt floor is 100000
    const otpHash = await bcrypt.hash(otp, 10);

    await EmailOtp.findOneAndUpdate(
      { email: cleanEmail },
      { email: cleanEmail, otpHash, attempts: 0, verified: false, lastSentAt: new Date(), expiresAt: new Date(Date.now() + OTP_TTL_MS) },
      { upsert: true }
    );

    const mailResult = await sendEmailWithBrevo(cleanEmail, 'Your Quatar verification code', otpEmailTemplate(otp));
    if (!mailResult.success) {
      console.error('Failed to send signup OTP email:', mailResult.error);
      return res.status(502).json({ message: 'Could not send the verification email. Please try again in a moment.' });
    }

    return res.json({ message: 'Verification code sent to your email' });
  } catch (err) {
    console.error('Send signup OTP error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ── Signup: Step 2 — verify the OTP ──
// Marks the EmailOtp doc `verified: true` on a correct code, which /api/user/signup
// below checks before creating the account. Wrong guesses are capped at
// OTP_MAX_ATTEMPTS so the 6-digit space can't just be brute-forced within the
// 5-minute window.
app.post('/api/user/signup/verify-otp', otpLimiter, async (req, res) => {
  try {
    const { email, otp } = req.body || {};
    if (!email || !otp) return res.status(400).json({ message: 'Email and code are required' });
    const cleanEmail = String(email).toLowerCase().trim();

    const record = await EmailOtp.findOne({ email: cleanEmail });
    if (!record) return res.status(400).json({ message: 'Code expired or not found. Please request a new one.' });
    if (record.attempts >= OTP_MAX_ATTEMPTS) {
      return res.status(429).json({ message: 'Too many incorrect attempts. Please request a new code.' });
    }

    const match = await bcrypt.compare(String(otp).trim(), record.otpHash);
    if (!match) {
      record.attempts += 1;
      await record.save();
      return res.status(400).json({ message: 'Incorrect code. Please try again.' });
    }

    record.verified = true;
    await record.save();
    return res.json({ message: 'Email verified' });
  } catch (err) {
    console.error('Verify signup OTP error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ── User Signup ──
app.post('/api/user/signup', userAuthLimiter, async (req, res) => {
  try {
    const { firstName, lastName, email, mobile, password, confirmPassword } = req.body || {};

    if (!firstName || !String(firstName).trim()) return res.status(400).json({ message: 'First name is required' });
    if (!lastName  || !String(lastName).trim())  return res.status(400).json({ message: 'Last name is required' });
    if (!email     || !String(email).trim())     return res.status(400).json({ message: 'Email is required' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).trim())) return res.status(400).json({ message: 'Please enter a valid email address' });
    if (!mobile    || !String(mobile).trim())    return res.status(400).json({ message: 'Mobile number is required' });
    if (!/^[\d+\-\s]{7,15}$/.test(String(mobile).trim())) return res.status(400).json({ message: 'Please enter a valid mobile number' });
    if (!password || password.length < 6) return res.status(400).json({ message: 'Password must be at least 6 characters' });
    if (password !== confirmPassword) return res.status(400).json({ message: 'Passwords do not match' });

    const cleanEmail  = String(email).toLowerCase().trim();
    const cleanMobile = String(mobile).trim();

    const [existingEmail, existingMobile] = await Promise.all([
      User.findOne({ email: cleanEmail }),
      User.findOne({ mobile: cleanMobile }),
    ]);
    if (existingEmail)  return res.status(409).json({ message: 'Account already exists for this email. Please log in.' });
    if (existingMobile) return res.status(409).json({ message: 'Account already exists for this mobile number. Please log in.' });

    // Email must have gone through the OTP flow above and come back verified —
    // this is what actually stops an account from being created on an email the
    // person doesn't own. The OTP doc still carries its original 5-minute TTL,
    // so this also enforces "finish signup shortly after verifying".
    const otpRecord = await EmailOtp.findOne({ email: cleanEmail, verified: true });
    if (!otpRecord) return res.status(403).json({ message: 'Please verify your email with the code we sent before continuing.' });

    const hashed = await bcrypt.hash(password, 10);
    const userId = await nextSequenceId('USER');
    const name = `${String(firstName).trim()} ${String(lastName).trim()}`.trim();
    const user = await User.create({
      firstName: String(firstName).trim(),
      lastName:  String(lastName).trim(),
      name,
      email:     cleanEmail,
      mobile:    cleanMobile,
      password:  hashed,
      userId,
    });
    const userKey = await issueUserSession(user);
    await EmailOtp.deleteOne({ email: cleanEmail }); // one-time use — clear it now that the account exists
    return res.status(201).json({
      message: 'Account created successfully',
      _id: user._id, userId: user.userId,
      firstName: user.firstName, lastName: user.lastName, name: user.name,
      email: user.email, mobile: user.mobile,
      userKey,
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ── User Login ──
app.post('/api/user/login', userAuthLimiter, async (req, res) => {
  try {
    const { contact, password } = req.body || {};
    if (!contact || !password) return res.status(400).json({ message: 'Please enter your details' });

    // 'contact' is whatever the person typed into the single "Phone or email"
    // field — figure out which one it is and match the corresponding column.
    const identifier = String(contact).toLowerCase().trim();
    const query = identifier.includes('@') ? { email: identifier } : { mobile: identifier };
    const user = await User.findOne(query);
    if (!user) return res.status(401).json({ message: 'No account found. Please sign up.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Incorrect password' });

    const userKey = await issueUserSession(user);
    return res.json({
      message: 'Logged in successfully',
      _id: user._id, userId: user.userId,
      firstName: user.firstName, lastName: user.lastName, name: user.name,
      email: user.email, mobile: user.mobile,
      userKey,
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ── User Logout ──
app.post('/api/user/logout', async (req, res) => {
  try {
    const key = (req.headers['x-user-key'] || '').toString();
    await UserSession.deleteOne({ key });
    res.json({ message: 'Logged out' });
  } catch (err) {
    console.error('User logout error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ── GET current user profile ──
app.get('/api/user/me', requireUser, async (req, res) => {
  try {
    const user = await User.findById(req.userId).lean();
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({
      _id: user._id, userId: user.userId || '',
      firstName: user.firstName || '', lastName: user.lastName || '', name: user.name || '',
      email: user.email || '', mobile: user.mobile || '',
      createdAt: user.createdAt,
    });
  } catch (err) {
    console.error('GET /api/user/me error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ── UPDATE current user profile (name / email / mobile) ──
app.put('/api/user/me', requireUser, async (req, res) => {
  try {
    const { name, email, mobile } = req.body || {};
    const update = {};
    if (name !== undefined) update.name = String(name).trim();
    if (email !== undefined) {
      const cleanEmail = String(email).toLowerCase().trim();
      if (!cleanEmail) return res.status(400).json({ message: 'Email cannot be empty' });
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) return res.status(400).json({ message: 'Please enter a valid email address' });
      const existing = await User.findOne({ email: cleanEmail, _id: { $ne: req.userId } });
      if (existing) return res.status(409).json({ message: 'That email is already in use by another account' });
      update.email = cleanEmail;
    }
    if (mobile !== undefined) {
      const cleanMobile = String(mobile).trim();
      if (!cleanMobile) return res.status(400).json({ message: 'Mobile number cannot be empty' });
      const existing = await User.findOne({ mobile: cleanMobile, _id: { $ne: req.userId } });
      if (existing) return res.status(409).json({ message: 'That mobile number is already in use by another account' });
      update.mobile = cleanMobile;
    }
    const user = await User.findByIdAndUpdate(req.userId, update, { new: true });
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'Profile updated', _id: user._id, name: user.name || '', email: user.email || '', mobile: user.mobile || '' });
  } catch (err) {
    console.error('PUT /api/user/me error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ── CHANGE password ──
app.put('/api/user/password', requireUser, userAuthLimiter, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) return res.status(400).json({ message: 'Current and new password are required' });
    if (newPassword.length < 6) return res.status(400).json({ message: 'New password must be at least 6 characters' });

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) return res.status(401).json({ message: 'Current password is incorrect' });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('PUT /api/user/password error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// Middleware to protect admin-only API routes.
// Apply this to any route you want to require a valid session for, e.g.:
//   app.delete('/api/properties/:id', requireAdmin, async (req, res) => {...})
async function requireAdmin(req, res, next) {
  try {
    const key = (req.headers['x-admin-key'] || '').toString();
    if (!(await isValidAdminSession(key))) {
      return res.status(401).json({ message: 'Not authenticated' });
    }
    next();
  } catch (err) {
    console.error('requireAdmin error:', err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
}
// ────────────────────────────────────────────────────────────────────────────

// ── MongoDB ──
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// ── Property Schema (nested, matches the listing-submission payload shape) ──
const BasicSchema = new mongoose.Schema({
  status:    { type: String, enum: ['For Sale','For Rent','New Launch','Sold','Booked','Lease','PG','Short Stay'], default: 'For Rent' },
  listedBy:  { type: String, default: 'Owner' },
}, { _id: false });

const LocationSchema = new mongoose.Schema({
  area:    { type: String, required: true },
  city:    { type: String, default: 'Bengaluru' },
  address: { type: String, default: '' },
  lat:     { type: Number, default: null },
  lng:     { type: Number, default: null },
  mapLink: { type: String, default: '' },
}, { _id: false });

const OwnerSchema = new mongoose.Schema({
  propertyName: { type: String, required: true },
  name:         { type: String, default: '' },
  phone:        { type: String, default: '' },
  email:        { type: String, default: '' },
  altPhone:     { type: String, default: '' },
  contactTime:  { type: String, default: '' },
  address:      { type: String, default: '' },
  agentPhone:   { type: String, default: '' },
  agentArea:    { type: String, default: '' },
}, { _id: false });

const PriceSchema = new mongoose.Schema({
  rent:         { type: Number, required: true },
  deposit:      { type: Number, default: null },
  monthlyRent:  { type: Number }, // Legacy field — no form sends this anymore (not even Lease); no default so it no longer appears on newly saved listings
  maintenance:  { type: Number, default: null }, // Not collected for PG or Short Stay listings (form hides this field for both) — sent as null
  rentIncrease: { type: String, default: null }, // Legacy field — Lease's "Rent escalation" dropdown was removed from the form; kept only to preserve older saved listings, new submissions send null
  electricity:  { type: String, default: null }, // Not collected for PG or Short Stay listings (form hides this field for both) — sent as null
  water:        { type: String, default: null }, // Not collected for PG or Short Stay listings (form hides this field for both) — sent as null
  negotiable:   { type: String, default: null }, // 'Yes' | 'No' | null (not answered)
}, { _id: false });

const PropertyDetailsSchema = new mongoose.Schema({
  type:      { type: String, default: null },   // propertyType (Apartment/Villa/etc.)
  bhk:       { type: String, default: null },
  bike:      { type: String, default: '0' },    // bikeparking: count as string, e.g. '0'..'4'
  car:       { type: String, default: '0' },    // carparking:  count as string, e.g. '0'..'4'
  floor:     { type: String, default: 'G' },
  area:      { type: String, default: null },
  bathrooms: { type: String, default: '1' },     // toilet
  furnish:   { type: String, default: 'Unfurnished' }, // furnishing
  facing:    { type: String, default: 'North' },
  age:       { type: String, default: null },
  tenant:    { type: String, default: 'Any' },   // tenantPref
  available: { type: String, default: null },    // availableFrom
}, { _id: false });

const AmenitiesSchema = new mongoose.Schema({
  selected: { type: [String], default: [] },
  extra:    { type: String, default: '' },
}, { _id: false });

const TermsSchema = new mongoose.Schema({
  notice:    { type: String, default: null }, // noticePeriod / leaseNotice / pgNotice
  lease:     { type: String, default: null }, // leaseDuration (Rent) / leaseDurationVal (Lease)
  leaseType: { type: String }, // Lease only: Residential / Commercial / Industrial / Mixed Use — no default, so Rent (and other non-Lease) listings omit this field entirely
  lockIn:    { type: String }, // Lease only: lock-in period — no default, so Rent (and other non-Lease) listings omit this field entirely
}, { _id: false });

const RulesSchema = new mongoose.Schema({
  pets:   { type: String, default: null }, // petsAllowed / leasePets — PG's "Pets allowed" field was removed from the form, so PG listings always send null here now
  nonVeg: { type: String, default: null }, // nonVegAllowed / leaseNonVeg / pgNonVeg
  gas:    { type: String }, // No longer sent by the Rent form (or any form) — no default, so it's omitted entirely from newly saved listings
}, { _id: false });

const MediaSchema = new mongoose.Schema({
  video:  { type: String, default: '' },
  desc:   { type: String, default: '' },
  images: { type: [String], default: [] },
}, { _id: false });

const PgSchema = new mongoose.Schema({
  gender:        { type: String, default: null },
  room:          { type: String, default: null }, // pgRoomType
  meals:         { type: String, default: null }, // pgMeals
  occupancy:     { type: String, default: null },
  notice:        { type: String, default: null }, // pgNotice (also mirrored into terms.notice)
  bathroom:      { type: String, default: null },
  mealCost:      { type: Number, default: null }, // Legacy field — "Meals cost" input was removed from the PG form; kept only to preserve older saved listings, new submissions send null
  beds:          { type: String, default: null }, // Legacy field — "Total beds" input was removed from the PG form; kept only to preserve older saved listings, new submissions send null
  furnish:       { type: String, default: null }, // pgRoomFurnishing
  food:          { type: String, default: null }, // pgFoodType
  kitchen:       { type: String, default: null }, // pgKitchenAccess
  available:     { type: String, default: null }, // pgAvailableFrom
  visitors:      { type: String, default: null }, // pgVisitorPolicy
  gateTime:      { type: String, default: null },
  nonVeg:        { type: String, default: null },
  pets:          { type: String, default: null }, // Legacy field — "Pets allowed" input was removed from the PG form; kept only to preserve older saved listings, new submissions send null
}, { _id: false });

const ShortStaySchema = new mongoose.Schema({
  roomType:       { type: String, default: null }, // ssRoomType (Single/Double/Deluxe/Suite)
  maxGuests:      { type: String, default: null }, // ssMaxGuests
  minDays:        { type: String, default: null }, // ssMinDays
  checkinTime:    { type: String, default: null }, // ssCheckinTime, e.g. '12:00'
  checkoutTime:   { type: String, default: null }, // ssCheckoutTime, e.g. '11:00'
  extraDayRate:   { type: Number, default: null }, // ssExtraDayRate
  cancellation:   { type: String, default: null }, // ssCancellation
  idProof:        { type: String, default: null }, // ssIdProof (Yes/No)
  couplesAllowed: { type: String, default: null }, // ssCouples (Yes/No)
}, { _id: false });

// ── Counter (atomic per-type sequence for human-readable property IDs) ──
// Using a dedicated collection with $inc (rather than e.g. Property.countDocuments()+1)
// so two simultaneous submissions can never be handed the same number.
const CounterSchema = new mongoose.Schema({
  _id: { type: String, required: true }, // e.g. 'RENT' | 'LEASE' | 'PG'
  seq: { type: Number, default: 0 },
}, { _id: false });
const Counter = mongoose.model('Counter', CounterSchema);


// Generic version of the same atomic-counter trick, reused below for
// visitId (VisitRequest) and userId (User) — same Counter collection,
// keyed by whatever prefix is passed in, so each entity type counts
// independently of the others.
async function nextSequenceId(prefix) {
  const counter = await Counter.findOneAndUpdate(
    { _id: prefix },
    { $inc: { seq: 1 } },
    { new: true, upsert: true }
  );
  return `${prefix}-${String(counter.seq).padStart(6, '0')}`; // e.g. RENT-000123
}

async function nextPropertyId() {
  // Random alphanumeric code (e.g. AAA123) instead of a sequential, type-prefixed
  // counter. IDs are generated randomly rather than incremented, so we retry on
  // the rare collision instead of relying on Counter's atomic $inc.
  const LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const DIGITS = '0123456789';
  const randomCode = () => {
    let code = '';
    for (let i = 0; i < 3; i++) code += LETTERS[Math.floor(Math.random() * LETTERS.length)];
    for (let i = 0; i < 3; i++) code += DIGITS[Math.floor(Math.random() * DIGITS.length)];
    return code;
  };
  let id, exists = true, attempts = 0;
  while (exists && attempts < 10) {
    id = randomCode();
    const [inRent, inLease, inPg, inHourlyStay] = await Promise.all([
      Rent.exists({ propertyId: id }),
      Lease.exists({ propertyId: id }),
      Pg.exists({ propertyId: id }),
      HourlyStay.exists({ propertyId: id }),
    ]);
    exists = !!(inRent || inLease || inPg || inHourlyStay);
    attempts++;
  }
  return id;
}

// ────────────────────────────────────────────────────────────────────────────
// ── LISTING MODELS: split across four collections by category ──
// A listing is stored in exactly one of four collections based on its
// basic.status: 'Lease' → the `lease` collection, 'PG' → the `pg` collection,
// 'Short Stay' → the `hourlyStay` collection, and everything else (For Rent /
// For Sale / New Launch / Sold / Booked) → the `rent` collection. All four
// share the identical schema shape below — only the collection (and therefore
// the Mongoose model) differs — so a listing's category can be switched later
// by moving the document between models (see moveListingIfNeeded below)
// rather than needing a migration.
// ────────────────────────────────────────────────────────────────────────────
function buildListingSchema() {
  const schema = new mongoose.Schema({
    basic:      { type: BasicSchema,            required: true },
    location:   { type: LocationSchema,         required: true },
    owner:      { type: OwnerSchema,            required: true },
    price:      { type: PriceSchema,            required: true },
    property:   { type: PropertyDetailsSchema,  default: () => ({}) },
    amenities:  { type: AmenitiesSchema,        default: () => ({}) },
    terms:      { type: TermsSchema,            default: () => ({}) },
    rules:      { type: RulesSchema,            default: () => ({}) },
    media:      { type: MediaSchema,            default: () => ({}) },
    pg:         { type: PgSchema }, // no default — left unset for non-PG listings so we don't store an all-null subdocument
    shortStay:  { type: ShortStaySchema }, // no default — left unset for non-Short-Stay listings, same reasoning as pg above
    // ── Meta (kept top-level / flat — not part of the submitted payload) ──
    propertyId:       { type: String, unique: true, sparse: true, index: true }, // random alphanumeric code, e.g. AAA123
    userId:           { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true }, // owner of this listing, null = posted while logged out
    userReadableId:   { type: String, default: null, index: true }, // human-readable User.userId (e.g. USER-000001), stamped at creation for admin readability — same pattern as UserSession.userId
    verified:         { type: Boolean, default: false },
    promoted:         { type: Boolean, default: false },
    promotedPriority: { type: Number,  default: 3 },
    views:            { type: Number,  default: 0 },
    visitCount:       { type: Number,  default: 0 }, // # of "Schedule a Visit" requests made for this listing
    bookingCount:     { type: Number,  default: 0 }, // # of direct "Book Now" requests made for this listing (Short Stay only)
    remarks:          { type: [String], default: [] }, // admin-panel notes
    createdAt:        { type: Date,    default: Date.now },
  });
  schema.index({ createdAt: -1 });
  schema.index({ 'basic.status': 1, createdAt: -1 });
  return schema;
}

// Explicit 3rd arg pins the exact collection name — 'rent' / 'lease' / 'pg' /
// 'hourlyStay' — instead of Mongoose's default pluralization.
const Rent       = mongoose.model('Rent',       buildListingSchema(), 'rent');
const Lease      = mongoose.model('Lease',      buildListingSchema(), 'lease');
const Pg         = mongoose.model('Pg',         buildListingSchema(), 'pg');
const HourlyStay = mongoose.model('HourlyStay', buildListingSchema(), 'hourlyStay');

// Keyed by the same names used for VisitRequest.propertyType (refPath target).
const LISTING_MODELS = { Rent, Lease, Pg, HourlyStay };
const LISTING_MODEL_LIST = Object.values(LISTING_MODELS);

// A listing's basic.status decides which collection it belongs in.
function modelForStatus(status) {
  if (status === 'Lease')      return Lease;
  if (status === 'PG')         return Pg;
  if (status === 'Short Stay') return HourlyStay;
  return Rent; // For Rent, For Sale, New Launch, Sold, Booked
}
// Finds a listing by Mongo _id without knowing in advance which of the four
// collections it lives in — tries all four in parallel (a given ObjectId can
// only ever exist in one, since each collection mints its own _ids).
async function findListingById(id, { lean = false } = {}) {
  if (!mongoose.Types.ObjectId.isValid(id)) return { doc: null, model: null, type: null };
  const types = Object.keys(LISTING_MODELS);
  const results = await Promise.all(types.map(t => {
    const q = LISTING_MODELS[t].findById(id);
    return lean ? q.lean() : q;
  }));
  for (let i = 0; i < types.length; i++) {
    if (results[i]) return { doc: results[i], model: LISTING_MODELS[types[i]], type: types[i] };
  }
  return { doc: null, model: null, type: null };
}

// Same idea, scoped to a specific owner — used by the user-owned-listing routes.
async function findUserListingById(id, userId, { lean = false } = {}) {
  if (!mongoose.Types.ObjectId.isValid(id)) return { doc: null, model: null, type: null };
  const types = Object.keys(LISTING_MODELS);
  const results = await Promise.all(types.map(t => {
    const q = LISTING_MODELS[t].findOne({ _id: id, userId });
    return lean ? q.lean() : q;
  }));
  for (let i = 0; i < types.length; i++) {
    if (results[i]) return { doc: results[i], model: LISTING_MODELS[types[i]], type: types[i] };
  }
  return { doc: null, model: null, type: null };
}

// Tries findByIdAndUpdate against each collection in turn, stopping at the
// first hit — used by the admin verified/promoted toggles, which only have
// an _id to go on.
async function updateListingById(id, update, options = { new: true }) {
  if (!mongoose.Types.ObjectId.isValid(id)) return null;
  for (const M of LISTING_MODEL_LIST) {
    const result = await M.findByIdAndUpdate(id, update, options);
    if (result) return result;
  }
  return null;
}

async function deleteListingById(id) {
  if (!mongoose.Types.ObjectId.isValid(id)) return null;
  for (const M of LISTING_MODEL_LIST) {
    const deleted = await M.findByIdAndDelete(id);
    if (deleted) return deleted;
  }
  return null;
}

// If an edit changes basic.status into a different category (e.g. Rent →
// Lease), the document needs to move to the matching collection rather than
// just being saved in place. Re-creates it in the target collection with the
// same _id and deletes the original; returns the (possibly new) document.
async function moveListingIfNeeded(doc, currentModel) {
  const targetModel = modelForStatus(doc.basic && doc.basic.status);
  if (targetModel === currentModel) {
    await doc.save();
    return doc;
  }
  const plain = doc.toObject();
  const moved = new targetModel(plain); // same _id, since plain._id is preserved
  await moved.save();
  await currentModel.findByIdAndDelete(doc._id);
  return moved;
}

// ── Visit Request Schema (from the "Schedule a Visit" modal) ──
const VisitRequestSchema = new mongoose.Schema({
  // Human-readable unique id, same pattern as Property.propertyId (e.g. VISIT-000001).
  visitId:      { type: String, unique: true, sparse: true, index: true },
  propertyId:   { type: mongoose.Schema.Types.ObjectId, refPath: 'propertyType', required: true, index: true },
  // Which of the three listing collections propertyId points into — stamped
  // at creation (see POST /api/visits) so populate() can resolve it dynamically.
  propertyType: { type: String, enum: ['Rent', 'Lease', 'Pg', 'HourlyStay'], default: 'Rent' },
  userId:       { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  userReadableId: { type: String, default: null, index: true }, // human-readable User.userId (e.g. USER-000001), stamped at creation for admin readability — same pattern as UserSession.userId
  visitorName:  { type: String, required: true, trim: true },
  visitorPhone: { type: String, required: true, trim: true },
  email:        { type: String, default: '', trim: true, lowercase: true }, // preloaded from the logged-in user's account email
  note:         { type: String, default: '', trim: true },
  visitDate:    { type: String, required: true }, // 'YYYY-MM-DD'
  visitTime:    { type: String, required: true }, // 'HH:MM'
  status:       { type: String, enum: ['Pending', 'Confirmed', 'Cancelled', 'Completed'], default: 'Pending' },
  remarks:      { type: [RemarkEntrySchema], default: [] },
  createdAt:    { type: Date, default: Date.now },
});
VisitRequestSchema.index({ createdAt: -1 });
// Speeds up the duplicate-visit lookup in POST /api/visits (same user + property + date).
VisitRequestSchema.index({ userId: 1, propertyId: 1, visitDate: 1 });
const VisitRequest = mongoose.model('VisitRequest', VisitRequestSchema);

// ── Booking Request Schema (from the "Book Now" modal — Short Stay direct booking) ──
const BookingRequestSchema = new mongoose.Schema({
  // Human-readable unique id, same pattern as VisitRequest.visitId (e.g. BOOKING-000001).
  bookingId:    { type: String, unique: true, sparse: true, index: true },
  propertyId:   { type: mongoose.Schema.Types.ObjectId, refPath: 'propertyType', required: true, index: true },
  // Which listing collection propertyId points into — stamped at creation
  // (see POST /api/bookings) so populate() can resolve it dynamically.
  // In practice this is always 'HourlyStay' today, since Book Now only appears
  // on Short Stay cards, but kept as an enum (matching VisitRequest's pattern)
  // in case direct booking is ever offered on another listing type.
  propertyType: { type: String, enum: ['Rent', 'Lease', 'Pg', 'HourlyStay'], default: 'HourlyStay' },
  userId:       { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  userReadableId: { type: String, default: null, index: true }, // human-readable User.userId (e.g. USER-000001), stamped at creation for admin readability
  guestName:    { type: String, required: true, trim: true },
  guestPhone:   { type: String, required: true, trim: true },
  email:        { type: String, default: '', trim: true, lowercase: true }, // preloaded from the logged-in user's account email
  note:         { type: String, default: '', trim: true },
  checkinDate:  { type: String, required: true }, // 'YYYY-MM-DD'
  days:         { type: Number, required: true, min: 1 },
  guests:       { type: Number, default: 1, min: 1 },
  status:       { type: String, enum: ['Pending', 'Confirmed', 'Cancelled', 'Completed'], default: 'Pending' },
  remarks:      { type: [RemarkEntrySchema], default: [] },
  createdAt:    { type: Date, default: Date.now },
});
BookingRequestSchema.index({ createdAt: -1 });
// Speeds up the duplicate-booking lookup in POST /api/bookings (same user + property + check-in date).
BookingRequestSchema.index({ userId: 1, propertyId: 1, checkinDate: 1 });
const BookingRequest = mongoose.model('BookingRequest', BookingRequestSchema);

// ── Notification Schema (in-app notifications for logged-in users) ──
// Fired whenever an admin action changes something a user is waiting on:
// a listing gets verified, a submitted Honest Review video gets approved,
// or a Schedule-a-Visit request changes status. Read via GET
// /api/user/notifications and the unread badge polls /unread-count.
const NotificationSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type:      { type: String, enum: ['property_verified', 'review_approved', 'visit_status'], required: true },
  title:     { type: String, required: true },
  message:   { type: String, required: true },
  read:      { type: Boolean, default: false, index: true },
  meta:      { type: mongoose.Schema.Types.Mixed, default: {} }, // e.g. { propertyId, visitId, status }
  createdAt: { type: Date, default: Date.now },
});
NotificationSchema.index({ userId: 1, createdAt: -1 });
const Notification = mongoose.model('Notification', NotificationSchema);

// Best-effort notification creation — never lets a notification failure
// break the admin action that triggered it. No-op if userId is null (e.g.
// a listing posted while logged out has no owner to notify).
async function notifyUser(userId, { type, title, message, meta }) {
  if (!userId) return;
  try {
    await Notification.create({ userId, type, title, message, meta: meta || {} });
  } catch (err) {
    console.error('notifyUser error:', err.message);
  }
}

// ── Helpers ──
function formatPrice(price, status) {
  const num = Number(price);
  let display = '';
  if      (num >= 10000000) display = (num / 10000000).toFixed(2).replace(/\.?0+$/, '') + 'Cr';
  else if (num >= 100000)   display = (num / 100000).toFixed(1).replace(/\.?0+$/, '') + 'L';
  else if (num >= 1000)     display = (num / 1000).toFixed(1).replace(/\.?0+$/, '') + 'K';
  else                      display = String(num);
  if (status === 'Short Stay') display += '/Day';
  else if (['For Rent', 'Lease', 'PG'].includes(status)) display += '/Month';
  return display;
}

// Formats a Date as 'dd-mm-yyyy hh:mm AM/PM' in IST, e.g. '30-06-2026 02:30 PM'.
function formatPostedDateTime(date) {
  const d = new Date(date);
  const parts = new Intl.DateTimeFormat('en-IN', {
    timeZone: 'Asia/Kolkata',
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: true
  }).formatToParts(d);
  const get = (type) => parts.find(p => p.type === type)?.value || '';
  const dayPart   = get('day');
  const monthPart = get('month');
  const yearPart  = get('year');
  const hourPart  = get('hour');
  const minPart   = get('minute');
  const ampm      = get('dayPeriod').toUpperCase();
  return `${dayPart}-${monthPart}-${yearPart} ${hourPart}:${minPart} ${ampm}`;
}

// Top-level keys accepted from the client, matching the nested submission shape exactly.
const NESTED_SECTIONS = ['basic','location','owner','price','property','amenities','terms','rules','media','pg','shortStay'];

const URL_FIELDS_BY_SECTION = { location: ['mapLink'], media: ['video'] };
const MAX_LENGTHS = {
  'owner.propertyName': 200,
  'media.desc':         5000,
  'location.area':      200,
  'location.address':   500,
  'owner.name':         100,
  'owner.address':      300,
  'owner.contactTime':  100,
};

function validatePropertyFields(fields) {
  for (const [section, urlKeys] of Object.entries(URL_FIELDS_BY_SECTION)) {
    const obj = fields[section] || {};
    for (const k of urlKeys) {
      const val = obj[k];
      if (val && String(val).trim()) {
        let parsed;
        try { parsed = new URL(String(val).trim()); } catch { return `Invalid URL in field '${section}.${k}'.`; }
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
          return `Field '${section}.${k}' must be an http(s) URL.`;
        }
      }
    }
  }
  for (const [path, max] of Object.entries(MAX_LENGTHS)) {
    const [section, key] = path.split('.');
    const val = (fields[section] || {})[key];
    if (val && String(val).length > max)
      return `Field '${path}' must be at most ${max} characters.`;
  }
  const email = (fields.owner || {}).email;
  if (email && String(email).trim() &&
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).trim()))
    return `Invalid email address in field 'owner.email'.`;

  const images = (fields.media || {}).images;
  if (images !== undefined) {
    if (!Array.isArray(images)) return `Field 'media.images' must be an array.`;
    if (images.length > 20) return `Field 'media.images' must have at most 20 images.`;
    for (const img of images) {
      if (typeof img !== 'string' || !img.trim()) return `Field 'media.images' contains an invalid entry.`;
      const val = img.trim();
      if (val.startsWith('/uploads/')) continue; // our own upload endpoint returns relative paths — allow as-is
      let parsed;
      try { parsed = new URL(val); } catch { return `Field 'media.images' contains an invalid URL.`; }
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return `Field 'media.images' must contain only http(s) URLs.`;
      }
    }
  }

  return null;
}

// ────────────────────────────────────────────────────────────────────────────
// ── REQUIRED-FIELD ENFORCEMENT ──
// The listing form now marks nearly every field mandatory client-side, but a
// client-side check can always be bypassed (a direct API call, a modified
// request, etc.) — so the same requiredness is enforced again here before
// anything is written to Mongo. Fields intentionally left null for a given
// listing type (e.g. property.bhk for a PG, price.deposit for a Lease — the
// form hides those inputs entirely for that type) are NOT required for that
// type; only fields the form actually shows are enforced, matching the
// per-status field visibility in onFTypeChange() on the frontend.
// ────────────────────────────────────────────────────────────────────────────
function getPath(obj, path) {
  return path.split('.').reduce((o, k) => (o == null ? o : o[k]), obj);
}
function isEmptyValue(v) {
  return v === undefined || v === null || (typeof v === 'string' && v.trim() === '');
}

// Required for every listing type — propertyName/area/price.rent are already
// checked (with a type-specific label) right before this runs, so they're
// deliberately left out here to avoid a duplicate message.
const BASE_REQUIRED_FIELDS = [
  ['location.city',     'Location: City'],
  ['location.address',  'Location: Building live address'],
  ['location.mapLink',  'Location: Google Maps link'],
  ['owner.name',        'Owner name'],
  ['owner.phone',       'Owner phone number'],
  ['owner.email',       'Owner email'],
  ['owner.altPhone',    'Owner alternate number'],
  ['owner.contactTime', 'Preferred contact time'],
  ['owner.address',     'Owner address'],
  ['media.desc',        'Description'],
  ['media.video',       'Video tour URL'],
];

// Extra fields required only for the listing types whose form section
// actually shows them.
const TYPE_REQUIRED_FIELDS = {
  'For Rent': [
    ['price.deposit',      'Security deposit'],
    ['price.maintenance',  'Maintenance'],
    ['price.negotiable',   'Price negotiable'],
    ['property.type',      'Property type'],
    ['property.bhk',       'BHK'],
    ['property.floor',     'Floor'],
    ['property.area',      'Area (sqft)'],
    ['property.age',       'Age of property'],
    ['property.available', 'Available from'],
    ['terms.lease',        'Lease duration'],
    ['rules.pets',         'Pets allowed'],
    ['rules.nonVeg',       'Non-veg allowed'],
  ],
  'Lease': [
    ['price.maintenance',  'Maintenance'],
    ['property.type',      'Property type'],
    ['property.bhk',       'BHK'],
    ['property.floor',     'Floor'],
    ['property.area',      'Area (sqft)'],
    ['property.available', 'Available from'],
    ['terms.leaseType',    'Lease type'],
    ['rules.pets',         'Pets allowed'],
    ['rules.nonVeg',       'Non-veg allowed'],
  ],
  'PG': [
    ['pg.meals',     'Meals'],
    ['pg.occupancy', 'Occupancy available'],
    ['pg.bathroom',  'Attached bathroom'],
    ['pg.furnish',   'Room furnishing'],
    ['pg.kitchen',   'Kitchen access'],
    ['pg.available', 'Available from'],
    ['pg.visitors',  'Visitor policy'],
    ['pg.nonVeg',    'Non-veg allowed'],
    ['pg.food',      'Food type'],
  ],
  'Short Stay': [
    ['shortStay.maxGuests',      'Max guests'],
    ['shortStay.minDays',        'Minimum stay (days)'],
    ['shortStay.checkinTime',    'Check-in time'],
    ['shortStay.checkoutTime',   'Check-out time'],
    ['shortStay.cancellation',   'Free cancellation window'],
    ['shortStay.idProof',        'ID proof required'],
    ['shortStay.couplesAllowed', 'Unmarried couples allowed'],
  ],
};

// Returns a list of human-readable labels for every required field that's
// missing/empty for this listing's status — empty array means nothing's missing.
function findMissingRequiredFields(fields, status) {
  const required = BASE_REQUIRED_FIELDS.concat(TYPE_REQUIRED_FIELDS[status] || []);
  if ((fields.basic || {}).listedBy === 'Agent') {
    required.push(['owner.agentPhone', 'Agent phone number'], ['owner.agentArea', 'Agent service area']);
  }
  const missing = required.filter(([path]) => isEmptyValue(getPath(fields, path)));
  const labels = missing.map(([, label]) => label);
  const images = (fields.media || {}).images;
  if (!Array.isArray(images) || images.length === 0) labels.push('Property images');
  return labels;
}

// ── Rate limiter ──
const listingLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  message: { message: 'Too many listing submissions. Please try again later.' }
});

// ── POST /api/properties ──
app.post('/api/properties', listingLimiter, requireUser, async (req, res) => {
  try {
    const body = req.body || {};
    const fields = NESTED_SECTIONS.reduce((acc, k) => {
      acc[k] = (body[k] && typeof body[k] === 'object') ? body[k] : {};
      return acc;
    }, {});

    const validationError = validatePropertyFields(fields);
    if (validationError) return res.status(400).json({ message: validationError });

    fields.basic = Object.assign({ status: 'For Rent', listedBy: 'Owner' }, fields.basic);
    fields.media.displayPrice = undefined; // not part of media; computed separately below

    const status = fields.basic.status;

    // Fields required by every listing type, with a type-appropriate label in the error message
    // (price.rent doubles as "monthly rent" for Rent, "lease amount" for Lease, "monthly charge" for PG,
    // "per day rate" for Short Stay).
    const priceLabel = status === 'Lease'      ? 'price.rent (lease amount)'
                      : status === 'PG'         ? 'price.rent (monthly charge)'
                      : status === 'Short Stay' ? 'price.rent (per day rate)'
                      :                           'price.rent (monthly rent)';
    if (!fields.owner.propertyName || !fields.location.area ||
        fields.price.rent === undefined || fields.price.rent === null || fields.price.rent === '') {
      return res.status(400).json({ message: `owner.propertyName, location.area, and ${priceLabel} are required.` });
    }

    // Fields required only for specific listing types.
    if (status === 'PG' && (!fields.pg.gender || !fields.pg.room)) {
      return res.status(400).json({ message: 'pg.gender and pg.room are required for PG listings.' });
    }
    if (status === 'Lease' && !fields.terms.lease) {
      return res.status(400).json({ message: 'terms.lease (lease duration) is required for Lease listings.' });
    }
    if (status === 'Short Stay' && !fields.shortStay.roomType) {
      return res.status(400).json({ message: 'shortStay.roomType is required for Short Stay listings.' });
    }

    // Every other field the form shows for this listing type must be filled
    // in too — reject the whole request rather than silently storing nulls.
    const missingFields = findMissingRequiredFields(fields, status);
    if (missingFields.length) {
      return res.status(400).json({ message: `Please fill in all required fields: ${missingFields.join(', ')}.` });
    }

    const displayPrice = formatPrice(fields.price.rent, status);
    const propertyId = await nextPropertyId();

    const ListingModel = modelForStatus(status); // Rent, Lease, Pg, or HourlyStay — decided by basic.status
    const prop = new ListingModel({
      propertyId,
      userId:         req.userId || null, // links the listing to its creator when logged in
      userReadableId: req.userReadableId || null, // e.g. USER-000001, for admin readability
      basic:     fields.basic,
      location:  fields.location,
      owner:     fields.owner,
      price:     fields.price,
      property:  fields.property,
      amenities: fields.amenities,
      terms:     fields.terms,
      rules:     fields.rules,
      media:     fields.media,
      pg:        status === 'PG' ? fields.pg : undefined,
      shortStay: status === 'Short Stay' ? fields.shortStay : undefined,
    });
    await prop.save();

    const saved = prop.toObject();
    saved.displayPrice = displayPrice;

    res.status(201).json({ message: 'Property added successfully!', property: saved });
  } catch (err) {
    console.error('POST /api/properties error:', err);
    res.status(500).json({ message: 'Error saving property: ' + err.message });
  }
});

// ── GET /api/properties ──
app.get('/api/properties', async (req, res) => {
  try {
    const { status, q, limit = 100, skip = 0 } = req.query;
    const filter = { verified: true }; // a listing only appears to the public once admin has verified it
    if (status && typeof status === 'string') filter['basic.status'] = status;
    if (q && typeof q === 'string') {
      const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filter.$or = [{ 'owner.propertyName': re }, { 'location.area': re }, { 'media.desc': re }];
    }

    // Internal/admin-only fields — never read by the public frontend
    const PUBLIC_SELECT =
      '-remarks -userId -userReadableId -promotedPriority -__v ' +
      // Owner PII that only ever populated hidden form inputs in the read-only
      // detail view (VIEW_ALWAYS_HIDDEN_GROUPS on the frontend). owner.phone is
      // excluded too — Call/WhatsApp now read owner.agentPhone only (dynamically),
      // so the owner's personal number never needs to leave the server.
      // owner.propertyName excluded too (client-side search no longer matches on
      // it — search now matches area/BHK only). owner.agentPhone is kept for
      // Call/WhatsApp.
      '-owner.name -owner.propertyName -owner.email -owner.phone -owner.altPhone -owner.contactTime -owner.address -owner.agentArea ' +
      // Location detail that's likewise only used to fill the always-hidden
      // full-address/lat-lng/Google-Maps-link form groups
      '-location.address -location.lat -location.lng -location.mapLink';

    // If a status was requested, we already know exactly which single
    // collection to query. Otherwise we need to fan out to all four and
    // merge, since listings now live in separate rent/lease/pg/hourlyStay collections.
    const modelsToQuery = (status && typeof status === 'string')
      ? [modelForStatus(status)]
      : LISTING_MODEL_LIST;

    const docArrays = await Promise.all(
      modelsToQuery.map(M => M.find(filter).select(PUBLIC_SELECT).lean())
    );
    let docs = docArrays.flat();

    // Sort/paginate in memory across the merged set (same ordering as before:
    // promoted first, then promotedPriority, then newest).
    docs.sort((a, b) =>
      (Number(b.promoted) - Number(a.promoted)) ||
      ((a.promotedPriority ?? 3) - (b.promotedPriority ?? 3)) ||
      (new Date(b.createdAt) - new Date(a.createdAt))
    );
    docs = docs.slice(Number(skip), Number(skip) + Number(limit));

    // Attach id + computed displayPrice + posted label; the nested shape itself
    // (basic/location/owner/price/property/amenities/terms/rules/media/pg)
    // is returned as-is and read directly by the frontend.
    const mapped = docs.map(doc => ({
      ...doc,
      id:           String(doc._id),
      displayPrice: formatPrice((doc.price || {}).rent, (doc.basic || {}).status),
      posted:       doc.createdAt
                      ? formatPostedDateTime(doc.createdAt)
                      : 'Recently',
      verified:     !!doc.verified,
    }));

    res.json({ properties: mapped, total: mapped.length });
  } catch (err) {
    console.error('GET /api/properties error:', err);
    res.status(500).json({ message: 'Error fetching properties: ' + err.message });
  }
});

// ── POST /api/visits (Schedule a Visit modal) ──
const visitLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { message: 'Too many visit requests. Please try again later.' }
});

app.post('/api/visits', visitLimiter, requireUser, async (req, res) => {
  try {
    const { propertyId, visitorName, visitorPhone, email, note, visitDate, visitTime } = req.body || {};

    if (!propertyId || !mongoose.Types.ObjectId.isValid(propertyId)) {
      return res.status(400).json({ message: 'A valid propertyId is required' });
    }
    if (!visitorName || !String(visitorName).trim()) {
      return res.status(400).json({ message: 'Your name is required' });
    }
    if (!visitorPhone || !String(visitorPhone).trim()) {
      return res.status(400).json({ message: 'Your phone number is required' });
    }
    if (!visitDate || !/^\d{4}-\d{2}-\d{2}$/.test(visitDate)) {
      return res.status(400).json({ message: 'A valid visit date is required' });
    }
    if (!visitTime || !/^\d{2}:\d{2}$/.test(visitTime)) {
      return res.status(400).json({ message: 'A valid visit time is required' });
    }

    const { doc: property, model: propertyModel, type: propertyType } = await findListingById(propertyId, { lean: true });
    if (!property) return res.status(404).json({ message: 'Property not found' });

    // Block a second visit request from the same user for the same property on the
    // same date — regardless of the time slot chosen. A previously cancelled request
    // doesn't count, so the user can still rebook after cancelling.
    if (req.userId) {
      const duplicate = await VisitRequest.findOne({
        userId:     req.userId,
        propertyId,
        visitDate,
        status: { $ne: 'Cancelled' },
      }).lean();
      if (duplicate) {
        return res.status(409).json({ message: 'You already have a visit request for this property on this date. Please choose a different date, or cancel your existing request first.' });
      }
    }

    const visitId = await nextSequenceId('VISIT');

    const visit = await VisitRequest.create({
      visitId,
      propertyId,
      propertyType,
      userId:         req.userId || null,
      userReadableId: req.userReadableId || null, // e.g. USER-000001, for admin readability
      visitorName:  String(visitorName).trim(),
      visitorPhone: String(visitorPhone).trim(),
      email:        email ? String(email).trim().toLowerCase() : '',
      note:         note ? String(note).trim().slice(0, 1000) : '',
      visitDate,
      visitTime,
    });

    // Bump the property's visit-request counter. $inc is atomic, so concurrent
    // requests for the same property can't race and undercount each other.
    const updatedProperty = await propertyModel.findByIdAndUpdate(
      propertyId,
      { $inc: { visitCount: 1 } },
      { new: true, select: 'visitCount' }
    ).lean();

    res.status(201).json({
      message: 'Visit request saved',
      visit,
      visitCount: updatedProperty ? updatedProperty.visitCount : undefined,
    });
  } catch (err) {
    console.error('POST /api/visits error:', err);
    res.status(500).json({ message: 'Error saving visit request: ' + err.message });
  }
});

// ── POST /api/bookings (Book Now modal — Short Stay direct booking) ──
const bookingLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { message: 'Too many booking requests. Please try again later.' }
});

app.post('/api/bookings', bookingLimiter, requireUser, async (req, res) => {
  try {
    const { propertyId, guestName, guestPhone, email, note, checkinDate, days, guests } = req.body || {};

    if (!propertyId || !mongoose.Types.ObjectId.isValid(propertyId)) {
      return res.status(400).json({ message: 'A valid propertyId is required' });
    }
    if (!guestName || !String(guestName).trim()) {
      return res.status(400).json({ message: 'Your name is required' });
    }
    if (!guestPhone || !String(guestPhone).trim()) {
      return res.status(400).json({ message: 'Your phone number is required' });
    }
    if (!checkinDate || !/^\d{4}-\d{2}-\d{2}$/.test(checkinDate)) {
      return res.status(400).json({ message: 'A valid check-in date is required' });
    }
    const daysNum = parseInt(days, 10);
    if (!daysNum || daysNum < 1) {
      return res.status(400).json({ message: 'Number of days must be at least 1' });
    }
    const guestsNum = parseInt(guests, 10) || 1;

    const { doc: property, model: propertyModel, type: propertyType } = await findListingById(propertyId, { lean: true });
    if (!property) return res.status(404).json({ message: 'Property not found' });
    if (propertyType !== 'HourlyStay') {
      return res.status(400).json({ message: 'Direct booking is only available for Short Stay listings.' });
    }

    // Block a second booking from the same user for the same property on the
    // same check-in date. A previously cancelled booking doesn't count, so the
    // user can still rebook after cancelling.
    if (req.userId) {
      const duplicate = await BookingRequest.findOne({
        userId:      req.userId,
        propertyId,
        checkinDate,
        status: { $ne: 'Cancelled' },
      }).lean();
      if (duplicate) {
        return res.status(409).json({ message: 'You already have a booking for this property on this check-in date. Please choose a different date, or cancel your existing booking first.' });
      }
    }

    const bookingId = await nextSequenceId('BOOKING');

    const booking = await BookingRequest.create({
      bookingId,
      propertyId,
      propertyType,
      userId:         req.userId || null,
      userReadableId: req.userReadableId || null, // e.g. USER-000001, for admin readability
      guestName:  String(guestName).trim(),
      guestPhone: String(guestPhone).trim(),
      email:      email ? String(email).trim().toLowerCase() : '',
      note:       note ? String(note).trim().slice(0, 1000) : '',
      checkinDate,
      days:   daysNum,
      guests: guestsNum,
    });

    // Bump the property's booking counter. $inc is atomic, so concurrent
    // requests for the same property can't race and undercount each other.
    const updatedProperty = await propertyModel.findByIdAndUpdate(
      propertyId,
      { $inc: { bookingCount: 1 } },
      { new: true, select: 'bookingCount' }
    ).lean();

    res.status(201).json({
      message: 'Booking confirmed',
      booking,
      bookingCount: updatedProperty ? updatedProperty.bookingCount : undefined,
    });
  } catch (err) {
    console.error('POST /api/bookings error:', err);
    res.status(500).json({ message: 'Error saving booking: ' + err.message });
  }
});

// ── GET /api/user/my-visits (visit requests the logged-in user has made) ──
app.get('/api/user/my-visits', requireUser, async (req, res) => {
  try {
    const docs = await VisitRequest.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .populate('propertyId', 'owner.propertyName location.area')
      .lean();
    res.json({ visits: docs });
  } catch (err) {
    console.error('GET /api/user/my-visits error:', err);
    res.status(500).json({ message: 'Error fetching your visit requests: ' + err.message });
  }
});

// ── GET /api/user/notifications (logged-in user's notification feed) ──
app.get('/api/user/notifications', requireUser, async (req, res) => {
  try {
    const notifications = await Notification.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();
    const unreadCount = await Notification.countDocuments({ userId: req.userId, read: false });
    res.json({ notifications, unreadCount });
  } catch (err) {
    console.error('GET /api/user/notifications error:', err);
    res.status(500).json({ message: 'Error fetching notifications: ' + err.message });
  }
});

// ── GET /api/user/notifications/unread-count (lightweight — polled for the nav badge) ──
app.get('/api/user/notifications/unread-count', requireUser, async (req, res) => {
  try {
    const unreadCount = await Notification.countDocuments({ userId: req.userId, read: false });
    res.json({ unreadCount });
  } catch (err) {
    console.error('GET /api/user/notifications/unread-count error:', err);
    res.status(500).json({ message: 'Error fetching unread count: ' + err.message });
  }
});

// ── PATCH /api/user/notifications/:id/read (marks a single notification as read) ──
app.patch('/api/user/notifications/:id/read', requireUser, async (req, res) => {
  try {
    const notif = await Notification.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      { read: true },
      { new: true }
    );
    if (!notif) return res.status(404).json({ message: 'Notification not found' });
    res.json({ message: 'Marked as read', notification: notif });
  } catch (err) {
    console.error('PATCH /api/user/notifications/:id/read error:', err);
    res.status(500).json({ message: 'Error marking notification as read: ' + err.message });
  }
});

// ── PATCH /api/user/notifications/read-all (marks every notification as read) ──
app.patch('/api/user/notifications/read-all', requireUser, async (req, res) => {
  try {
    await Notification.updateMany({ userId: req.userId, read: false }, { read: true });
    res.json({ message: 'All notifications marked as read' });
  } catch (err) {
    console.error('PATCH /api/user/notifications/read-all error:', err);
    res.status(500).json({ message: 'Error marking notifications as read: ' + err.message });
  }
});

// ── GET /api/admin/visits (admin panel — all visit requests, newest first) ──
app.get('/api/admin/visits', requireAdmin, async (req, res) => {
  try {
    const docs = await VisitRequest.find({})
      .sort({ createdAt: -1 })
      .populate('propertyId', 'owner.propertyName location.area owner.phone')
      .lean();
    res.json({ visits: docs, total: docs.length });
  } catch (err) {
    console.error('GET /api/admin/visits error:', err);
    res.status(500).json({ message: 'Error fetching visit requests: ' + err.message });
  }
});

// ── PATCH /api/admin/visits/:id/status (admin: confirm/cancel/complete a visit) ──
app.patch('/api/admin/visits/:id/status', requireAdmin, async (req, res) => {
  try {
    const { status } = req.body || {};
    if (!['Pending', 'Confirmed', 'Cancelled', 'Completed'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }
    const before = await VisitRequest.findById(req.params.id).lean();
    const visit = await VisitRequest.findByIdAndUpdate(req.params.id, { status }, { new: true });
    if (!visit) return res.status(404).json({ message: 'Visit request not found' });

    if (before && before.status !== status && visit.userId) {
      const statusText = {
        Confirmed: 'confirmed', Cancelled: 'cancelled',
        Completed: 'marked as completed', Pending: 'set back to pending',
      }[status] || status.toLowerCase();
      await notifyUser(visit.userId, {
        type: 'visit_status',
        title: `Visit ${statusText}`,
        message: `Your visit scheduled for ${visit.visitDate} at ${visit.visitTime} has been ${statusText}.`,
        meta: { visitId: visit.visitId, mongoId: String(visit._id), status },
      });
    }

    res.json({ message: 'Status updated', visit });
  } catch (err) {
    console.error('PATCH /api/admin/visits/:id/status error:', err);
    res.status(500).json({ message: 'Error updating visit status: ' + err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────
// ── ADMIN: CUSTOMERS GRID ──
// ─────────────────────────────────────────────────────────────────────────
app.get('/api/users', requireAdmin, async (req, res) => {
  try {
    const users = await User.find({}).sort({ createdAt: -1 }).lean();
    const userIds = users.map(u => u._id);

    const [propAggByModel, visitAgg] = await Promise.all([
      Promise.all(LISTING_MODEL_LIST.map(M => M.aggregate([
        { $match: { userId: { $in: userIds } } },
        { $group: { _id: '$userId', count: { $sum: 1 } } }
      ]))),
      VisitRequest.aggregate([
        { $match: { userId: { $in: userIds } } },
        { $group: { _id: '$userId', count: { $sum: 1 } } }
      ])
    ]);

    // Sum counts per user across the four collections (a user's listings can
    // be split between rent/lease/pg/hourlyStay).
    const propMap = {};
    for (const agg of propAggByModel) {
      for (const x of agg) {
        const key = String(x._id);
        propMap[key] = (propMap[key] || 0) + x.count;
      }
    }
    const visitMap = Object.fromEntries(visitAgg.map(x => [String(x._id), x.count]));

    const rows = users.map(u => ({
      _id:           u._id,
      userId:        u.userId || '',
      name:          u.name || '',
      firstName:     u.firstName || '',
      lastName:      u.lastName || '',
      mobile:        u.mobile || '',
      email:         u.email  || '',
      password:      u.password || '',
      remarks:       u.remarks || [],
      listingsCount: propMap[String(u._id)]  || 0,
      visitsCount:   visitMap[String(u._id)] || 0,
      createdAt:     u.createdAt,
    }));

    res.json(rows);
  } catch (err) {
    console.error('GET /api/users error:', err);
    res.status(500).json({ message: 'Error fetching customers: ' + err.message });
  }
});

async function findUserByMobileOrId(key) {
  const decoded = decodeURIComponent(key || '').toLowerCase().trim();
  if (mongoose.Types.ObjectId.isValid(decoded)) {
    const byId = await User.findById(decoded);
    if (byId) return byId;
  }
  return User.findOne({ $or: [{ mobile: decoded }, { email: decoded }] });
}

app.delete('/api/users/mobile/:mobile', requireAdmin, async (req, res) => {
  try {
    const user = await findUserByMobileOrId(req.params.mobile);
    if (!user) return res.status(404).json({ message: 'Customer not found' });
    await User.deleteOne({ _id: user._id });
    res.json({ message: 'Customer deleted' });
  } catch (err) {
    console.error('DELETE /api/users/mobile/:mobile error:', err);
    res.status(500).json({ message: 'Error deleting customer: ' + err.message });
  }
});

// ── POST /api/users/bulk-delete (admin: delete many customers at once) ──
app.post('/api/users/bulk-delete', requireAdmin, async (req, res) => {
  try {
    const { mobiles } = req.body || {};
    if (!Array.isArray(mobiles) || !mobiles.length) {
      return res.status(400).json({ message: 'mobiles must be a non-empty array' });
    }
    const users = await Promise.all(mobiles.map(m => findUserByMobileOrId(m)));
    const ids = users.filter(Boolean).map(u => u._id);
    if (!ids.length) return res.status(404).json({ message: 'No matching customers found' });
    const result = await User.deleteMany({ _id: { $in: ids } });
    res.json({ message: `${result.deletedCount} customer(s) deleted`, deletedCount: result.deletedCount });
  } catch (err) {
    console.error('POST /api/users/bulk-delete error:', err);
    res.status(500).json({ message: 'Error deleting customers: ' + err.message });
  }
});

app.patch('/api/users/mobile/:mobile/remarks', requireAdmin, async (req, res) => {
  try {
    const { remarks } = req.body || {};
    if (!remarks || !String(remarks).trim()) return res.status(400).json({ message: 'Remark text is required' });
    const user = await findUserByMobileOrId(req.params.mobile);
    if (!user) return res.status(404).json({ message: 'Customer not found' });
    user.remarks.push({ remark: String(remarks).trim().slice(0, 200), date: new Date() });
    await user.save();
    res.json({ message: 'Remark added', remarks: user.remarks });
  } catch (err) {
    console.error('PATCH /api/users/mobile/:mobile/remarks error:', err);
    res.status(500).json({ message: 'Error saving remark: ' + err.message });
  }
});

app.delete('/api/users/mobile/:mobile/remarks/:idx', requireAdmin, async (req, res) => {
  try {
    const idx  = Number(req.params.idx);
    const user = await findUserByMobileOrId(req.params.mobile);
    if (!user) return res.status(404).json({ message: 'Customer not found' });
    if (!Number.isInteger(idx) || idx < 0 || idx >= user.remarks.length)
      return res.status(400).json({ message: 'Invalid remark index' });
    user.remarks.splice(idx, 1);
    await user.save();
    res.json({ message: 'Remark deleted', remarks: user.remarks });
  } catch (err) {
    console.error('DELETE /api/users/mobile/:mobile/remarks/:idx error:', err);
    res.status(500).json({ message: 'Error deleting remark: ' + err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────
// ── ADMIN: APPOINTMENTS GRID ──
// ─────────────────────────────────────────────────────────────────────────
function visitTimeToDisplay(hhmm) {
  if (!hhmm) return '';
  const [hStr, mStr] = hhmm.split(':');
  let h = Number(hStr);
  const m = String(mStr || '00').padStart(2, '0');
  const ampm = h >= 12 ? 'PM' : 'AM';
  if (h === 0) h = 12;
  else if (h > 12) h -= 12;
  return `${h}:${m} ${ampm}`;
}

function visitTimeToSlot(hhmm) {
  const h = Number(String(hhmm || '').split(':')[0]);
  if (Number.isNaN(h)) return '';
  if (h < 12) return 'Morning';
  if (h < 17) return 'Afternoon';
  return 'Evening';
}

function toApptRow(doc) {
  const prop         = doc.propertyId && typeof doc.propertyId === 'object' ? doc.propertyId : null;
  const propertyName = (prop && prop.owner    && prop.owner.propertyName) || '';
  const propertyArea = (prop && prop.location && prop.location.area)      || '';
  const purpose      = (prop && prop.basic    && prop.basic.status)       || 'General Enquiry';
  return {
    _id:             doc._id,
    visitId:         doc.visitId      || '',
    name:            doc.visitorName  || '',
    mobile:          doc.visitorPhone || '',
    email:           doc.email        || '',
    propertyId:      (prop && prop.propertyId) || '', // human-readable Property.propertyId code (e.g. AAA123), not the Mongo _id
    propertyName,
    propertyArea,
    purpose,
    date:            doc.visitDate    || '',
    visitTime:       doc.visitTime    || '',
    visitTimeDisplay:visitTimeToDisplay(doc.visitTime),
    timeSlot:        visitTimeToSlot(doc.visitTime),
    message:         doc.note         || '',
    status:          String(doc.status || 'Pending').toLowerCase(),
    remarks:         doc.remarks      || [],
    userId:          doc.userId       || null,
    userReadableId:  doc.userReadableId || '',
    createdAt:       doc.createdAt,
  };
}

app.get('/api/appointments', requireAdmin, async (req, res) => {
  try {
    const docs = await VisitRequest.find({})
      .sort({ createdAt: -1 })
      .populate('propertyId', 'basic.status owner.propertyName location.area propertyId')
      .lean();
    res.json(docs.map(toApptRow));
  } catch (err) {
    console.error('GET /api/appointments error:', err);
    res.status(500).json({ message: 'Error fetching appointments: ' + err.message });
  }
});

app.patch('/api/appointments/:id', requireAdmin, async (req, res) => {
  try {
    const { status } = req.body || {};
    const STATUS_MAP = { pending:'Pending', confirmed:'Confirmed', cancelled:'Cancelled', completed:'Completed' };
    const mapped = STATUS_MAP[String(status || '').toLowerCase()];
    if (!mapped) return res.status(400).json({ message: 'Invalid status' });
    const before = await VisitRequest.findById(req.params.id).lean();
    const visit = await VisitRequest.findByIdAndUpdate(req.params.id, { status: mapped }, { new: true });
    if (!visit) return res.status(404).json({ message: 'Appointment not found' });

    if (before && before.status !== mapped && visit.userId) {
      const statusText = {
        Confirmed: 'confirmed', Cancelled: 'cancelled',
        Completed: 'marked as completed', Pending: 'set back to pending',
      }[mapped] || mapped.toLowerCase();
      await notifyUser(visit.userId, {
        type: 'visit_status',
        title: `Visit ${statusText}`,
        message: `Your visit scheduled for ${visit.visitDate} at ${visit.visitTime} has been ${statusText}.`,
        meta: { visitId: visit.visitId, mongoId: String(visit._id), status: mapped },
      });
    }

    res.json({ message: 'Status updated' });
  } catch (err) {
    console.error('PATCH /api/appointments/:id error:', err);
    res.status(500).json({ message: 'Error updating appointment: ' + err.message });
  }
});

app.patch('/api/appointments/:id/remarks', requireAdmin, async (req, res) => {
  try {
    const { remarks } = req.body || {};
    if (!remarks || !String(remarks).trim()) return res.status(400).json({ message: 'Remark text is required' });
    const visit = await VisitRequest.findById(req.params.id);
    if (!visit) return res.status(404).json({ message: 'Appointment not found' });
    visit.remarks.push({ remark: String(remarks).trim().slice(0, 200), date: new Date() });
    await visit.save();
    res.json({ message: 'Remark added', remarks: visit.remarks });
  } catch (err) {
    console.error('PATCH /api/appointments/:id/remarks error:', err);
    res.status(500).json({ message: 'Error saving remark: ' + err.message });
  }
});

app.delete('/api/appointments/:id/remarks/:idx', requireAdmin, async (req, res) => {
  try {
    const idx   = Number(req.params.idx);
    const visit = await VisitRequest.findById(req.params.id);
    if (!visit) return res.status(404).json({ message: 'Appointment not found' });
    if (!Number.isInteger(idx) || idx < 0 || idx >= visit.remarks.length)
      return res.status(400).json({ message: 'Invalid remark index' });
    visit.remarks.splice(idx, 1);
    await visit.save();
    res.json({ message: 'Remark deleted', remarks: visit.remarks });
  } catch (err) {
    console.error('DELETE /api/appointments/:id/remarks/:idx error:', err);
    res.status(500).json({ message: 'Error deleting remark: ' + err.message });
  }
});

app.delete('/api/appointments/:id', requireAdmin, async (req, res) => {
  try {
    const visit = await VisitRequest.findByIdAndDelete(req.params.id);
    if (!visit) return res.status(404).json({ message: 'Appointment not found' });
    res.json({ message: 'Appointment deleted' });
  } catch (err) {
    console.error('DELETE /api/appointments/:id error:', err);
    res.status(500).json({ message: 'Error deleting appointment: ' + err.message });
  }
});

// ── POST /api/appointments/bulk-delete (admin: delete many appointments at once) ──
app.post('/api/appointments/bulk-delete', requireAdmin, async (req, res) => {
  try {
    const { ids } = req.body || {};
    if (!Array.isArray(ids) || !ids.length) {
      return res.status(400).json({ message: 'ids must be a non-empty array' });
    }
    const validIds = ids.filter(id => mongoose.Types.ObjectId.isValid(id));
    if (!validIds.length) return res.status(400).json({ message: 'No valid appointment ids provided' });
    const result = await VisitRequest.deleteMany({ _id: { $in: validIds } });
    res.json({ message: `${result.deletedCount} appointment(s) deleted`, deletedCount: result.deletedCount });
  } catch (err) {
    console.error('POST /api/appointments/bulk-delete error:', err);
    res.status(500).json({ message: 'Error deleting appointments: ' + err.message });
  }
});

// ── GET /api/admin/properties (admin panel — flat array + flat fields) ──
// admin.html's DataTable AND its View-modal (openAdminPropModal) both read
// flat fields off each row — there is no nested basic/location/owner/... here,
// everything is flattened to match what the modal's MODAL_FIELD_GROUPS expects.
// Kept separate from the public GET /api/properties so that endpoint's
// nested shape stays untouched for whatever already consumes it.
app.get('/api/admin/properties', requireAdmin, async (req, res) => {
  try {
    const docArrays = await Promise.all(LISTING_MODEL_LIST.map(M => M.find({}).lean()));
    const docs = docArrays.flat().sort((a, b) =>
      (Number(b.promoted) - Number(a.promoted)) ||
      ((a.promotedPriority ?? 3) - (b.promotedPriority ?? 3)) ||
      (new Date(b.createdAt) - new Date(a.createdAt))
    );

    const flat = docs.map(doc => {
      const basic    = doc.basic    || {};
      const location = doc.location || {};
      const owner    = doc.owner    || {};
      const price    = doc.price    || {};
      const property = doc.property || {};
      const amenities = doc.amenities || {};
      const media     = doc.media     || {};
      const pg        = doc.pg        || {};
      const shortStay = doc.shortStay || {};

      return {
        _id:          String(doc._id),
        propertyId:   doc.propertyId || '',
        userId:       doc.userReadableId || '', // human-readable User.userId (e.g. USER-000001), blank if posted while logged out

        // Complete raw record (every field stored in the DB for this property,
        // nested exactly as in the schema). The flattened fields below remain
        // for the table/cards and for the modal's existing named fields; `full`
        // exists so the View modal can also render anything NOT covered by the
        // flattened fields below — including ones added to the schema later
        // without needing a matching admin.html change.
        full: {
          basic, location, owner, price, property,
          amenities, terms: doc.terms || {}, rules: doc.rules || {},
          media, pg, shortStay,
          verified:         !!doc.verified,
          promoted:         !!doc.promoted,
          promotedPriority: doc.promotedPriority != null ? doc.promotedPriority : null,
          views:            doc.views != null ? doc.views : 0,
          visitCount:       doc.visitCount != null ? doc.visitCount : 0,
        },

        // Basic Info
        title:        owner.propertyName || '',
        status:       basic.status || '',
        price:        price.rent != null ? price.rent : null,
        displayPrice: formatPrice(price.rent, basic.status),
        city:         location.city || '',
        loc:          location.area || '',
        facing:       property.facing || '',
        age:          property.age || '',
        visitCount:   doc.visitCount != null ? doc.visitCount : 0,
        verified:     !!doc.verified,
        promoted:     !!doc.promoted,

        // Property Details
        bhk:          property.bhk || '',
        area:         property.area || '',
        floor:        property.floor || '',
        furnishing:   property.furnish || '',
        carparking:   property.car || '',
        bikeparking:  property.bike || '',
        toilet:       property.bathrooms || '',
        deposit:      price.deposit != null ? price.deposit : null,

        // PG Details
        pgGender:     pg.gender || '',
        pgRoomType:   pg.room || '',
        pgMeals:      pg.meals || '',
        pgOccupancy:  pg.occupancy || '',
        pgNotice:     pg.notice || '',
        pgBathroom:   pg.bathroom || '',

        // Short Stay Details
        ssRoomType:      shortStay.roomType || '',
        ssMaxGuests:     shortStay.maxGuests || '',
        ssMinDays:       shortStay.minDays || '',
        ssCheckinTime:   shortStay.checkinTime || '',
        ssCheckoutTime:  shortStay.checkoutTime || '',
        ssExtraDayRate:  shortStay.extraDayRate != null ? shortStay.extraDayRate : null,
        ssCancellation:  shortStay.cancellation || '',
        ssIdProof:       shortStay.idProof || '',
        ssCouplesAllowed:shortStay.couplesAllowed || '',

        // Owner Info
        ownerName:    owner.name || '',
        ownerNumber:  owner.phone || '',

        // Admin
        remarks:      doc.remarks || [],
        createdAt:    doc.createdAt,

        // Gallery / description / amenities / map
        images:       Array.isArray(media.images) ? media.images : [],
        desc:         media.desc || '',
        amenities:    Array.isArray(amenities.selected) ? amenities.selected : [],
        latitude:     location.lat != null ? location.lat : null,
        longitude:    location.lng != null ? location.lng : null,
      };
    });

    res.json(flat);
  } catch (err) {
    console.error('GET /api/admin/properties error:', err);
    res.status(500).json({ message: 'Error fetching properties: ' + err.message });
  }
});

// ── PATCH /api/properties/:id/remarks (admin: add a remark) ──
app.patch('/api/properties/:id/remarks', requireAdmin, async (req, res) => {
  try {
    const { remarks } = req.body || {};
    if (!remarks || !String(remarks).trim()) {
      return res.status(400).json({ message: 'remarks is required' });
    }
    const { doc: prop } = await findListingById(req.params.id);
    if (!prop) return res.status(404).json({ message: 'Property not found' });
    if (prop.remarks.length >= 200) {
      return res.status(400).json({ message: 'This property already has the maximum number of remarks (200). Delete an old one first.' });
    }
    prop.remarks.push(String(remarks).trim());
    await prop.save();
    res.json({ message: 'Remark added', remarks: prop.remarks });
  } catch (err) {
    console.error('PATCH /api/properties/:id/remarks error:', err);
    res.status(500).json({ message: 'Error adding remark: ' + err.message });
  }
});

// ── DELETE /api/properties/:id/remarks/:idx (admin: remove a remark) ──
app.delete('/api/properties/:id/remarks/:idx', requireAdmin, async (req, res) => {
  try {
    const idx = Number(req.params.idx);
    const { doc: prop } = await findListingById(req.params.id);
    if (!prop) return res.status(404).json({ message: 'Property not found' });
    if (idx < 0 || idx >= prop.remarks.length) {
      return res.status(400).json({ message: 'Invalid remark index' });
    }
    prop.remarks.splice(idx, 1);
    await prop.save();
    res.json({ message: 'Remark deleted', remarks: prop.remarks });
  } catch (err) {
    console.error('DELETE /api/properties/:id/remarks/:idx error:', err);
    res.status(500).json({ message: 'Error deleting remark: ' + err.message });
  }
});

// ── PATCH /api/properties/:id/verified (admin: toggle verified flag) ──
app.patch('/api/properties/:id/verified', requireAdmin, async (req, res) => {
  try {
    const { verified } = req.body || {};
    if (typeof verified !== 'boolean') {
      return res.status(400).json({ message: 'verified must be a boolean' });
    }
    // Grab the pre-update state so we only notify on the false → true
    // transition, not on every re-save while already verified.
    const before = await findListingById(req.params.id, { lean: true });
    const prop = await updateListingById(req.params.id, { verified }, { new: true });
    if (!prop) return res.status(404).json({ message: 'Property not found' });

    if (verified === true && before.doc && !before.doc.verified && prop.userId) {
      await notifyUser(prop.userId, {
        type: 'property_verified',
        title: 'Listing verified',
        message: `Your ${prop.basic.status} listing "${prop.owner.propertyName}" in ${prop.location.area} is now verified and live for everyone to see.`,
        meta: { propertyId: prop.propertyId, mongoId: String(prop._id) },
      });
    }

    res.json({ message: 'Verified status updated', verified: prop.verified });
  } catch (err) {
    console.error('PATCH /api/properties/:id/verified error:', err);
    res.status(500).json({ message: 'Error updating verified status: ' + err.message });
  }
});

// ── PATCH /api/properties/:id/promoted (admin: toggle promoted flag) ──
app.patch('/api/properties/:id/promoted', requireAdmin, async (req, res) => {
  try {
    const { promoted } = req.body || {};
    if (typeof promoted !== 'boolean') {
      return res.status(400).json({ message: 'promoted must be a boolean' });
    }
    const prop = await updateListingById(req.params.id, { promoted }, { new: true });
    if (!prop) return res.status(404).json({ message: 'Property not found' });
    res.json({ message: 'Promoted status updated', promoted: prop.promoted });
  } catch (err) {
    console.error('PATCH /api/properties/:id/promoted error:', err);
    res.status(500).json({ message: 'Error updating promoted status: ' + err.message });
  }
});

// ── DELETE /api/properties/:id (example admin-protected route) ──
app.delete('/api/properties/:id', requireAdmin, async (req, res) => {
  try {
    const deleted = await deleteListingById(req.params.id);
    if (!deleted) return res.status(404).json({ message: 'Property not found' });
    res.json({ message: 'Property deleted' });
  } catch (err) {
    console.error('DELETE /api/properties/:id error:', err);
    res.status(500).json({ message: 'Error deleting property: ' + err.message });
  }
});

// ── POST /api/properties/bulk-delete (admin: delete many properties at once) ──
app.post('/api/properties/bulk-delete', requireAdmin, async (req, res) => {
  try {
    const { ids } = req.body || {};
    if (!Array.isArray(ids) || !ids.length) {
      return res.status(400).json({ message: 'ids must be a non-empty array' });
    }
    const validIds = ids.filter(id => mongoose.Types.ObjectId.isValid(id));
    if (!validIds.length) return res.status(400).json({ message: 'No valid property ids provided' });
    const results = await Promise.all(LISTING_MODEL_LIST.map(M => M.deleteMany({ _id: { $in: validIds } })));
    const deletedCount = results.reduce((sum, r) => sum + r.deletedCount, 0);
    res.json({ message: `${deletedCount} propert${deletedCount === 1 ? 'y' : 'ies'} deleted`, deletedCount });
  } catch (err) {
    console.error('POST /api/properties/bulk-delete error:', err);
    res.status(500).json({ message: 'Error deleting properties: ' + err.message });
  }
});

// ────────────────────────────────────────────────────────────────────────────
// ── USER-OWNED LISTINGS ──
// These three routes are the only way a regular (non-admin) user can read,
// edit, or delete listings tied to their own account. Every query below
// filters by { _id, userId: req.userId } together — never by _id alone — so
// a user can only ever touch a property that has THEIR userId stamped on it.
// Listings posted while logged out (userId: null) are not user-editable by
// anyone; only the admin panel can manage those.
// ────────────────────────────────────────────────────────────────────────────

// ── GET /api/user/my-listings ──
app.get('/api/user/my-listings', requireUser, async (req, res) => {
  try {
    const docArrays = await Promise.all(LISTING_MODEL_LIST.map(M => M.find({ userId: req.userId }).lean()));
    const docs = docArrays.flat().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    const mapped = docs.map(doc => ({
      ...doc,
      id:           String(doc._id),
      displayPrice: formatPrice((doc.price || {}).rent, (doc.basic || {}).status),
    }));

    res.json({ properties: mapped, total: mapped.length });
  } catch (err) {
    console.error('GET /api/user/my-listings error:', err);
    res.status(500).json({ message: 'Error fetching your listings: ' + err.message });
  }
});

// ── PUT /api/user/listings/:id (edit a listing the user owns) ──
app.put('/api/user/listings/:id', requireUser, async (req, res) => {
  try {
    const { doc: prop, model: currentModel } = await findUserListingById(req.params.id, req.userId);
    if (!prop) return res.status(404).json({ message: 'Listing not found, or you do not have permission to edit it' });

    const body = req.body || {};
    const fields = NESTED_SECTIONS.reduce((acc, k) => {
      acc[k] = (body[k] && typeof body[k] === 'object') ? body[k] : {};
      return acc;
    }, {});

    // Only validate/apply sections the client actually sent something for,
    // so a partial edit (e.g. just price) doesn't get wiped by empty objects.
    const sentSections = NESTED_SECTIONS.filter(k => body[k] && typeof body[k] === 'object');
    const fieldsForValidation = {};
    for (const k of sentSections) fieldsForValidation[k] = fields[k];
    const validationError = validatePropertyFields(fieldsForValidation);
    if (validationError) return res.status(400).json({ message: validationError });

    for (const section of sentSections) {
      prop[section] = Object.assign({}, prop[section]?.toObject ? prop[section].toObject() : prop[section], fields[section]);
    }

    const savedDoc = await moveListingIfNeeded(prop, currentModel);
    const saved = savedDoc.toObject();
    saved.displayPrice = formatPrice((saved.price || {}).rent, (saved.basic || {}).status);

    res.json({ message: 'Listing updated successfully', property: saved });
  } catch (err) {
    console.error('PUT /api/user/listings/:id error:', err);
    res.status(500).json({ message: 'Error updating listing: ' + err.message });
  }
});

// ── DELETE /api/user/listings/:id (delete a listing the user owns) ──
app.delete('/api/user/listings/:id', requireUser, async (req, res) => {
  try {
    let deleted = null;
    for (const M of LISTING_MODEL_LIST) {
      deleted = await M.findOneAndDelete({ _id: req.params.id, userId: req.userId });
      if (deleted) break;
    }
    if (!deleted) return res.status(404).json({ message: 'Listing not found, or you do not have permission to delete it' });
    res.json({ message: 'Listing deleted' });
  } catch (err) {
    console.error('DELETE /api/user/listings/:id error:', err);
    res.status(500).json({ message: 'Error deleting listing: ' + err.message });
  }
});

// ── Serve frontend ──
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── Global error handler ──
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(err.status || 500).json({ message: err.message || 'An unexpected error occurred.' });
});


const reviewSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  userKey:   { type: String, required: true, index: true },
  userName:  { type: String, required: true },
  rating:    { type: Number, required: true, min: 1, max: 5 },
  text:      { type: String, required: true, maxlength: 500 },
  createdAt: { type: Date, default: Date.now }
});

const Review = mongoose.model('Review', reviewSchema);

// GET /api/reviews?page=1&limit=10
// Public — no auth required to read reviews.
app.get('/api/reviews', async (req, res) => {
  try {
    const page  = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 10, 1), 50);
    const skip  = (page - 1) * limit;

    const [reviews, total, avgResult, starBuckets] = await Promise.all([
      Review.find({}).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      Review.countDocuments({}),
      Review.aggregate([{ $group: { _id: null, avg: { $avg: '$rating' } } }]),
      Review.aggregate([{ $group: { _id: '$rating', count: { $sum: 1 } } }])
    ]);

    const ratingCounts = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
    starBuckets.forEach(b => { if (ratingCounts[b._id] !== undefined) ratingCounts[b._id] = b.count; });

    res.json({
      reviews,
      total,
      avgRating: avgResult[0]?.avg || 0,
      ratingCounts
    });
  } catch (err) {
    console.error('GET /api/reviews error:', err.message);
    res.status(500).json({ error: 'Could not load reviews' });
  }
});

// GET /api/reviews/mine — tells the client whether the logged-in user has
// already posted a review, so the form can be hidden/shown correctly on load
// (not just right after a successful submit in the same session).
app.get('/api/reviews/mine', async (req, res) => {
  try {
    const userKey = req.headers['x-user-key'];
    if (!userKey) return res.json({ hasReviewed: false });

    const userId = await getUserIdFromSession(userKey);
    if (!userId) return res.json({ hasReviewed: false });

    const existing = await Review.findOne({ userId }).lean();
    res.json({ hasReviewed: !!existing, review: existing || null });
  } catch (err) {
    console.error('GET /api/reviews/mine error:', err.message);
    res.status(500).json({ error: 'Could not check review status' });
  }
});

// POST /api/reviews — requires a logged-in user (x-user-key header).
// Mirrors the same auth pattern used by your other /api/user/... routes.
app.post('/api/reviews', async (req, res) => {
  try {
    const userKey = req.headers['x-user-key'];
    if (!userKey) return res.status(401).json({ error: 'Please log in to leave a review' });

    const userId = await getUserIdFromSession(userKey);
    if (!userId) return res.status(401).json({ error: 'Invalid or expired session' });

    const user = await User.findById(userId);
    if (!user) return res.status(401).json({ error: 'Invalid or expired session' });

    const rating = Number(req.body.rating);
    const text = (req.body.text || '').trim();
    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Rating must be between 1 and 5' });
    }
    if (!text || text.length > 500) {
      return res.status(400).json({ error: 'Review text must be 1–500 characters' });
    }

    const existing = await Review.findOne({ userId: user._id });
    if (existing) {
      return res.status(409).json({ error: 'You have already posted a review' });
    }

    const review = await Review.create({
      userId: user._id,
      userKey,
      userName: user.name || 'Quatar user',
      rating,
      text
    });

    res.status(201).json({ review });
  } catch (err) {
    console.error('POST /api/reviews error:', err.message);
    res.status(500).json({ error: 'Could not save review' });
  }
});


// ── Honest Reviews (video testimonials shown as a "Shorts" style row) ──
// Two ways cards get in here, both go live immediately (no manage/approve
// UI exists on the site yet):
//  1) Admin adds one directly via POST /api/honest-reviews.
//  2) A logged-in user submits their own YouTube link via
//     POST /api/honest-reviews/submit.
// The `status` field (pending/approved/rejected) and the admin-only
// /api/honest-reviews/all, PUT, DELETE routes are kept so a moderation
// step can be reintroduced later without a schema change.
const honestReviewSchema = new mongoose.Schema({
  videoUrl:  { type: String, required: true },       // real YouTube/video link opened on click
  thumbUrl:  { type: String, required: true },        // thumbnail image shown on the card
  caption:   { type: String, required: true, maxlength: 120 },  // overlay text on the thumbnail
  title:     { type: String, required: true, maxlength: 120 }, // e.g. "Priya & Rohan — 2BHK in Indiranagar"
  meta:      { type: String, default: '', maxlength: 80 },     // e.g. "Moved in April 2026"
  verifiedLabel: { type: String, default: 'Verified tenant' },
  order:     { type: Number, default: 0 },             // lower shows first
  active:    { type: Boolean, default: true },
  status:    { type: String, enum: ['pending', 'approved', 'rejected'], default: 'approved', index: true },
  userId:    { type: mongoose.Schema.Types.ObjectId, default: null },   // set only for user-submitted videos
  userName:  { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

const HonestReview = mongoose.model('HonestReview', honestReviewSchema);

// Pulls the video ID out of the common YouTube URL shapes so we can build a
// thumbnail automatically for user submissions (they won't have one to give
// us). Returns null if the link isn't a YouTube URL we recognize.
function extractYouTubeId(url) {
  try {
    const u = new URL(String(url).trim());
    const host = u.hostname.replace(/^www\./, '');
    if (host === 'youtu.be') return u.pathname.slice(1).split('/')[0] || null;
    if (host === 'youtube.com' || host === 'm.youtube.com') {
      if (u.pathname === '/watch') return u.searchParams.get('v');
      const shortsMatch = u.pathname.match(/^\/shorts\/([^/?]+)/);
      if (shortsMatch) return shortsMatch[1];
      const embedMatch = u.pathname.match(/^\/embed\/([^/?]+)/);
      if (embedMatch) return embedMatch[1];
    }
    return null;
  } catch {
    return null;
  }
}

// GET /api/honest-reviews — public, powers the homepage video row.
// Only approved + active cards are ever shown to regular visitors.
app.get('/api/honest-reviews', async (req, res) => {
  try {
    const reviews = await HonestReview.find({ active: true, status: 'approved' })
      .sort({ order: 1, createdAt: -1 })
      .lean();
    res.json({ reviews });
  } catch (err) {
    console.error('GET /api/honest-reviews error:', err.message);
    res.status(500).json({ error: 'Could not load honest reviews' });
  }
});

// GET /api/honest-reviews/all — admin-only, returns every entry regardless
// of status (pending/approved/rejected) or active flag, for the manage UI.
app.get('/api/honest-reviews/all', requireAdmin, async (req, res) => {
  try {
    const reviews = await HonestReview.find({})
      .sort({ createdAt: -1 })
      .lean();
    res.json({ reviews });
  } catch (err) {
    console.error('GET /api/honest-reviews/all error:', err.message);
    res.status(500).json({ error: 'Could not load honest reviews' });
  }
});

// GET /api/honest-reviews/mine — a logged-in user checking the status of
// the video(s) they've submitted (pending / approved / rejected).
app.get('/api/honest-reviews/mine', requireUser, async (req, res) => {
  try {
    const reviews = await HonestReview.find({ userId: req.userId }).sort({ createdAt: -1 }).lean();
    res.json({ reviews });
  } catch (err) {
    console.error('GET /api/honest-reviews/mine error:', err.message);
    res.status(500).json({ error: 'Could not load your submissions' });
  }
});

// POST /api/honest-reviews/submit — any logged-in user can submit their own
// YouTube video. Goes live immediately (no manage/approve UI exists yet on
// the site) — if moderation is added back later, flip `active`/`status`
// below to false/'pending' and reintroduce an approve step.
app.post('/api/honest-reviews/submit', requireUser, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(401).json({ error: 'Invalid or expired session' });

    const videoUrl = (req.body.videoUrl || '').trim();
    const title = (req.body.title || '').trim();
    const caption = (req.body.caption || '').trim();

    const videoId = extractYouTubeId(videoUrl);
    if (!videoId) {
      return res.status(400).json({ error: 'Please paste a valid YouTube video link' });
    }
    if (!title) return res.status(400).json({ error: 'Please give your video a short title' });

    const review = await HonestReview.create({
      videoUrl,
      thumbUrl: `https://img.youtube.com/vi/${videoId}/hqdefault.jpg`,
      caption: caption || title,
      title: title.slice(0, 120),
      meta: `Submitted by ${user.name || 'a Quatar user'}`,
      verifiedLabel: 'Verified user',
      active: true,
      status: 'approved',
      userId: user._id,
      userName: user.name || ''
    });

    res.status(201).json({ review, message: 'Thanks! Your video is now live in Honest Reviews.' });
  } catch (err) {
    console.error('POST /api/honest-reviews/submit error:', err.message);
    res.status(500).json({ error: 'Could not submit your video' });
  }
});

// POST /api/honest-reviews — admin-only, add a new video card (goes live immediately)
app.post('/api/honest-reviews', requireAdmin, async (req, res) => {
  try {
    const { videoUrl, thumbUrl, caption, title, meta, verifiedLabel, order, active } = req.body;
    if (!videoUrl || !thumbUrl || !caption || !title) {
      return res.status(400).json({ error: 'videoUrl, thumbUrl, caption and title are required' });
    }
    const review = await HonestReview.create({
      videoUrl, thumbUrl, caption, title,
      meta: meta || '',
      verifiedLabel: verifiedLabel || 'Verified tenant',
      order: Number(order) || 0,
      active: active !== false,
      status: 'approved'
    });
    res.status(201).json({ review });
  } catch (err) {
    console.error('POST /api/honest-reviews error:', err.message);
    res.status(500).json({ error: 'Could not save honest review' });
  }
});

// PUT /api/honest-reviews/:id — admin-only, edit an existing video card.
// Also used to approve/reject user submissions by setting `status` (and
// typically `active` alongside it).
app.put('/api/honest-reviews/:id', requireAdmin, async (req, res) => {
  try {
    const fields = (({ videoUrl, thumbUrl, caption, title, meta, verifiedLabel, order, active, status }) =>
      ({ videoUrl, thumbUrl, caption, title, meta, verifiedLabel, order, active, status }))(req.body);
    Object.keys(fields).forEach(k => fields[k] === undefined && delete fields[k]);

    const before = await HonestReview.findById(req.params.id).lean();
    const review = await HonestReview.findByIdAndUpdate(req.params.id, fields, { new: true });
    if (!review) return res.status(404).json({ error: 'Honest review not found' });

    // Only notify on the pending/rejected → approved transition, not on
    // every subsequent edit to an already-approved card.
    if (review.status === 'approved' && before && before.status !== 'approved' && review.userId) {
      await notifyUser(review.userId, {
        type: 'review_approved',
        title: 'Honest Review approved',
        message: `Your video "${review.title}" has been approved and is now live in Honest Reviews.`,
        meta: { reviewId: String(review._id) },
      });
    }

    res.json({ review });
  } catch (err) {
    console.error('PUT /api/honest-reviews/:id error:', err.message);
    res.status(500).json({ error: 'Could not update honest review' });
  }
});

// DELETE /api/honest-reviews/:id — admin-only
app.delete('/api/honest-reviews/:id', requireAdmin, async (req, res) => {
  try {
    const deleted = await HonestReview.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Honest review not found' });
    res.json({ message: 'Honest review deleted' });
  } catch (err) {
    console.error('DELETE /api/honest-reviews/:id error:', err.message);
    res.status(500).json({ error: 'Could not delete honest review' });
  }
});



// Accepts any number of images (multipart/form-data, field name 'images'), converts
// each to WebP (max 1200px on the long edge, quality 80) via sharp, and saves
// the resulting bytes as a document in MongoDB (not the local disk — Render's
// filesystem is wiped on every restart/redeploy/free-tier spin-down, but Mongo
// data persists, and this way no extra paid service or third-party account is
// needed). Each image is served back from GET /uploads/:id. Files never touch
// disk — multer holds them in memory, sharp re-encodes buffer-to-buffer, which
// also strips any embedded scripts/metadata that might be hiding in a
// malicious "image" upload.
// ────────────────────────────────────────────────────────────────────────────
const ImageAssetSchema = new mongoose.Schema({
  data:        { type: Buffer, required: true },
  contentType: { type: String, required: true, default: 'image/webp' },
  createdAt:   { type: Date, default: Date.now },
});
const ImageAsset = mongoose.model('ImageAsset', ImageAssetSchema);

// Public — anyone viewing a listing needs to load these, no auth required.
// Cached hard since each id's bytes never change (a re-upload creates a new id).
app.get('/uploads/:id', async (req, res) => {
  try {
    const img = await ImageAsset.findById(req.params.id).lean();
    if (!img) return res.status(404).end();
    res.set('Content-Type', img.contentType);
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
    res.send(Buffer.isBuffer(img.data) ? img.data : Buffer.from(img.data.buffer || img.data));
  } catch (err) {
    // Malformed/non-ObjectId id, etc. — just 404 rather than 500.
    res.status(404).end();
  }
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB per file, no cap on file count
  fileFilter: (req, file, cb) => {
    const ok = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/heic', 'image/heif'].includes(file.mimetype);
    cb(ok ? null : new Error('Only image files are allowed'), ok);
  },
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 30,
  standardHeaders: true, legacyHeaders: false,
  message: { message: 'Too many upload requests. Please try again later.' }
});

app.post('/api/upload-images', uploadLimiter, attachUserIfPresent, upload.array('images'), async (req, res) => {
  try {
    const files = req.files || [];
    if (!files.length) return res.status(400).json({ message: 'No images uploaded' });

    const urls = [];
    for (const file of files) {
      const webpBuffer = await sharp(file.buffer)
        .rotate() // honor EXIF orientation before stripping metadata
        .resize({ width: 1200, height: 1200, fit: 'inside', withoutEnlargement: true })
        .webp({ quality: 80 })
        .toBuffer();

      const doc = await ImageAsset.create({ data: webpBuffer, contentType: 'image/webp' });
      urls.push(`/uploads/${doc._id}`);
    }

    res.status(201).json({ message: 'Images uploaded successfully', urls });
  } catch (err) {
    console.error('POST /api/upload-images error:', err);
    res.status(500).json({ message: 'Error uploading images: ' + err.message });
  }
});

// Multer-specific errors (file too large, too many files, wrong type) come through
// as thrown errors rather than rejections multer itself formats — catch them here
// so the client gets a clean 400 instead of a raw 500.
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || (err && /Only image files/.test(err.message || ''))) {
    return res.status(400).json({ message: err.message });
  }
  next(err);
});

// ────────────────────────────────────────────────────────────────────────────
// ── SITE STATS (visitor counter + total registered users) ──
// Powers the two small stat pills above the FAB on the homepage:
//   - "Website visitors": all-time count of page loads, bumped once per
//     visit by a fire-and-forget call from the frontend on load.
//   - "Login users": total registered users (User.countDocuments()).
// A single-document counter (keyed by `key`) is enough here — no need for
// the Counter/nextSequenceId pattern used for human-readable IDs elsewhere.
// ────────────────────────────────────────────────────────────────────────────
const SiteStatSchema = new mongoose.Schema({
  key:   { type: String, required: true, unique: true, index: true },
  value: { type: Number, default: 0 },
});
const SiteStat = mongoose.model('SiteStat', SiteStatSchema);

// Light rate limit — this is a public, unauthenticated endpoint hit once per
// page load, so it just needs to keep bots from spamming it, not restrict
// normal browsing.
const visitLimiterStats = rateLimit({
  windowMs: 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { message: 'Too many requests. Please try again later.' }
});

app.post('/api/stats/visit', visitLimiterStats, async (req, res) => {
  try {
    const doc = await SiteStat.findOneAndUpdate(
      { key: 'totalVisits' },
      { $inc: { value: 1 } },
      { upsert: true, new: true }
    );
    res.json({ totalVisits: doc.value });
  } catch (err) {
    console.error('POST /api/stats/visit error:', err.message);
    res.status(500).json({ message: 'Error recording visit' });
  }
});

app.get('/api/stats', async (req, res) => {
  try {
    const [visitDoc, totalUsers] = await Promise.all([
      SiteStat.findOne({ key: 'totalVisits' }).lean(),
      User.countDocuments(),
    ]);
    res.json({ totalVisits: visitDoc ? visitDoc.value : 0, totalUsers });
  } catch (err) {
    console.error('GET /api/stats error:', err.message);
    res.status(500).json({ message: 'Error fetching stats' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));