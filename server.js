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

// ── Env checks ──
if (!process.env.MONGODB_URI)   throw new Error('MONGODB_URI env var is required');
if (!process.env.ALLOWED_ORIGIN) {
  if (process.env.NODE_ENV === 'production') throw new Error('ALLOWED_ORIGIN env var is required in production');
  console.warn('⚠️  ALLOWED_ORIGIN not set — defaulting to * (development only)');
}
if (process.env.NODE_ENV === 'production' && (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD)) {
  throw new Error('ADMIN_EMAIL and ADMIN_PASSWORD env vars are required in production (hardcoded admin/admin login is dev-only)');
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
  status:    { type: String, enum: ['For Sale','For Rent','New Launch','Sold','Booked','Lease','PG'], default: 'For Rent' },
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
  monthlyRent:  { type: Number, default: null }, // Lease only: optional recurring rent on top of the lease/token amount (f-leaseMonthlyRent)
  maintenance:  { type: Number, default: null },
  rentIncrease: { type: String, default: null },
  electricity:  { type: String, default: null },
  water:        { type: String, default: null },
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
  leaseType: { type: String, default: null }, // Lease only: Residential / Commercial / Industrial / Mixed Use
  lockIn:    { type: String, default: null }, // Lease only: lock-in period
}, { _id: false });

const RulesSchema = new mongoose.Schema({
  pets:   { type: String, default: null }, // petsAllowed / leasePets / pgPets
  nonVeg: { type: String, default: null }, // nonVegAllowed / leaseNonVeg / pgNonVeg
  gas:    { type: String, default: null }, // pipedGas
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
  mealCost:      { type: Number, default: null },
  beds:          { type: String, default: null }, // pgTotalBeds
  furnish:       { type: String, default: null }, // pgRoomFurnishing
  food:          { type: String, default: null }, // pgFoodType
  kitchen:       { type: String, default: null }, // pgKitchenAccess
  available:     { type: String, default: null }, // pgAvailableFrom
  visitors:      { type: String, default: null }, // pgVisitorPolicy
  gateTime:      { type: String, default: null },
  nonVeg:        { type: String, default: null },
  pets:          { type: String, default: null },
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
    exists = await Property.exists({ propertyId: id });
    attempts++;
  }
  return id;
}

const PropertySchema = new mongoose.Schema({
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
  // ── Meta (kept top-level / flat — not part of the submitted payload) ──
  propertyId:       { type: String, unique: true, sparse: true, index: true }, // random alphanumeric code, e.g. AAA123
  userId:           { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true }, // owner of this listing, null = posted while logged out
  userReadableId:   { type: String, default: null, index: true }, // human-readable User.userId (e.g. USER-000001), stamped at creation for admin readability — same pattern as UserSession.userId
  verified:         { type: Boolean, default: false },
  promoted:         { type: Boolean, default: false },
  promotedPriority: { type: Number,  default: 3 },
  views:            { type: Number,  default: 0 },
  visitCount:       { type: Number,  default: 0 }, // # of "Schedule a Visit" requests made for this listing
  remarks:          { type: [String], default: [] }, // admin-panel notes
  createdAt:        { type: Date,    default: Date.now },
});
PropertySchema.index({ createdAt: -1 });
PropertySchema.index({ 'basic.status': 1, createdAt: -1 });
const Property = mongoose.model('Property', PropertySchema);

// ── Visit Request Schema (from the "Schedule a Visit" modal) ──
const VisitRequestSchema = new mongoose.Schema({
  // Human-readable unique id, same pattern as Property.propertyId (e.g. VISIT-000001).
  visitId:      { type: String, unique: true, sparse: true, index: true },
  propertyId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Property', required: true, index: true },
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

// ── Helpers ──
function formatPrice(price, status) {
  const num = Number(price);
  let display = '';
  if      (num >= 10000000) display = (num / 10000000).toFixed(2).replace(/\.?0+$/, '') + 'Cr';
  else if (num >= 100000)   display = (num / 100000).toFixed(1).replace(/\.?0+$/, '') + 'L';
  else if (num >= 1000)     display = (num / 1000).toFixed(1).replace(/\.?0+$/, '') + 'K';
  else                      display = String(num);
  if (['For Rent', 'Lease', 'PG'].includes(status)) display += '/Month';
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
const NESTED_SECTIONS = ['basic','location','owner','price','property','amenities','terms','rules','media','pg'];

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
    // (price.rent doubles as "monthly rent" for Rent, "lease amount" for Lease, "monthly charge" for PG).
    const priceLabel = status === 'Lease' ? 'price.rent (lease amount)'
                      : status === 'PG'   ? 'price.rent (monthly charge)'
                      :                     'price.rent (monthly rent)';
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

    const displayPrice = formatPrice(fields.price.rent, status);
    const propertyId = await nextPropertyId();

    const prop = new Property({
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
    const filter = {};
    if (status && typeof status === 'string') filter['basic.status'] = status;
    if (q && typeof q === 'string') {
      const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filter.$or = [{ 'owner.propertyName': re }, { 'location.area': re }, { 'media.desc': re }];
    }

    const docs = await Property.find(filter)
      .select(
        // Internal/admin-only fields — never read by the public frontend
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
        '-location.address -location.lat -location.lng -location.mapLink'
      )
      .sort({ promoted: -1, promotedPriority: 1, createdAt: -1 })
      .skip(Number(skip))
      .limit(Number(limit))
      .lean();

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

    const property = await Property.findById(propertyId).lean();
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
    const updatedProperty = await Property.findByIdAndUpdate(
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
    const visit = await VisitRequest.findByIdAndUpdate(req.params.id, { status }, { new: true });
    if (!visit) return res.status(404).json({ message: 'Visit request not found' });
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

    const [propAgg, visitAgg] = await Promise.all([
      Property.aggregate([
        { $match: { userId: { $in: userIds } } },
        { $group: { _id: '$userId', count: { $sum: 1 } } }
      ]),
      VisitRequest.aggregate([
        { $match: { userId: { $in: userIds } } },
        { $group: { _id: '$userId', count: { $sum: 1 } } }
      ])
    ]);

    const propMap  = Object.fromEntries(propAgg.map(x  => [String(x._id), x.count]));
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
    const visit = await VisitRequest.findByIdAndUpdate(req.params.id, { status: mapped }, { new: true });
    if (!visit) return res.status(404).json({ message: 'Appointment not found' });
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
    const docs = await Property.find({})
      .sort({ promoted: -1, promotedPriority: 1, createdAt: -1 })
      .lean();

    const flat = docs.map(doc => {
      const basic    = doc.basic    || {};
      const location = doc.location || {};
      const owner    = doc.owner    || {};
      const price    = doc.price    || {};
      const property = doc.property || {};
      const amenities = doc.amenities || {};
      const media     = doc.media     || {};
      const pg        = doc.pg        || {};

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
          media, pg,
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
    const prop = await Property.findById(req.params.id);
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
    const prop = await Property.findById(req.params.id);
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
    const prop = await Property.findByIdAndUpdate(
      req.params.id,
      { verified },
      { new: true }
    );
    if (!prop) return res.status(404).json({ message: 'Property not found' });
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
    const prop = await Property.findByIdAndUpdate(
      req.params.id,
      { promoted },
      { new: true }
    );
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
    const deleted = await Property.findByIdAndDelete(req.params.id);
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
    const result = await Property.deleteMany({ _id: { $in: validIds } });
    res.json({ message: `${result.deletedCount} propert${result.deletedCount === 1 ? 'y' : 'ies'} deleted`, deletedCount: result.deletedCount });
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
    const docs = await Property.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .lean();

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
    const prop = await Property.findOne({ _id: req.params.id, userId: req.userId });
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

    await prop.save();
    const saved = prop.toObject();
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
    const deleted = await Property.findOneAndDelete({ _id: req.params.id, userId: req.userId });
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


// ────────────────────────────────────────────────────────────────────────────
// ── IMAGE UPLOAD (POST /api/upload-images) ──
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));