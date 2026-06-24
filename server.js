require('dotenv').config();

const express    = require('express');
const mongoose   = require('mongoose');
const cors       = require('cors');
const path       = require('path');
const rateLimit  = require('express-rate-limit');

// ── Env checks ──
if (!process.env.MONGODB_URI)   throw new Error('MONGODB_URI env var is required');
if (!process.env.ALLOWED_ORIGIN) {
  if (process.env.NODE_ENV === 'production') throw new Error('ALLOWED_ORIGIN env var is required in production');
  console.warn('⚠️  ALLOWED_ORIGIN not set — defaulting to * (development only)');
}

const app = express();
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
app.use(express.json({ limit: '10mb' })); // 10mb to allow base64 images
app.use(express.static('public', { maxAge: '7d', etag: true }));

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
}, { _id: false });

const PriceSchema = new mongoose.Schema({
  rent:         { type: Number, required: true },
  deposit:      { type: Number, default: null },
  maintenance:  { type: Number, default: null },
  rentIncrease: { type: String, default: null },
  electricity:  { type: String, default: null },
  water:        { type: String, default: null },
  negotiable:   { type: Boolean, default: false },
}, { _id: false });

const PropertyDetailsSchema = new mongoose.Schema({
  type:      { type: String, default: null },   // propertyType (Apartment/Villa/etc.)
  bhk:       { type: String, default: null },
  bike:      { type: String, default: 'No' },    // bikeparking: 'Yes' | 'No'
  car:       { type: String, default: 'No' },    // carparking:  'Yes' | 'No'
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
  notice: { type: String, default: null }, // noticePeriod / leaseNotice / pgNotice
  lease:  { type: String, default: null }, // leaseDuration / leaseDurationVal (+type/lock-in folded in)
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
  pg:         { type: PgSchema,               default: () => ({}) },
  // ── Meta (kept top-level / flat — not part of the submitted payload) ──
  promoted:         { type: Boolean, default: false },
  promotedPriority: { type: Number,  default: 3 },
  views:            { type: Number,  default: 0 },
  createdAt:        { type: Date,    default: Date.now },
});
PropertySchema.index({ createdAt: -1 });
PropertySchema.index({ 'basic.status': 1, createdAt: -1 });
const Property = mongoose.model('Property', PropertySchema);

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
        try { new URL(String(val).trim()); } catch { return `Invalid URL in field '${section}.${k}'.`; }
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
  return null;
}

// ── Rate limiter ──
const listingLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  message: { message: 'Too many listing submissions. Please try again later.' }
});

// ── POST /api/properties ──
app.post('/api/properties', listingLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    const fields = NESTED_SECTIONS.reduce((acc, k) => {
      acc[k] = (body[k] && typeof body[k] === 'object') ? body[k] : {};
      return acc;
    }, {});

    const validationError = validatePropertyFields(fields);
    if (validationError) return res.status(400).json({ message: validationError });

    if (!fields.owner.propertyName || !fields.location.area || fields.price.rent === undefined || fields.price.rent === null || fields.price.rent === '') {
      return res.status(400).json({ message: 'owner.propertyName, location.area, and price.rent are required.' });
    }

    fields.basic = Object.assign({ status: 'For Rent', listedBy: 'Owner' }, fields.basic);
    fields.media.displayPrice = undefined; // not part of media; computed separately below

    const status = fields.basic.status;
    const displayPrice = formatPrice(fields.price.rent, status);

    const prop = new Property({
      basic:     fields.basic,
      location:  fields.location,
      owner:     fields.owner,
      price:     fields.price,
      property:  fields.property,
      amenities: fields.amenities,
      terms:     fields.terms,
      rules:     fields.rules,
      media:     fields.media,
      pg:        fields.pg,
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
    if (status) filter['basic.status'] = status;
    if (q) {
      const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filter.$or = [{ 'owner.propertyName': re }, { 'location.area': re }, { 'media.desc': re }];
    }

    const docs = await Property.find(filter)
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
                      ? new Date(doc.createdAt).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' })
                      : 'Recently',
      verified:     false,
    }));

    res.json({ properties: mapped, total: mapped.length });
  } catch (err) {
    console.error('GET /api/properties error:', err);
    res.status(500).json({ message: 'Error fetching properties: ' + err.message });
  }
});

// ── Serve frontend ──
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── Global error handler ──
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(err.status || 500).json({ message: err.message || 'An unexpected error occurred.' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));