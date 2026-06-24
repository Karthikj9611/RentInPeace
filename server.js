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

// ── Property Schema ──
const PropertySchema = new mongoose.Schema({
  title:        { type: String, required: true },
  loc:          { type: String, required: true },
  city:         { type: String, default: 'Bengaluru' },
  price:        { type: Number, required: true },
  displayPrice: { type: String, required: true },
  bhk:          { type: Number, default: null },
  area:         String,
  status:       { type: String, enum: ['For Sale','For Rent','New Launch','Sold','Booked','Lease','PG'], default: 'For Rent' },
  furnishing:   { type: String, default: 'Unfurnished' },
  floor: String, floorLevel: String, age: String, facing: String,
  carparking: String, bikeparking: String, toilet: String,
  amenities: [String], images: [String], desc: String,
  deposit:   { type: Number, default: null },
  latitude:  { type: Number, default: null },
  longitude: { type: Number, default: null },
  // ── PG fields ──
  pgGender:         { type: String, default: null },
  pgRoomType:       { type: String, default: null },
  pgMeals:          { type: String, default: null },
  pgOccupancy:      { type: Number, default: null },
  pgNotice:         { type: String, default: null },
  pgBathroom:       { type: String, default: null },
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
  // ── For Rent fields ──
  availableFrom:  { type: String, default: null },
  noticePeriod:   { type: String, default: null },
  leaseDuration:  { type: String, default: null },
  tenantPref:     { type: String, default: null },
  maintenance:    { type: Number, default: null },
  petsAllowed:    { type: String, default: null },
  nonVegAllowed:  { type: String, default: null },
  pipedGas:       { type: String, default: null },
  // ── Lease fields ──
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
  // ── Extra fields ──
  propertyType:        { type: String, default: null },
  societyName:         { type: String, default: '' },
  totalFloors:         { type: Number, default: null },
  electricityIncluded: { type: String, default: null },
  waterCharge:         { type: String, default: null },
  escalation:          { type: Number, default: null },
  listedBy:            { type: String, default: 'Owner' },
  googleMapsLink:      { type: String, default: '' },
  videoUrl:            { type: String, default: '' },
  // ── Owner details ──
  ownerName:    { type: String, default: '' },
  ownerNumber:  { type: String, default: '' },
  ownerEmail:   { type: String, default: '' },
  ownerAltPhone:{ type: String, default: '' },
  ownerAddress: { type: String, default: '' },
  contactTime:  { type: String, default: '' },
  fullAddress:  { type: String, default: '' },
  // ── Meta ──
  negotiable:       { type: Boolean, default: false },
  submittedBy:      { type: String,  default: '' },
  promoted:         { type: Boolean, default: false },
  promotedPriority: { type: Number,  default: 3 },
  views:            { type: Number,  default: 0 },
  createdAt:        { type: Date,    default: Date.now },
});
PropertySchema.index({ createdAt: -1 });
PropertySchema.index({ status: 1, createdAt: -1 });
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

const PROPERTY_FIELDS = [
  'title','loc','city','price','bhk','area','status','furnishing',
  'floor','floorLevel','age','facing','carparking','bikeparking','toilet',
  'amenities','images','desc','deposit','latitude','longitude',
  'pgGender','pgRoomType','pgMeals','pgOccupancy','pgNotice','pgBathroom',
  'pgMealsCost','pgTotalBeds','pgRoomFurnishing','pgFoodType','pgKitchenAccess',
  'pgAvailableFrom','pgVisitorPolicy','pgGateTime','pgNonVeg','pgPets',
  'availableFrom','noticePeriod','leaseDuration','tenantPref','maintenance',
  'petsAllowed','nonVegAllowed','pipedGas',
  'leaseAmount','leaseMonthlyRent','leaseMaintenance','leaseDurationVal','leaseType',
  'lockInPeriod','leaseAvailFrom','leaseNotice','rentEscalation','leasePets','leaseNonVeg',
  'propertyType','societyName','totalFloors','electricityIncluded','waterCharge',
  'escalation','listedBy','googleMapsLink','videoUrl',
  'ownerName','ownerNumber','ownerEmail','ownerAltPhone','ownerAddress','contactTime',
  'fullAddress','negotiable','submittedBy'
];

const URL_FIELDS  = ['googleMapsLink', 'videoUrl'];
const MAX_LENGTHS = { title: 200, desc: 5000, loc: 200, fullAddress: 500,
                      ownerName: 100, ownerAddress: 300, contactTime: 100 };

function validatePropertyFields(fields) {
  for (const f of URL_FIELDS) {
    if (fields[f] && fields[f].trim()) {
      try { new URL(fields[f].trim()); } catch { return `Invalid URL in field '${f}'.`; }
    }
  }
  for (const [f, max] of Object.entries(MAX_LENGTHS)) {
    if (fields[f] && String(fields[f]).length > max)
      return `Field '${f}' must be at most ${max} characters.`;
  }
  if (fields.ownerEmail && fields.ownerEmail.trim() &&
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fields.ownerEmail.trim()))
    return `Invalid email address in field 'ownerEmail'.`;
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
    const fields = PROPERTY_FIELDS.reduce((acc, k) => { if (k in body) acc[k] = body[k]; return acc; }, {});

    const validationError = validatePropertyFields(fields);
    if (validationError) return res.status(400).json({ message: validationError });

    if (!fields.title || !fields.loc || !fields.price) {
      return res.status(400).json({ message: 'title, loc, and price are required.' });
    }

    fields.displayPrice = formatPrice(fields.price, fields.status);

    const prop = new Property(fields);
    await prop.save();

    res.status(201).json({ message: 'Property added successfully!', property: prop });
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
    if (status) filter.status = status;
    if (q) {
      const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filter.$or = [{ title: re }, { loc: re }, { desc: re }];
    }

    const docs = await Property.find(filter)
      .sort({ promoted: -1, promotedPriority: 1, createdAt: -1 })
      .skip(Number(skip))
      .limit(Number(limit))
      .select(PROPERTY_FIELDS.join(' ') + ' _id promoted promotedPriority createdAt views')
      .lean();

    // Map schema field names → frontend field names expected by index.html
    const mapped = docs.map(doc => ({
      ...doc,
      id:         String(doc._id),
      // type tab (Rent/Lease/PG) from status enum
      type:       doc.status === 'For Rent' ? 'Rent'
                : doc.status === 'Lease'    ? 'Lease'
                : doc.status === 'PG'       ? 'PG'
                : doc.status,
      location:   doc.loc,
      bathrooms:  parseInt(doc.toilet) || 1,
      carpark:    doc.carparking === 'Yes',
      bikepark:   doc.bikeparking === 'Yes',
      lift:       (doc.amenities || []).some(a => /lift/i.test(a)),
      tenant:     doc.tenantPref || 'Any',
      ownerPhone: doc.ownerNumber || '',
      posted:     doc.createdAt
                    ? new Date(doc.createdAt).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' })
                    : 'Recently',
      verified:   false,
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