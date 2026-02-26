const mongoose = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose');
const findOrCreate = require('mongoose-findorcreate');

// Admin Schema
const adminSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    fullName: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    role: {
        type: String,
        default: 'admin'
    },
    active: {
        type: Boolean,
        default: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// SubAdmin Schema
const subAdminSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    fullName: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    role: {
        type: String,
        default: 'subadmin'
    },
    permissions: [String],
    active: {
        type: Boolean,
        default: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Recent Trip Schema
const recentTripSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true
    },
    description: {
        type: String,
        required: true,
        trim: true
    },
    imageUrl: {
        type: String,
        required: true
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Admin',
        required: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Update timestamps on save
recentTripSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

// Tour Package Schema
const tourPackageSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true
    },
    description: {
        type: String,
        required: true,
        trim: true
    },
    imageUrl: {
        type: String,
        default: ''
    },
    gallery: [{
        url: {
            type: String,
            required: true
        },
        caption: {
            type: String,
            default: ''
        },
        alt: {
            type: String,
            default: ''
        }
    }],
    stars: {
        type: Number,
        required: true,
        min: 1,
        max: 5
    },
    price: {
        type: Number,
        required: true,
        min: 0
    },
    duration: {
        type: String,
        trim: true
    },
    location: {
        type: String,
        trim: true
    },
    maxGroupSize: {
        type: Number,
        min: 1
    },
    included: [{
        type: String,
        trim: true
    }],
    excluded: [{
        type: String,
        trim: true
    }],
    highlights: [{
        type: String,
        trim: true
    }],
    featured: {
        type: Boolean,
        default: false
    },
    active: {
        type: Boolean,
        default: true
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Admin',
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Hiking Schema
const hikingSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true
    },
    description: {
        type: String,
        required: true,
        trim: true
    },
    imageUrl: {
        type: String,
        default: ''
    },
    gallery: [{
        url: {
            type: String,
            required: true
        },
        caption: {
            type: String,
            default: ''
        },
        alt: {
            type: String,
            default: ''
        }
    }],
    stars: {
        type: Number,
        required: true,
        min: 1,
        max: 5
    },
    reviews: {
        type: Number,
        default: 0
    },
    location: {
        type: String,
        required: true,
        trim: true
    },
    difficulty: {
        type: String,
        enum: ['easy', 'moderate', 'hard', 'expert'],
        default: 'moderate'
    },
    activity: {
        type: String,
        enum: ['hiking', 'trekking', 'photography', 'trophy hunting', 'camping', 'cultural', 'sports', 'adventure sports'],
        default: 'hiking'
    },
    duration: {
        type: String,
        trim: true
    },
    price: {
        type: Number,
        required: true,
        min: 0
    },
    distance: {
        type: String,
        trim: true
    },
    pickup: {
        type: String,
        enum: ['Bus', 'Car', 'By Air', 'Bus & Car', 'Car & By Air', 'Bus & By Air', 'All Options', 'Not Available'],
        default: 'Not Available'
    },
    elevation: {
        type: String,
        trim: true
    },
    bestTime: {
        type: String,
        trim: true
    },
    features: [{
        type: String,
        trim: true
    }],
    tips: [{
        type: String,
        trim: true
    }],
    featured: {
        type: Boolean,
        default: false
    },
    active: {
        type: Boolean,
        default: true
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Admin',
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Update timestamps on save
tourPackageSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

// Update timestamps on save
hikingSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

// Payment Settings (admin-configured QR and bank details)
const paymentSettingSchema = new mongoose.Schema({
    qrImageUrl: { type: String, default: '' },
    bankName: { type: String, default: '' },
    accountName: { type: String, default: '' },
    accountNumber: { type: String, default: '' },
    iban: { type: String, default: '' },
    swift: { type: String, default: '' },
    instructions: { type: String, default: '' },
    updatedAt: { type: Date, default: Date.now }
});

paymentSettingSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

// Payment Requests (submitted from website)
const paymentRequestSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    userEmail: { type: String, required: true, trim: true },
    userName: { type: String, default: '' },
    tourPackageId: { type: mongoose.Schema.Types.ObjectId, ref: 'TourPackage' },
    hikingId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hiking' },
    bookingId: { type: mongoose.Schema.Types.ObjectId, ref: 'Booking' }, // Link to booking
    amount: { type: Number, required: true, min: 0 },
    currency: { type: String, default: 'USD' },
    paymentMethod: { type: String, default: 'bank_transfer' },
    transactionId: { type: String, default: '' },
    proofImageUrl: { type: String, default: '' },
    notes: { type: String, default: '' },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

paymentRequestSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

// Testimonial Schema
const testimonialSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    country: {
        type: String,
        required: true,
        trim: true
    },
    avatarUrl: {
        type: String,
        default: ''
    },
    storyImgUrl: {
        type: String,
        default: ''
    },
    active: {
        type: Boolean,
        default: true
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Admin',
        required: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

testimonialSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

// Apply plugins
adminSchema.plugin(passportLocalMongoose);
adminSchema.plugin(findOrCreate);

subAdminSchema.plugin(passportLocalMongoose);
subAdminSchema.plugin(findOrCreate);

// Booking Schema (read bookings created by public site)
const bookingSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    tourPackageId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'TourPackage',
        required: false
    },
    hikingId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Hiking',
        required: false
    },
    bookingNumber: {
        type: String,
        required: true,
        unique: true
    },
    customerInfo: {
        firstName: String,
        lastName: String,
        email: String,
        phone: String,
        nationality: String,
        emergencyContact: {
            name: String,
            phone: String,
            relationship: String
        }
    },
    travelInfo: {
        departureDate: Date,
        returnDate: Date,
        numberOfTravelers: Number,
        specialRequests: String
    },
    paymentInfo: {
        amount: Number,
        currency: { type: String, default: 'USD' },
        stripePaymentIntentId: String,
        stripeChargeId: String,
        paymentStatus: { type: String, enum: ['pending', 'completed', 'failed', 'refunded'], default: 'pending' },
        paymentDate: { type: Date, default: Date.now }
    },
    bookingStatus: { type: String, enum: ['pending', 'confirmed', 'cancelled', 'completed'], default: 'pending' },
    notes: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

bookingSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

// User Schema (from Tourist Website)
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    fullName: {
        type: String,
        required: true
    },
    phone: String,
    nationality: String,
    active: {
        type: Boolean,
        default: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Order Schema (from Tourist Website)
const orderSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    items: [{
        productId: {
            type: mongoose.Schema.Types.ObjectId,
            required: true
        },
        productType: {
            type: String,
            enum: ['tour', 'hiking'],
            required: true
        },
        quantity: Number,
        price: Number
    }],
    totalAmount: {
        type: Number,
        required: true
    },
    paymentStatus: {
        type: String,
        enum: ['pending', 'completed', 'failed', 'refunded'],
        default: 'pending'
    },
    bookingNumber: String,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Review Schema (from Tourist Website)
const reviewSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    productId: {
        type: String,
        required: true
    },
    productType: {
        type: String,
        enum: ['tour', 'hiking'],
        required: true
    },
    rating: {
        type: Number,
        required: true,
        min: 1,
        max: 5
    },
    title: String,
    comment: {
        type: String,
        required: true
    },
    verified: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Apply plugins to User schema
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Create models
const Admin = mongoose.model('Admin', adminSchema);
const SubAdmin = mongoose.model('SubAdmin', subAdminSchema);
const RecentTrip = mongoose.model('RecentTrip', recentTripSchema);
const TourPackage = mongoose.model('TourPackage', tourPackageSchema);
const Hiking = mongoose.model('Hiking', hikingSchema);
const Booking = mongoose.model('Booking', bookingSchema);

// Tourist Website models (aliased to avoid conflicts)
const User = mongoose.model('User', userSchema);
const Order = mongoose.model('Order', orderSchema);
const Review = mongoose.model('Review', reviewSchema);

// Payments models
const PaymentSetting = mongoose.model('PaymentSetting', paymentSettingSchema);
const PaymentRequest = mongoose.model('PaymentRequest', paymentRequestSchema);

// Testimonial model
const Testimonial = mongoose.model('Testimonial', testimonialSchema);

// Create aliases for Tour Package, RecentTrip, Hiking, andBooking models to match Tourist Website naming
const TouristRecentTrip = RecentTrip;
const TouristTourPackage = TourPackage;
const TouristHiking = Hiking;
const TouristBooking = Booking;

module.exports = {
    Admin,
    SubAdmin,
    RecentTrip,
    TourPackage,
    Hiking,
    Booking,
    // Export Tourist Website models with aliases
    User,
    Order,
    Review,
    TouristRecentTrip,
    TouristTourPackage,
    TouristHiking,
    TouristBooking,
    PaymentSetting,
    PaymentRequest,
    Testimonial
};
