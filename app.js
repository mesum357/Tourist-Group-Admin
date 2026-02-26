require('dotenv').config();
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const findOrCreate = require('mongoose-findorcreate');
const passportLocalMongoose = require('passport-local-mongoose');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const expressLayouts = require('express-ejs-layouts');

// mongodb+srv://mesum357:pDliM118811@cluster0.h3knh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0

// Import models from db.js
const {
    SubAdmin,
    Admin,
    RecentTrip,
    TourPackage,
    Hiking,
    Booking,
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
} = require('./db');

// Increase body parser limits for image uploads
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(bodyParser.json({ limit: '50mb' }));
app.set('view engine', 'ejs');
app.set('layout', 'layout');
app.use(expressLayouts);
app.use(express.static(path.join(__dirname, 'public')));

// Explicitly serve uploads with cache headers for production
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads'), {
    setHeaders: (res) => {
        // cache images for 7 days
        res.setHeader('Cache-Control', 'public, max-age=604800, immutable');
    }
}));

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, 'public', 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit per file
    },
    fileFilter: function (req, file, cb) {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// MONGOOSE
const mongooseOptions = {};

if (process.env.NODE_ENV === 'production') {
    mongooseOptions.ssl = true;
    mongooseOptions.tls = true;
    mongooseOptions.tlsAllowInvalidCertificates = true;
    mongooseOptions.tlsAllowInvalidHostnames = true;
}

// Get MongoDB URI from environment variables
const mongoURI = process.env.MONGODB_URI;
console.log("Environment variables loaded:", !!process.env.MONGODB_URI);
console.log("MongoURI:", mongoURI ? "MongoURI found" : "MongoURI not found");

if (!mongoURI) {
    console.error("MONGODB_URI is not defined in environment variables");
    console.error("Available env vars:", Object.keys(process.env).filter(key => key.includes('MONGO')));
    process.exit(1);
}

mongoose.connect(mongoURI, {
    serverSelectionTimeoutMS: 5000,
    connectTimeoutMS: 10000
})
    .then(() => {
        console.log("Connected to MongoDB database:", mongoose.connection.name);
    })
    .catch((err) => {
        console.error("Error connecting to MongoDB Atlas:", err);
        process.exit(1);
    });



// Passport configuration
passport.use('local', new (require('passport-local').Strategy)({
    usernameField: 'email',
    passwordField: 'password'
}, async function (email, password, done) {
    try {
        const user = await Admin.findOne({ email: email });
        if (!user) {
            return done(null, false, { message: 'Incorrect email.' });
        }

        const isMatch = await new Promise((resolve) => {
            user.authenticate(password, (err, result) => {
                if (err) {
                    resolve(false);
                } else {
                    resolve(result);
                }
            });
        });

        if (isMatch) {
            return done(null, user);
        } else {
            return done(null, false, { message: 'Incorrect password.' });
        }
    } catch (err) {
        return done(err);
    }
}));
passport.use('subadmin-local', SubAdmin.createStrategy({
    usernameField: 'email',
    passwordField: 'password'
}));

passport.serializeUser(function (user, done) {
    done(null, { id: user.id, type: user.constructor.modelName });
});

passport.deserializeUser(async function (obj, done) {
    if (obj.type === 'Admin') {
        const user = await Admin.findById(obj.id);
        done(null, user);
    } else if (obj.type === 'SubAdmin') {
        const user = await SubAdmin.findById(obj.id);
        done(null, user);
    } else {
        done(new Error('No user type found'), null);
    }
});


// Set up layout
app.set('view engine', 'ejs');

// Routes

// Dashboard route - using modern layout
app.get('/', ensureAuthenticated, async function (req, res) {
    try {
        // Check MongoDB connection status
        const dbState = mongoose.connection.readyState;
        const states = { 0: 'disconnected', 1: 'connected', 2: 'connecting', 3: 'disconnecting' };
        console.log(`MongoDB state: ${states[dbState]} (${dbState})`);

        // Fetch real data from the database

        // Get total revenue from completed bookings (from Tourist Website)
        let revenueData;
        try {
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Revenue aggregation timeout')), 15000)
            );
            const aggregationPromise = TouristBooking.aggregate([
                { $match: { 'paymentInfo.paymentStatus': 'completed' } },
                {
                    $group: {
                        _id: null,
                        totalRevenue: { $sum: '$paymentInfo.amount' },
                        count: { $sum: 1 }
                    }
                }
            ]);
            revenueData = await Promise.race([aggregationPromise, timeoutPromise]);
        } catch (error) {
            console.error('Revenue aggregation error:', error.message);
            revenueData = [{ totalRevenue: 0, count: 0 }];
        }

        // Get revenue comparison (current month vs last month)
        const currentMonth = new Date();
        const lastMonth = new Date();
        lastMonth.setMonth(currentMonth.getMonth() - 1);

        let currentMonthRevenue, lastMonthRevenue;
        try {
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Monthly aggregation timeout')), 12000)
            );

            const currentMonthPromise = TouristBooking.aggregate([
                {
                    $match: {
                        'paymentInfo.paymentStatus': 'completed',
                        'createdAt': { $gte: new Date(currentMonth.getFullYear(), currentMonth.getMonth(), 1) }
                    }
                },
                {
                    $group: {
                        _id: null,
                        totalRevenue: { $sum: '$paymentInfo.amount' },
                        count: { $sum: 1 }
                    }
                }
            ]);

            const lastMonthPromise = TouristBooking.aggregate([
                {
                    $match: {
                        'paymentInfo.paymentStatus': 'completed',
                        'createdAt': {
                            $gte: new Date(lastMonth.getFullYear(), lastMonth.getMonth(), 1),
                            $lt: new Date(currentMonth.getFullYear(), currentMonth.getMonth(), 1)
                        }
                    }
                },
                {
                    $group: {
                        _id: null,
                        totalRevenue: { $sum: '$paymentInfo.amount' },
                        count: { $sum: 1 }
                    }
                }
            ]);

            const results = await Promise.race([
                Promise.all([currentMonthPromise, lastMonthPromise]),
                timeoutPromise
            ]);
            currentMonthRevenue = results[0];
            lastMonthRevenue = results[1];
        } catch (error) {
            console.error('Monthly revenue aggregation error:', error.message);
            currentMonthRevenue = [{ totalRevenue: 0, count: 0 }];
            lastMonthRevenue = [{ totalRevenue: 0, count: 0 }];
        }

        // Get count of active users (users who made bookings) - simplified
        let activeUsersCount = 0;
        try {
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Active users timeout')), 8000)
            );
            const userPromise = TouristBooking.distinct('userId').then(userIds => userIds.length);
            activeUsersCount = await Promise.race([userPromise, timeoutPromise]);
        } catch (error) {
            console.error('Active users query error:', error.message);
        }

        // Get tour packages count - simplified
        let tourPackagesCount = 0;
        try {
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Tour packages timeout')), 5000)
            );
            const tourPromise = TouristTourPackage.countDocuments();
            tourPackagesCount = await Promise.race([tourPromise, timeoutPromise]);
        } catch (error) {
            console.error('Tour packages count error:', error.message);
        }

        // Get hiking trails count - simplified
        let hikingTrailsCount = 0;
        try {
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Hiking trails timeout')), 5000)
            );
            const hikingPromise = TouristHiking.countDocuments();
            hikingTrailsCount = await Promise.race([hikingPromise, timeoutPromise]);
        } catch (error) {
            console.error('Hiking trails count error:', error.message);
        }

        // Get recent bookings - simplified without population to avoid joins
        let recentBookings = [];
        try {
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Recent bookings timeout')), 8000)
            );
            const bookingsPromise = TouristBooking.find({ 'paymentInfo.paymentStatus': 'completed' })
                .sort({ createdAt: -1 })
                .limit(5);
            recentBookings = await Promise.race([bookingsPromise, timeoutPromise]);
        } catch (error) {
            console.error('Recent bookings query error:', error.message);
        }

        // Calculate revenue change percentage
        const totalRevenue = revenueData[0]?.totalRevenue || 0;
        const currentMonthRev = currentMonthRevenue[0]?.totalRevenue || 0;
        const lastMonthRev = lastMonthRevenue[0]?.totalRevenue || 0;
        const revenueChange = lastMonthRev > 0 ? ((currentMonthRev - lastMonthRev) / lastMonthRev) * 100 : 0;

        // Calculate booking change percentage
        const currentMonthBookings = currentMonthRevenue[0]?.count || 0;
        const lastMonthBookings = lastMonthRevenue[0]?.count || 0;
        const bookingChange = lastMonthBookings > 0 ? ((currentMonthBookings - lastMonthBookings) / lastMonthBookings) * 100 : 0;

        // Get recent trips count - simplified
        let recentTripsCount = 0;
        try {
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Recent trips count timeout')), 5000)
            );
            const tripsPromise = TouristRecentTrip.countDocuments();
            recentTripsCount = await Promise.race([tripsPromise, timeoutPromise]);
        } catch (error) {
            console.error('Recent trips count error:', error.message);
        }

        // Get booking data by month for the last 12 months - simplified
        let bookingDataByMonth = [];
        try {
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Booking aggregate timeout')), 18000)
            );
            const now = new Date();
            const twelveMonthsAgo = new Date();
            twelveMonthsAgo.setMonth(now.getMonth() - 12);

            const aggregatePromise = TouristBooking.aggregate([
                {
                    $match: {
                        'paymentInfo.paymentStatus': 'completed',
                        'createdAt': { $gte: twelveMonthsAgo }
                    }
                },
                {
                    $group: {
                        _id: {
                            year: { $year: '$createdAt' },
                            month: { $month: '$createdAt' }
                        },
                        bookingCount: { $sum: 1 }
                    }
                },
                {
                    $sort: { '_id.year': 1, '_id.month': 1 }
                }
            ]);

            bookingDataByMonth = await Promise.race([aggregatePromise, timeoutPromise]);
        } catch (aggregateError) {
            console.error('Booking aggregation error:', aggregateError.message);
            // Fallback: Create empty chart data if aggregation fails
            bookingDataByMonth = [];
        }

        // Get average rating - simplified
        let avgRatingData;
        try {
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Review aggregation timeout')), 10000)
            );
            const reviewPromise = Review.aggregate([
                {
                    $group: {
                        _id: null,
                        avgRating: { $avg: '$rating' },
                        totalReviews: { $sum: 1 }
                    }
                }
            ]);
            avgRatingData = await Promise.race([reviewPromise, timeoutPromise]);
        } catch (error) {
            console.error('Review aggregation error:', error.message);
            avgRatingData = [{ avgRating: 0, totalReviews: 0 }];
        }

        const avgRating = avgRatingData[0]?.avgRating || 0;
        const totalReviews = avgRatingData[0]?.totalReviews || 0;

        res.render('index', {
            title: 'Dashboard',
            pageTitle: 'Dashboard',
            currentPage: 'dashboard',
            user: req.user,
            layout: 'layout',
            dashboardData: {
                totalRevenue,
                revenueChange,
                totalBookings: revenueData[0]?.count || 0,
                bookingChange,
                activeUsersCount,
                tourPackagesCount,
                hikingTrailsCount,
                recentTripsCount,
                recentBookings,
                avgRating: avgRating.toFixed(1),
                totalReviews,
                bookingDataByMonth
            }
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        // Fallback to original render with error message and default data
        res.render('index', {
            title: 'Dashboard',
            pageTitle: 'Dashboard',
            currentPage: 'dashboard',
            user: req.user,
            layout: 'layout',
            error: 'Unable to load dashboard data',
            dashboardData: {
                totalRevenue: 0,
                revenueChange: 0,
                totalBookings: 0,
                bookingChange: 0,
                activeUsersCount: 0,
                tourPackagesCount: 0,
                hikingTrailsCount: 0,
                galleryCount: 0,
                recentBookings: [],
                avgRating: '0.0',
                totalReviews: 0,
                bookingDataByMonth: []
            }
        });
    }
});

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login?error=Please login to access this page');
}

// Login page route
app.get('/login', function (req, res) {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    }
    res.render('login', {
        title: 'Login',
        value: req.isAuthenticated() ? 1 : 0,
        data: req.user,
        error: req.query.error,
        success: req.query.success,
        layout: false
    });
});

// Register page route
app.get('/register', function (req, res) {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    }
    res.render('register', {
        title: 'Register',
        value: req.isAuthenticated() ? 1 : 0,
        data: req.user,
        error: req.query.error,
        success: req.query.success,
        layout: false
    });
});

app.post("/register", function (req, res) {
    console.log('Registration request received');
    console.log('req.body:', req.body);
    console.log('req.headers:', req.headers);

    const { name, email, password, confirmPassword } = req.body;
    console.log('Registration attempt:', { name, email, password: password ? '***' : 'missing', confirmPassword: confirmPassword ? '***' : 'missing' });

    // Validation
    if (!name || !email || !password || !confirmPassword) {
        console.log('Registration failed: Missing required fields');
        return res.redirect('/register?error=All fields are required');
    }
    if (password !== confirmPassword) {
        console.log('Registration failed: Passwords do not match');
        return res.redirect('/register?error=Passwords do not match');
    }
    if (password.length < 6) {
        console.log('Registration failed: Password too short');
        return res.redirect('/register?error=Password must be at least 6 characters long');
    }

    // Use Admin.register directly with user data and password
    Admin.register({ username: email, fullName: name, email: email }, password, function (err, user) {
        if (err) {
            console.error('Registration error:', err);
            let errorMessage = 'Registration failed';
            if (err.name === 'UserExistsError') {
                errorMessage = 'User already exists with this email';
            }
            return res.redirect(`/register?error=${encodeURIComponent(errorMessage)}`);
        }
        console.log('Registration successful for user:', {
            email: user.email,
            username: user.username,
            fullName: user.fullName,
            hasPassword: !!user.password,
            salt: !!user.salt,
            hash: !!user.hash
        });
        res.redirect(`/login?success=Account created successfully with email: ${user.email}! Please login to continue.`);
    });
});

app.post("/login", function (req, res, next) {
    console.log('Login request received');
    console.log('req.body:', req.body);
    console.log('req.headers:', req.headers);

    const { email, password } = req.body;
    console.log('Login attempt:', { email: email, password: password ? '***' : 'missing' });

    // Validation
    if (!email || !password) {
        console.log('❌ Login failed: Missing email or password');
        return res.redirect('/login?error=Email and password are required');
    }

    // First check if user exists
    Admin.findOne({ email: email }).then(user => {
        if (!user) {
            console.log('❌ User not found in database for email:', email);
            return res.redirect('/login?error=No account found with this email address');
        }
        console.log('✅ User found in database:', { email: user.email, username: user.username });

        // Now try Passport authentication
        passport.authenticate("local", function (err, user, info) {
            if (err) {
                console.error('❌ Login error:', err);
                return next(err);
            }
            if (!user) {
                console.log('❌ Login failed: Invalid password for user:', email);
                return res.redirect('/login?error=Incorrect password');
            }
            console.log('✅ Login successful for user:', user.email);
            req.logIn(user, function (err) {
                if (err) {
                    console.error('❌ Session error:', err);
                    return next(err);
                }
                console.log('✅ Session created successfully');
                return res.redirect('/?success=Welcome back');
            });
        })(req, res, next);
    }).catch(err => {
        console.error('❌ Database error:', err);
        return res.redirect('/login?error=Database error occurred');
    });
});


// Tour Packages route - using modern layout
app.get('/tour', ensureAuthenticated, function (req, res) {
    res.render('tour', {
        title: 'Tour Packages',
        pageTitle: 'Tour Packages',
        currentPage: 'tour',
        user: req.user,
        layout: 'layout'
    });
});

// Hiking route - using modern layout
app.get('/hiking', ensureAuthenticated, function (req, res) {
    res.render('hiking', {
        title: 'Hiking Trails',
        pageTitle: 'Hiking Trails',
        currentPage: 'hiking',
        user: req.user,
        layout: 'layout'
    });
});

// Users route - using modern layout
app.get('/users', ensureAuthenticated, function (req, res) {
    res.render('users', {
        title: 'Users',
        pageTitle: 'Users',
        currentPage: 'users',
        user: req.user,
        layout: 'layout'
    });
});

// Recent Trips route - using modern layout
app.get('/recent-trips', ensureAuthenticated, function (req, res) {
    res.render('recent-trips', {
        title: 'Recent Trips',
        pageTitle: 'Recent Trips',
        currentPage: 'recentTrips',
        user: req.user,
        layout: 'layout'
    });
});

// Bookings route - using modern layout
app.get('/bookings', ensureAuthenticated, function (req, res) {
    res.render('bookings', {
        title: 'Bookings',
        pageTitle: 'Bookings',
        currentPage: 'bookings',
        user: req.user,
        layout: 'layout'
    });
});

// Settings route - using modern layout
app.get('/settings', ensureAuthenticated, function (req, res) {
    res.render('settings', {
        title: 'Settings',
        pageTitle: 'Settings',
        currentPage: 'settings',
        user: req.user,
        layout: 'layout'
    });
});

// Payments Management route (tabs: requests, settings)
app.get('/payments', ensureAuthenticated, async function (req, res) {
    try {
        const settings = await PaymentSetting.findOne();
        res.render('payments', {
            title: 'Payments Management',
            pageTitle: 'Payments Management',
            currentPage: 'payments',
            user: req.user,
            layout: 'layout',
            settings: settings || {}
        });
    } catch (e) {
        res.render('payments', {
            title: 'Payments Management',
            pageTitle: 'Payments Management',
            currentPage: 'payments',
            user: req.user,
            layout: 'layout',
            settings: {}
        });
    }
});

// Payments API - admin protected
app.get('/api/payment/settings', ensureAuthenticated, async function (req, res) {
    try {
        const settings = await PaymentSetting.findOne();
        res.json(settings || {});
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

app.put('/api/payment/settings', ensureAuthenticated, upload.single('qr'), async function (req, res) {
    try {
        const update = {
            bankName: req.body.bankName || '',
            accountName: req.body.accountName || '',
            accountNumber: req.body.accountNumber || '',
            iban: req.body.iban || '',
            swift: req.body.swift || '',
            instructions: req.body.instructions || ''
        };
        if (req.file) {
            update.qrImageUrl = `/uploads/${req.file.filename}`;
        } else if (typeof req.body.qrImageUrl === 'string') {
            update.qrImageUrl = req.body.qrImageUrl;
        }

        const settings = await PaymentSetting.findOneAndUpdate({}, update, { new: true, upsert: true });
        res.json(settings);
    } catch (e) {
        console.error('Update settings failed:', e);
        res.status(500).json({ error: 'Failed to update settings' });
    }
});

app.get('/api/payment/requests', ensureAuthenticated, async function (req, res) {
    try {
        const status = req.query.status;
        const filter = status ? { status } : {};
        const requests = await PaymentRequest.find(filter).sort({ createdAt: -1 });
        console.log('Payment requests found:', requests.length);
        console.log('Database connection:', mongoose.connection.name, 'Host:', mongoose.connection.host, 'Port:', mongoose.connection.port);
        if (requests.length > 0) {
            console.log('Sample request with image:', {
                id: requests[0]._id,
                proofImageUrl: requests[0].proofImageUrl,
                hasImage: !!requests[0].proofImageUrl
            });
        } else {
            console.log('No payment requests found in database');
        }
        res.json(requests);
    } catch (e) {
        console.error('Error fetching payment requests:', e);
        res.status(500).json({ error: 'Failed to fetch requests' });
    }
});

app.patch('/api/payment/requests/:id', ensureAuthenticated, async function (req, res) {
    try {
        const { status, notes } = req.body;
        const allowed = ['pending', 'approved', 'rejected'];
        if (status && !allowed.includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        const update = {};
        if (status) update.status = status;
        if (typeof notes === 'string') update.notes = notes;
        const updated = await PaymentRequest.findByIdAndUpdate(req.params.id, update, { new: true });
        if (!updated) return res.status(404).json({ error: 'Not found' });

        // Update linked booking status if payment request has a bookingId
        if (updated.bookingId && status) {
            let bookingStatus = 'pending';
            let paymentStatus = 'pending';

            if (status === 'approved') {
                bookingStatus = 'confirmed';
                paymentStatus = 'completed';
            } else if (status === 'rejected') {
                bookingStatus = 'cancelled';
                paymentStatus = 'failed';
            }

            // Update the booking
            const booking = await TouristBooking.findByIdAndUpdate(updated.bookingId, {
                bookingStatus: bookingStatus,
                'paymentInfo.paymentStatus': paymentStatus
            }, { new: true });

            console.log(`Updated booking ${updated.bookingId} status to ${bookingStatus} based on payment request ${status}`);

            // Send email notification to user about booking status change
            if (booking && booking.customerInfo && booking.customerInfo.email) {
                try {
                    const nodemailer = require('nodemailer');

                    // Email configuration (you may need to adjust these settings)
                    const transporter = nodemailer.createTransporter({
                        service: 'gmail',
                        auth: {
                            user: process.env.GMAIL_USER,
                            pass: process.env.GMAIL_APP_PASSWORD
                        }
                    });

                    let emailSubject, emailBody;

                    if (status === 'approved') {
                        emailSubject = `Booking Confirmed - ${booking.bookingNumber}`;
                        emailBody = `
                            <h2>🎉 Your Booking Has Been Confirmed!</h2>
                            <p>Dear ${booking.customerInfo.firstName} ${booking.customerInfo.lastName},</p>
                            <p>Great news! Your payment has been approved and your booking is now confirmed.</p>
                            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                                <h3>Booking Details:</h3>
                                <p><strong>Booking Number:</strong> ${booking.bookingNumber}</p>
                                <p><strong>Amount Paid:</strong> $${updated.amount}</p>
                                <p><strong>Status:</strong> Confirmed</p>
                            </div>
                            <p>You will receive further details about your tour shortly. Thank you for choosing our services!</p>
                            <p>Best regards,<br>Tourist Website Team</p>
                        `;
                    } else if (status === 'rejected') {
                        emailSubject = `Booking Cancelled - ${booking.bookingNumber}`;
                        emailBody = `
                            <h2>Booking Cancelled</h2>
                            <p>Dear ${booking.customerInfo.firstName} ${booking.customerInfo.lastName},</p>
                            <p>We regret to inform you that your payment could not be approved and your booking has been cancelled.</p>
                            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                                <h3>Booking Details:</h3>
                                <p><strong>Booking Number:</strong> ${booking.bookingNumber}</p>
                                <p><strong>Amount:</strong> $${updated.amount}</p>
                                <p><strong>Status:</strong> Cancelled</p>
                            </div>
                            <p>Please contact our support team for assistance or submit a new payment if you wish to proceed with your booking.</p>
                            <p>Best regards,<br>Tourist Website Team</p>
                        `;
                    }

                    await transporter.sendMail({
                        from: process.env.GMAIL_USER,
                        to: booking.customerInfo.email,
                        subject: emailSubject,
                        html: emailBody
                    });

                    console.log(`Email notification sent to ${booking.customerInfo.email} for booking ${booking.bookingNumber}`);
                } catch (emailError) {
                    console.error('Failed to send email notification:', emailError);
                    // Don't fail the request if email fails
                }
            }
        }

        res.json(updated);
    } catch (e) {
        console.error('Error updating payment request:', e);
        res.status(500).json({ error: 'Failed to update request' });
    }
});

// Public endpoint for website to fetch settings (CORS open)
app.get('/public/payment-settings', async function (req, res) {
    try {
        res.setHeader('Access-Control-Allow-Origin', '*');
        const settings = await PaymentSetting.findOne();
        const base = `${req.protocol}://${req.get('host')}`;
        const qr = settings?.qrImageUrl || '';
        const absoluteQr = qr ? (qr.startsWith('http') ? qr : base + (qr.startsWith('/') ? '' : '/') + qr) : '';
        res.json({
            qrImageUrl: absoluteQr,
            bankName: settings?.bankName || '',
            accountName: settings?.accountName || '',
            accountNumber: settings?.accountNumber || '',
            iban: settings?.iban || '',
            swift: settings?.swift || '',
            instructions: settings?.instructions || ''
        });
    } catch (e) {
        res.status(200).json({});
    }
});

// Recent Trips API Routes
app.get('/api/recent-trips', ensureAuthenticated, async function (req, res) {
    try {
        const recentTrips = await RecentTrip.find().populate('createdBy', 'fullName').sort({ createdAt: -1 });
        res.json(recentTrips);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch recent trips' });
    }
});

app.post('/api/recent-trips', ensureAuthenticated, upload.single('image'), async function (req, res) {
    try {
        const { title, description } = req.body;

        let imageUrl = '';
        if (req.file) {
            imageUrl = `/uploads/${req.file.filename}`;
        } else if (req.body.imageUrl) {
            imageUrl = req.body.imageUrl;
        }

        const trip = new RecentTrip({
            title,
            description,
            imageUrl,
            createdBy: req.user._id
        });

        await trip.save();
        res.json(trip);
    } catch (err) {
        res.status(500).json({ error: 'Failed to create recent trip' });
    }
});

app.put('/api/recent-trips/:id', ensureAuthenticated, upload.single('image'), async function (req, res) {
    try {
        const { title, description } = req.body;

        const updateData = {
            title,
            description,
            updatedAt: Date.now()
        };

        if (req.file) {
            updateData.imageUrl = `/uploads/${req.file.filename}`;
        } else if (req.body.imageUrl) {
            updateData.imageUrl = req.body.imageUrl;
        }

        const trip = await RecentTrip.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true }
        );

        if (!trip) {
            return res.status(404).json({ error: 'Trip not found' });
        }

        res.json(trip);
    } catch (err) {
        res.status(500).json({ error: 'Failed to update recent trip' });
    }
});

app.delete('/api/recent-trips/:id', ensureAuthenticated, async function (req, res) {
    try {
        const trip = await RecentTrip.findByIdAndDelete(req.params.id);

        if (!trip) {
            return res.status(404).json({ error: 'Trip not found' });
        }

        // Optional: delete image file from fs
        if (trip.imageUrl && trip.imageUrl.startsWith('/uploads/')) {
            const filePath = path.join(__dirname, 'public', trip.imageUrl);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        }

        res.json({ message: 'Trip deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete recent trip' });
    }
});

// Tour Package API Routes
app.get('/api/tour-packages', ensureAuthenticated, async function (req, res) {
    try {
        const tourPackages = await TourPackage.find().populate('createdBy', 'fullName').sort({ createdAt: -1 });
        res.json(tourPackages);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch tour packages' });
    }
});

app.post('/api/tour-packages', ensureAuthenticated, upload.single('image'), async function (req, res) {
    try {
        console.log('Tour package creation request:', req.body);
        const { title, description, gallery, stars, price, duration, location, maxGroupSize, included, excluded, highlights, featured } = req.body;

        // Handle uploaded image
        let imageUrl = '';
        if (req.file) {
            imageUrl = `/uploads/${req.file.filename}`;
        }

        // Parse gallery if it's a string
        let galleryArray = [];
        if (gallery) {
            if (typeof gallery === 'string') {
                try {
                    galleryArray = JSON.parse(gallery);
                } catch (e) {
                    console.log('Error parsing gallery JSON:', e);
                    galleryArray = [];
                }
            } else if (Array.isArray(gallery)) {
                galleryArray = gallery;
            }
        }

        console.log('Gallery data:', galleryArray);

        const tourPackage = new TourPackage({
            title,
            description,
            imageUrl: imageUrl || '',
            gallery: galleryArray,
            stars: parseInt(stars),
            price: parseFloat(price),
            duration,
            location,
            maxGroupSize: maxGroupSize ? parseInt(maxGroupSize) : undefined,
            included: included ? included.split(',').map(item => item.trim()) : [],
            excluded: excluded ? excluded.split(',').map(item => item.trim()) : [],
            highlights: highlights ? highlights.split(',').map(item => item.trim()) : [],
            featured: featured === 'true',
            createdBy: req.user._id
        });

        console.log('Creating tour package:', tourPackage);
        await tourPackage.save();
        console.log('Tour package saved successfully:', tourPackage._id);
        res.json(tourPackage);
    } catch (err) {
        console.error('Error creating tour package:', err);
        console.error('Error details:', err.message);
        console.error('Error stack:', err.stack);
        res.status(500).json({ error: 'Failed to create tour package: ' + err.message });
    }
});

app.put('/api/tour-packages/:id', ensureAuthenticated, async function (req, res) {
    try {
        const { title, description, imageUrl, gallery, stars, price, duration, location, maxGroupSize, included, excluded, highlights, featured } = req.body;

        // Parse gallery if it's a string
        let galleryArray = [];
        if (gallery) {
            if (typeof gallery === 'string') {
                try {
                    galleryArray = JSON.parse(gallery);
                } catch (e) {
                    galleryArray = [];
                }
            } else if (Array.isArray(gallery)) {
                galleryArray = gallery;
            }
        }

        const tourPackage = await TourPackage.findByIdAndUpdate(
            req.params.id,
            {
                title,
                description,
                imageUrl,
                gallery: galleryArray,
                stars: parseInt(stars),
                price: parseFloat(price),
                duration,
                location,
                maxGroupSize: maxGroupSize ? parseInt(maxGroupSize) : undefined,
                included: included ? included.split(',').map(item => item.trim()) : [],
                excluded: excluded ? excluded.split(',').map(item => item.trim()) : [],
                highlights: highlights ? highlights.split(',').map(item => item.trim()) : [],
                featured: featured === 'true',
                updatedAt: Date.now()
            },
            { new: true }
        );

        if (!tourPackage) {
            return res.status(404).json({ error: 'Tour package not found' });
        }

        res.json(tourPackage);
    } catch (err) {
        console.error('Error updating tour package:', err);
        res.status(500).json({ error: 'Failed to update tour package' });
    }
});

app.delete('/api/tour-packages/:id', ensureAuthenticated, async function (req, res) {
    try {
        const tourPackage = await TourPackage.findByIdAndDelete(req.params.id);

        if (!tourPackage) {
            return res.status(404).json({ error: 'Tour package not found' });
        }

        res.json({ message: 'Tour package deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete tour package' });
    }
});

// Hiking API Routes
app.get('/api/hiking', ensureAuthenticated, async function (req, res) {
    try {
        const hiking = await Hiking.find().populate('createdBy', 'fullName').sort({ createdAt: -1 });
        res.json(hiking);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch hiking trails' });
    }
});

app.post('/api/hiking', ensureAuthenticated, upload.single('image'), async function (req, res) {
    try {
        console.log('Hiking trail creation request:', req.body);
        const { title, description, gallery, stars, reviews, location, difficulty, activity, duration, distance, elevation, bestTime, features, tips, featured, price } = req.body;

        // Handle uploaded image
        let imageUrl = '';
        if (req.file) {
            imageUrl = `/uploads/${req.file.filename}`;
        }

        // Parse gallery if it's a string
        let galleryArray = [];
        if (gallery) {
            if (typeof gallery === 'string') {
                try {
                    galleryArray = JSON.parse(gallery);
                } catch (e) {
                    galleryArray = [];
                }
            } else if (Array.isArray(gallery)) {
                galleryArray = gallery;
            }
        }

        const hikingTrail = new Hiking({
            title,
            description,
            imageUrl: imageUrl || '',
            gallery: galleryArray,
            stars: parseInt(stars),
            reviews: parseInt(reviews) || 0,
            location,
            difficulty,
            activity: activity || 'hiking',
            duration,
            distance,
            price: price ? parseFloat(price) : 0,
            elevation,
            bestTime,
            features: features ? features.split(',').map(item => item.trim()) : [],
            tips: tips ? tips.split(',').map(item => item.trim()) : [],
            featured: featured === 'true',
            createdBy: req.user._id
        });

        console.log('Creating hiking trail:', hikingTrail);
        await hikingTrail.save();
        console.log('Hiking trail saved successfully:', hikingTrail._id);
        res.json(hikingTrail);
    } catch (err) {
        console.error('Error creating hiking trail:', err);
        res.status(500).json({ error: 'Failed to create hiking trail' });
    }
});

app.put('/api/hiking/:id', ensureAuthenticated, async function (req, res) {
    try {
        const { title, description, imageUrl, gallery, stars, reviews, location, difficulty, activity, duration, distance, elevation, bestTime, features, tips, featured, price } = req.body;

        // Parse gallery if it's a string
        let galleryArray = [];
        if (gallery) {
            if (typeof gallery === 'string') {
                try {
                    galleryArray = JSON.parse(gallery);
                } catch (e) {
                    galleryArray = [];
                }
            } else if (Array.isArray(gallery)) {
                galleryArray = gallery;
            }
        }

        const hikingTrail = await Hiking.findByIdAndUpdate(
            req.params.id,
            {
                title,
                description,
                imageUrl,
                gallery: galleryArray,
                stars: parseInt(stars),
                reviews: parseInt(reviews) || 0,
                location,
                difficulty,
                activity: activity || 'hiking',
                duration,
                distance,
                price: price ? parseFloat(price) : 0,
                elevation,
                bestTime,
                features: features ? features.split(',').map(item => item.trim()) : [],
                tips: tips ? tips.split(',').map(item => item.trim()) : [],
                featured: featured === 'true',
                updatedAt: Date.now()
            },
            { new: true }
        );

        if (!hikingTrail) {
            return res.status(404).json({ error: 'Hiking trail not found' });
        }

        res.json(hikingTrail);
    } catch (err) {
        console.error('Error updating hiking trail:', err);
        res.status(500).json({ error: 'Failed to update hiking trail' });
    }
});

app.delete('/api/hiking/:id', ensureAuthenticated, async function (req, res) {
    try {
        const hikingTrail = await Hiking.findByIdAndDelete(req.params.id);

        if (!hikingTrail) {
            return res.status(404).json({ error: 'Hiking trail not found' });
        }

        res.json({ message: 'Hiking trail deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete hiking trail' });
    }
});

// Admin - Bookings API (successful bookings only) with pagination 50/page
app.get('/api/bookings', ensureAuthenticated, async function (req, res) {
    try {
        const page = Math.max(parseInt(req.query.page) || 1, 1);
        const limit = 50;
        const filter = { 'paymentInfo.paymentStatus': 'completed' };

        const [total, bookings] = await Promise.all([
            Booking.countDocuments(filter),
            Booking.find(filter)
                .populate('tourPackageId')
                .sort({ createdAt: -1 })
                .skip((page - 1) * limit)
                .limit(limit)
        ]);

        const totalPages = Math.max(Math.ceil(total / limit), 1);
        res.json({
            page,
            limit,
            total,
            totalPages,
            bookings
        });
    } catch (err) {
        console.error('Error fetching bookings:', err);
        res.status(500).json({ error: 'Failed to fetch bookings' });
    }
});

// Test endpoint to check image accessibility
app.get('/api/test-image/:filename', ensureAuthenticated, function (req, res) {
    const filename = req.params.filename;
    const imagePath = path.join(__dirname, 'public', 'uploads', filename);

    console.log('Testing image access:', {
        filename: filename,
        imagePath: imagePath,
        exists: require('fs').existsSync(imagePath)
    });

    if (require('fs').existsSync(imagePath)) {
        res.sendFile(imagePath);
    } else {
        res.status(404).json({ error: 'Image not found', path: imagePath });
    }
});

// Test endpoint to check payment requests in database
app.get('/api/test-payment-requests', ensureAuthenticated, async function (req, res) {
    try {
        const totalRequests = await PaymentRequest.countDocuments();
        const pendingRequests = await PaymentRequest.countDocuments({ status: 'pending' });
        const approvedRequests = await PaymentRequest.countDocuments({ status: 'approved' });
        const rejectedRequests = await PaymentRequest.countDocuments({ status: 'rejected' });

        const recentRequests = await PaymentRequest.find().sort({ createdAt: -1 }).limit(5).select('_id userEmail userName amount status createdAt');

        res.json({
            database: {
                name: mongoose.connection.name,
                host: mongoose.connection.host,
                port: mongoose.connection.port,
                readyState: mongoose.connection.readyState
            },
            counts: {
                total: totalRequests,
                pending: pendingRequests,
                approved: approvedRequests,
                rejected: rejectedRequests
            },
            recentRequests: recentRequests
        });
    } catch (error) {
        console.error('Error testing payment requests:', error);
        res.status(500).json({ error: 'Failed to test payment requests', details: error.message });
    }
});

// Testimonials page route
app.get('/testimonials', ensureAuthenticated, function (req, res) {
    res.render('testimonials', {
        title: 'Testimonials',
        pageTitle: 'Testimonials',
        currentPage: 'testimonials',
        user: req.user,
        layout: 'layout'
    });
});

// Testimonials API Routes
app.get('/api/testimonials', ensureAuthenticated, async function (req, res) {
    try {
        const testimonials = await Testimonial.find().sort({ createdAt: -1 });
        res.json(testimonials);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch testimonials' });
    }
});

app.post('/api/testimonials', ensureAuthenticated, upload.fields([
    { name: 'avatar', maxCount: 1 },
    { name: 'storyImage', maxCount: 1 }
]), async function (req, res) {
    try {
        const { name, country } = req.body;

        let avatarUrl = '';
        let storyImgUrl = '';

        if (req.files && req.files.avatar && req.files.avatar[0]) {
            avatarUrl = '/uploads/' + req.files.avatar[0].filename;
        }
        if (req.files && req.files.storyImage && req.files.storyImage[0]) {
            storyImgUrl = '/uploads/' + req.files.storyImage[0].filename;
        }

        const testimonial = new Testimonial({
            name,
            country,
            avatarUrl,
            storyImgUrl,
            createdBy: req.user._id
        });

        await testimonial.save();
        res.json(testimonial);
    } catch (err) {
        console.error('Error creating testimonial:', err);
        res.status(500).json({ error: 'Failed to create testimonial' });
    }
});

app.put('/api/testimonials/:id', ensureAuthenticated, upload.fields([
    { name: 'avatar', maxCount: 1 },
    { name: 'storyImage', maxCount: 1 }
]), async function (req, res) {
    try {
        const { name, country, active } = req.body;

        const updateData = {
            name,
            country,
            updatedAt: Date.now()
        };

        if (typeof active !== 'undefined') {
            updateData.active = active === 'true' || active === true;
        }

        if (req.files && req.files.avatar && req.files.avatar[0]) {
            updateData.avatarUrl = '/uploads/' + req.files.avatar[0].filename;
        } else if (req.body.avatarUrl) {
            updateData.avatarUrl = req.body.avatarUrl;
        }

        if (req.files && req.files.storyImage && req.files.storyImage[0]) {
            updateData.storyImgUrl = '/uploads/' + req.files.storyImage[0].filename;
        } else if (req.body.storyImgUrl) {
            updateData.storyImgUrl = req.body.storyImgUrl;
        }

        const testimonial = await Testimonial.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true }
        );

        if (!testimonial) {
            return res.status(404).json({ error: 'Testimonial not found' });
        }

        res.json(testimonial);
    } catch (err) {
        console.error('Error updating testimonial:', err);
        res.status(500).json({ error: 'Failed to update testimonial' });
    }
});

app.delete('/api/testimonials/:id', ensureAuthenticated, async function (req, res) {
    try {
        const testimonial = await Testimonial.findByIdAndDelete(req.params.id);

        if (!testimonial) {
            return res.status(404).json({ error: 'Testimonial not found' });
        }

        // Clean up uploaded files
        [testimonial.avatarUrl, testimonial.storyImgUrl].forEach(function (fileUrl) {
            if (fileUrl && fileUrl.startsWith('/uploads/')) {
                const filePath = path.join(__dirname, 'public', fileUrl);
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                }
            }
        });

        res.json({ message: 'Testimonial deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete testimonial' });
    }
});

// Public endpoint for tourist website to fetch testimonials
app.get('/public/testimonials', async function (req, res) {
    try {
        res.setHeader('Access-Control-Allow-Origin', '*');
        const testimonials = await Testimonial.find({ active: true }).sort({ createdAt: -1 });
        res.json(testimonials);
    } catch (e) {
        res.status(200).json([]);
    }
});

app.get('/logout', function (req, res, next) {
    req.logout(function (err) {
        if (err) { return next(err); }
        res.redirect('/login');
    });
});

// Port logging corrected to 5000
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

