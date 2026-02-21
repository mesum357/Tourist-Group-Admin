# Tourist Website Admin Panel

A modern, responsive admin panel for managing tourist services. Built with Express.js, MongoDB, and EJS templating.

## Features

- 🔐 **Authentication System**: Local authentication with Passport.js
- 🏨 **Hotel Management**: CRUD operations for hotel properties
- 🚗 **Car Rental Management**: Vehicle inventory and availability tracking
- 📋 **Order Management**: Booking and reservation system
- 👥 **User Management**: Admin and sub-admin role management
- 📱 **Responsive Design**: Mobile-friendly interface
- 🎨 **Modern UI**: Clean, professional design with Bootstrap 5

## Tech Stack

- **Backend**: Node.js, Express.js
- **Database**: MongoDB with Mongoose ODM
- **Authentication**: Passport.js with local strategy
- **Frontend**: EJS templating, Bootstrap 5, Bootstrap Icons
- **File Upload**: Multer for handling file uploads

## Prerequisites

- Node.js (v14 or higher)
- MongoDB database (local or Atlas)

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd tourist-website-admin-panel
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Setup**
   - Copy `env` to `.env`
   - Update the MongoDB URI and session secret:
     ```env
     MONGODB_URI=your_mongodb_connection_string
     SESSION_SECRET=your_session_secret_key
     ```

4. **Start the application**
   ```bash
   # Development mode with auto-reload
   npm run dev
   
   # Production mode
   npm start
   ```

5. **Access the application**
   - Open your browser and navigate to `http://localhost:3000`
   - Register a new admin account
   - Login to access the dashboard

## Authentication Flow

- **Registration**: Users can create new accounts and are redirected to login
- **Login**: Successful login redirects to the dashboard
- **Protected Routes**: Dashboard and other admin features require authentication
- **Logout**: Users are redirected to login page after logout

## Project Structure

```
tourist-website-admin-panel/
├── app.js                 # Main application file
├── db.js                  # Database models and schemas
├── package.json           # Dependencies and scripts
├── env                    # Environment variables template
├── public/                # Static assets
├── views/                 # EJS templates
│   ├── index.ejs          # Dashboard view
│   ├── login.ejs          # Login page
│   └── register.ejs       # Registration page
└── routes/                # Route handlers (to be implemented)
```

## API Endpoints

### Authentication
- `GET /login` - Login page
- `POST /login` - Authenticate user
- `GET /register` - Registration page
- `POST /register` - Create new account
- `GET /logout` - Logout user

### Dashboard
- `GET /` - Main dashboard (protected)

## Database Models

### Admin
- Username, email, password (hashed)
- Role-based permissions
- Account status

### SubAdmin
- Username, email, password (hashed)
- Custom permissions
- Account status

## Development

### Running in Development Mode
```bash
npm run dev
```
This will start the server with nodemon for auto-reload on file changes.

### Running in Production Mode
```bash
npm start
```

## Troubleshooting

1. **MongoDB Connection Issues**
   - Ensure MongoDB is running
   - Check your connection string in `.env`
   - Verify network access if using MongoDB Atlas

2. **Authentication Issues**
   - Check if the database models are properly imported
   - Verify session configuration
   - Ensure environment variables are set correctly

## License

This project is licensed under the ISC License.
