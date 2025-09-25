# 🎫 IT Ticketing System

A secure, full-featured IT ticketing application built with Node.js, Express, and SQLite. Features a public ticket submission form and a comprehensive admin dashboard with user management capabilities.

## ✨ Features

### 🎯 **Ticket Management**
- Public ticket submission form
- Priority levels (High, Medium, Low)
- Issue categorization (Hardware, Software, Network, etc.)
- Department tracking
- Status management (Open, In Progress, Resolved, Closed)
- Real-time dashboard with statistics

### 👥 **User Management**
- Two permission levels: **Admin** and **Ticket Staff**
- Owner account protection (cannot be deleted)
- User creation/editing (Admin only)
- Password management (self-service + admin reset)
- Last login tracking
- Profile management

### 🔒 **Security Features**
- **Private SQLite Database** - Not web-accessible
- **Session-based Authentication** - Secure login system
- **Rate Limiting** - Protection against brute force attacks
- **Password Hashing** - bcrypt encryption
- **Input Validation** - All form data sanitized
- **CSP Headers** - Content Security Policy protection
- **Role-based Access Control** - Permission-based features

## 🚀 Quick Start

### Prerequisites
- Node.js (v14 or higher)
- npm (comes with Node.js)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YOUR-USERNAME/it-ticketing-system.git
   cd it-ticketing-system
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Set up the database:**
   ```bash
   node upgrade-db.js
   ```

4. **Configure environment variables:**
   - Update `.env` file with your settings
   - Change the `SESSION_SECRET` to a strong random string

5. **Start the application:**
   ```bash
   npm start
   ```

6. **Access the application:**
   - **Ticket Form**: http://localhost:3000
   - **Admin Login**: http://localhost:3000/admin/login
   - **Dashboard**: http://localhost:3000/admin/dashboard
   - **User Management**: http://localhost:3000/admin/users

## 🔐 Default Accounts

The system comes with two default accounts:

### Owner/Admin Account
- **Username**: `admin`
- **Password**: `admin123`
- **Permissions**: Full system access (Owner - cannot be deleted)

### Sample Staff Account
- **Username**: `staff`  
- **Password**: `staff123`
- **Permissions**: Ticket management only

> ⚠️ **Important**: Change these default passwords immediately after first login!

## 📊 Permission Levels

### 🛡️ **Admin**
- ✅ Create, edit, and delete users
- ✅ Manage all tickets
- ✅ Change any user's password
- ✅ Access user management panel
- ✅ Full system control

### 👤 **Ticket Staff**
- ✅ View and manage all tickets
- ✅ Update ticket status
- ✅ Change own password
- ✅ Edit own profile
- ❌ Cannot manage other users

## 🗄️ Database Schema

### Tickets Table
- Ticket details (name, email, department, priority, type, description)
- Status tracking and timestamps
- Full audit trail

### Admin Users Table
- User credentials (hashed passwords)
- Profile information (name, email)
- Permission levels and owner flag
- Last login tracking

## 🛡️ Security Considerations

### Database Security
- SQLite file stored locally (not web-accessible)
- Parameterized queries prevent SQL injection
- Database path configurable via environment variables

### Authentication & Authorization
- bcrypt password hashing with salt
- Session-based authentication with secure cookies
- Rate limiting on login attempts (5 attempts per 15 minutes)
- Role-based access control throughout the application

### Input Security
- All user inputs validated and sanitized
- XSS protection through proper HTML escaping
- Content Security Policy headers
- CSRF protection through session validation

## 📁 Project Structure

```
IT Ticketing/
├── server.js              # Main application server
├── upgrade-db.js           # Database setup script
├── package.json            # Dependencies and scripts
├── .env                    # Environment variables
├── .gitignore             # Git ignore rules
├── README.md              # This file
├── data/                  # Database storage (private)
│   └── tickets.db         # SQLite database (auto-created)
├── views/                 # HTML templates
│   ├── index.html         # Public ticket submission form
│   ├── login.html         # Admin login page
│   ├── dashboard.html     # Ticket management dashboard
│   └── users.html         # User management interface
└── public/                # Static files (CSS, JS, images)
```

## 🔧 Configuration

### Environment Variables

Update your `.env` file with:

```env
# Session Secret - Use a strong, random string
SESSION_SECRET=your-super-secret-session-key-change-this-immediately

# Database Configuration
DB_PATH=./data/tickets.db

# Server Configuration
PORT=3000
NODE_ENV=development
```

### Production Deployment

For production deployment:

1. **Set secure environment variables**
2. **Enable HTTPS** and update cookie settings
3. **Configure reverse proxy** (nginx, Apache)
4. **Set up regular database backups**
5. **Configure firewall rules**
6. **Update `NODE_ENV=production`**

## 🧪 Development

### Available Scripts

```bash
npm start          # Start the production server
npm run dev        # Start with nodemon for development
node upgrade-db.js # Reset/upgrade database schema
```

## 🐛 Troubleshooting

### Common Issues

**"Module not found" errors:**
```bash
npm install
```

**Database permission errors:**
- Ensure `data/` directory is writable
- Check file permissions

**Port already in use:**
- Change `PORT` in `.env` file
- Or stop the process using the port

**Session/login issues:**
- Clear browser cookies
- Restart the server
- Check session secret configuration

## 📄 License

This project is for internal use. All rights reserved.

## 📞 Support

For technical support or questions, please contact your system administrator.

---

**⚠️ Security Notice**: This application contains sensitive user data and authentication systems. Always follow security best practices when deploying to production environments.