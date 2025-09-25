const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

// Enhanced database setup script with user management
const dbPath = './data/tickets.db';
const db = new sqlite3.Database(dbPath);

console.log('🔧 Upgrading IT Ticketing Database for User Management...');

db.serialize(() => {
    // Drop existing admin_users table to recreate with new schema
    db.run(`DROP TABLE IF EXISTS admin_users`, (err) => {
        if (err) {
            console.error('❌ Error dropping old admin_users table:', err);
            return;
        }
        console.log('✅ Old admin_users table removed');
    });

    // Create enhanced admin users table
    db.run(`CREATE TABLE admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL,
        permission_level TEXT NOT NULL DEFAULT 'Ticket Staff',
        last_login DATETIME,
        is_owner INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) {
            console.error('❌ Error creating enhanced admin_users table:', err);
            return;
        }
        console.log('✅ Enhanced admin users table created');
    });

    // Create tickets table if it doesn't exist (unchanged)
    db.run(`CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        department TEXT NOT NULL,
        priority TEXT NOT NULL,
        issue_type TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT DEFAULT 'Open',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) {
            console.error('❌ Error creating tickets table:', err);
            return;
        }
        console.log('✅ Tickets table ready');
    });

    // Create the owner admin account
    const ownerUsername = 'admin';
    const ownerPassword = 'admin123';
    const ownerName = 'System Administrator';
    const ownerEmail = 'admin@shadybrookfarm.com';
    
    bcrypt.hash(ownerPassword, 10, (err, hash) => {
        if (err) {
            console.error('❌ Error hashing owner password:', err);
            return;
        }
        
        db.run(`INSERT INTO admin_users (username, password_hash, full_name, email, permission_level, is_owner) 
                VALUES (?, ?, ?, ?, ?, ?)`, 
            [ownerUsername, hash, ownerName, ownerEmail, 'Admin', 1], 
            function(err) {
                if (err) {
                    console.error('❌ Error creating owner account:', err);
                    return;
                }
                
                console.log('✅ Owner account created successfully!');
                console.log('👑 Owner Account Details:');
                console.log('   Username: admin');
                console.log('   Password: admin123');
                console.log('   Name: System Administrator');
                console.log('   Email: admin@shadybrookfarm.com');
                console.log('   Permission: Admin (Owner)');
                console.log('');
                console.log('🔒 IMPORTANT: Change the default password after first login!');
                
                // Create a sample Ticket Staff user for demonstration
                const staffPassword = 'staff123';
                bcrypt.hash(staffPassword, 10, (err, staffHash) => {
                    if (err) {
                        console.error('❌ Error hashing staff password:', err);
                        return;
                    }
                    
                    db.run(`INSERT INTO admin_users (username, password_hash, full_name, email, permission_level) 
                            VALUES (?, ?, ?, ?, ?)`, 
                        ['staff', staffHash, 'Support Staff', 'staff@company.com', 'Ticket Staff'], 
                        function(err) {
                            if (err) {
                                console.error('❌ Error creating staff account:', err);
                            } else {
                                console.log('✅ Sample staff account created!');
                                console.log('👤 Staff Account Details:');
                                console.log('   Username: staff');
                                console.log('   Password: staff123');
                                console.log('   Name: Support Staff');
                                console.log('   Email: staff@company.com');
                                console.log('   Permission: Ticket Staff');
                            }
                            
                            // Close database connection
                            db.close((err) => {
                                if (err) {
                                    console.error('❌ Error closing database:', err);
                                } else {
                                    console.log('');
                                    console.log('✅ Database upgrade complete!');
                                    console.log('🚀 You can now start the server with: node server.js');
                                }
                            });
                        }
                    );
                });
            }
        );
    });
});