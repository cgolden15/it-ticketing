// Azure App Service startup diagnostics
console.log('🚀 Starting IT Ticketing System...');
console.log('📊 Environment Info:');
console.log('  NODE_ENV:', process.env.NODE_ENV || 'undefined');
console.log('  PORT:', process.env.PORT || 'undefined');
console.log('  WEBSITES_PORT:', process.env.WEBSITES_PORT || 'undefined');
console.log('  WEBSITE_SITE_NAME:', process.env.WEBSITE_SITE_NAME || 'undefined');
console.log('  SESSION_SECRET:', process.env.SESSION_SECRET ? 'SET' : 'NOT SET');
console.log('  DB_PATH:', process.env.DB_PATH || 'undefined');

// Import and start the main application
require('./server.js');