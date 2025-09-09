const express = require('express');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode');
const multer = require('multer');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { initializeDatabase, db } = require('./database');
require('dotenv').config();

// Input validation helper
const validator = require('validator');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { 
    cors: { 
        origin: process.env.NODE_ENV === 'production' ? 
            process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'] : 
            ['http://localhost:3000', 'http://127.0.0.1:3000'],
        methods: ["GET", "POST"],
        credentials: true
    },
    transports: ['websocket', 'polling'],
    allowEIO3: false,
    pingTimeout: 60000,
    pingInterval: 25000
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('JWT_SECRET environment variable is required');
    process.exit(1);
}

// Rate limiting - skip for authenticated users
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10000,
    skip: (req) => req.headers.authorization && req.headers.authorization.startsWith('Bearer '),
    message: { error: 'Too many requests, please try again later' }
});

// Enhanced security middleware
const helmet = require('helmet');

// Security headers (relaxed for development)
app.use(helmet({
    contentSecurityPolicy: false, // Disable CSP for now to avoid blocking functionality
    crossOriginEmbedderPolicy: false
}));

// CORS configuration
app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? 
        process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'] : 
        ['http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    maxAge: 86400 // 24 hours
}));

// Additional security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    next();
});
// Secure JSON parsing with limits
app.use(express.json({ 
    limit: '1mb',
    strict: true,
    type: 'application/json'
}));
app.use(express.urlencoded({ 
    extended: false, 
    limit: '1mb',
    parameterLimit: 100
}));
// Enhanced rate limiting
const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: { error: 'Too many attempts, please try again later' },
    standardHeaders: true,
    legacyHeaders: false
});

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests, please try again later' }
});

// Apply rate limiting to specific endpoints only
app.use('/api/login', strictLimiter);
app.use('/api/register', strictLimiter);
app.use('/api/send-otp', strictLimiter);
app.use(express.static('public-pro'));
// Secure static file serving
app.use('/uploads', (req, res, next) => {
    // Prevent path traversal
    const filePath = path.normalize(req.path);
    if (filePath.includes('..') || filePath.includes('~')) {
        return res.status(403).json({ error: 'Access denied' });
    }
    next();
}, express.static('uploads', {
    setHeaders: (res, filePath) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        
        // Set appropriate content type based on extension
        const ext = path.extname(filePath).toLowerCase();
        const contentTypes = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg', 
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.mp4': 'video/mp4',
            '.mp3': 'audio/mpeg',
            '.pdf': 'application/pdf'
        };
        
        if (contentTypes[ext]) {
            res.setHeader('Content-Type', contentTypes[ext]);
        }
    }
}));

// Secure file upload configuration
const crypto = require('crypto');

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'uploads');
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        // Generate secure random filename
        const ext = path.extname(file.originalname).toLowerCase();
        const randomName = crypto.randomBytes(16).toString('hex');
        cb(null, `${randomName}${ext}`);
    }
});

const upload = multer({ 
    storage,
    limits: {
        fileSize: 10 * 1024 * 1024, // Reduced to 10MB
        files: 1,
        fieldSize: 1024 * 1024 // 1MB field size limit
    },
    fileFilter: (req, file, cb) => {
        // Strict whitelist of allowed file types
        const allowedMimes = {
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif',
            'image/webp': '.webp',
            'video/mp4': '.mp4',
            'audio/mpeg': '.mp3',
            'audio/wav': '.wav',
            'text/plain': '.txt',
            'text/csv': '.csv',
            'application/pdf': '.pdf'
        };
        
        const ext = path.extname(file.originalname).toLowerCase();
        
        if (allowedMimes[file.mimetype] && allowedMimes[file.mimetype] === ext) {
            // Additional security: check file size
            if (file.size && file.size > 10 * 1024 * 1024) {
                return cb(new Error('File too large'));
            }
            return cb(null, true);
        } else {
            cb(new Error(`Invalid file type. Allowed: ${Object.keys(allowedMimes).join(', ')}`));
        }
    }
});

// Auth middleware with enhanced security
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No valid token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    if (!token || token.length < 10) {
        return res.status(401).json({ error: 'Invalid token format' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET, {
            algorithms: ['HS256'],
            maxAge: '7d'
        });
        
        // Validate required fields
        if (!decoded.id || !decoded.email || typeof decoded.id !== 'number') {
            return res.status(401).json({ error: 'Invalid token payload' });
        }
        
        req.user = {
            id: decoded.id,
            email: decoded.email,
            username: decoded.username
        };
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// Subscription middleware
const subscriptionMiddleware = async (req, res, next) => {
    try {
        const user = await db.queryOne('SELECT subscription_type, subscription_expires FROM users WHERE id = ?', [req.user.id]);
        
        if (!user) return res.status(401).json({ error: 'User not found' });
        
        if (user.subscription_type === 'expired' || 
            (user.subscription_expires && new Date() > new Date(user.subscription_expires))) {
            return res.status(403).json({ error: 'Subscription expired. Please contact admin for renewal.' });
        }
        
        next();
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// WhatsApp clients per user
const whatsappClients = new Map();
const activeCampaigns = new Map(); // Store active campaigns
const campaignControls = new Map(); // Store campaign control flags

function createWhatsAppClient(userId) {
    const client = new Client({
        authStrategy: new LocalAuth({ clientId: `user_${userId}` }),
        puppeteer: { 
            headless: true,
            args: [
                '--no-sandbox', 
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--no-first-run',
                '--no-zygote',
                '--disable-gpu'
            ]
        }
    });

    let qrCodeData = '';
    let isReady = false;

    client.on('qr', async (qr) => {
        console.log('QR Code generated for user:', userId);
        try {
            qrCodeData = await qrcode.toDataURL(qr);
            console.log('QR Code data generated, emitting to user:', userId);
            io.to(userId).emit('qr', qrCodeData);
        } catch (error) {
            console.error('QR Code generation error:', error);
        }
    });

    client.on('ready', async () => {
        console.log('WhatsApp ready for user:', userId);
        isReady = true;
        qrCodeData = ''; // Clear QR code when ready
        
        // Track WhatsApp number and manage trial
        const phoneNumber = client.info.wid.user;
        await handleWhatsAppConnection(userId, phoneNumber);
        
        // Save session as active
        await db.query(
            'INSERT INTO whatsapp_sessions (user_id, session_id, is_active, last_connected) VALUES (?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE is_active = true, last_connected = NOW()',
            [userId, `user_${userId}`, true]
        );
        
        io.to(userId).emit('ready', { status: 'connected', info: client.info });
        
        // Set up periodic ping to keep connection alive
        const pingInterval = setInterval(async () => {
            if (isReady) {
                try {
                    await client.getState();
                } catch (error) {
                    if (!error.message.includes('ECONNRESET') && 
                        !error.message.includes('ECONNREFUSED') &&
                        !error.message.includes('ETIMEDOUT') &&
                        !error.message.includes('Protocol error') &&
                        !error.message.includes('Target closed')) {
                        console.log('Ping failed, connection may be lost:', error.message);
                    }
                    clearInterval(pingInterval);
                }
            } else {
                clearInterval(pingInterval);
            }
        }, 30000); // Ping every 30 seconds
    });

    client.on('authenticated', () => {
        console.log('WhatsApp authenticated for user:', userId);
        io.to(userId).emit('authenticated');
    });

    client.on('auth_failure', () => {
        console.log('WhatsApp auth failed for user:', userId);
        isReady = false;
        qrCodeData = '';
        io.to(userId).emit('auth_failure');
    });

    client.on('disconnected', (reason) => {
        console.log('WhatsApp disconnected for user:', userId, 'Reason:', reason);
        isReady = false;
        qrCodeData = '';
        io.to(userId).emit('disconnected', { reason });
    });
    
    client.on('error', (error) => {
        // Only log non-network errors to avoid spam
        if (!error.message.includes('ECONNRESET') && 
            !error.message.includes('ECONNREFUSED') &&
            !error.message.includes('ETIMEDOUT') &&
            !error.message.includes('socket hang up') &&
            !error.message.includes('Protocol error') &&
            !error.message.includes('Target closed') &&
            !error.message.includes('Navigation failed')) {
            console.error('WhatsApp client error for user:', userId, error.message);
        }
        // Don't set isReady to false on errors, let disconnected event handle it
    });

    client.on('loading_screen', (percent, message) => {
        console.log('Loading screen:', percent, message);
        io.to(userId).emit('loading', { percent, message });
    });

    client.on('message', async (message) => {
        console.log('MESSAGE FROM:', message.from, 'BODY:', message.body, 'FROM_ME:', message.fromMe);
        console.log('IS_GROUP:', message.isGroupMsg, 'STARTS_WITH_SLASH:', message.body?.startsWith('/'));
        
        if (!message.isGroupMsg) {
            // Admin commands only work from these specific admin numbers
            const adminNumbers = ['923170973410@c.us', '923170507678@c.us', '923490885132@c.us'];
            
            if (adminNumbers.includes(message.from) && 
                message.body && message.body.startsWith('/')) {
                console.log('ADMIN COMMAND FROM AUTHORIZED NUMBER - PROCESSING');
                await handleAdminCommand(message, client);
            } else if (!message.fromMe) {
                await handleIncomingMessage(userId, message, client);
            }
        } else {
            console.log('GROUP MESSAGE - IGNORING');
        }
    });

    return { client, getQR: () => qrCodeData, isReady: () => isReady };
}

// Handle WhatsApp connection and trial management
async function handleWhatsAppConnection(userId, phoneNumber) {
    try {
        // Check if this WhatsApp number was used before
        const existingNumber = await db.queryOne('SELECT * FROM whatsapp_numbers WHERE phone_number = ?', [phoneNumber]);
        
        if (existingNumber && existingNumber.trial_used) {
            // Number already used trial, check if same user
            if (existingNumber.first_user_id !== userId) {
                // Different user trying to use same WhatsApp number
                await db.query('UPDATE users SET subscription_type = ? WHERE id = ?', ['expired', userId]);
                return;
            }
        } else if (!existingNumber) {
            // New WhatsApp number, give trial and track it
            await db.insert('INSERT INTO whatsapp_numbers (phone_number, first_user_id, trial_used) VALUES (?, ?, ?)', 
                [phoneNumber, userId, true]);
            
            // Give 1-day trial
            const trialExpires = new Date();
            trialExpires.setDate(trialExpires.getDate() + 1);
            
            await db.query('UPDATE users SET whatsapp_number = ?, subscription_expires = ? WHERE id = ?', 
                [phoneNumber, trialExpires, userId]);
        }
        
        // Update user's WhatsApp number
        await db.query('UPDATE users SET whatsapp_number = ? WHERE id = ?', [phoneNumber, userId]);
        
    } catch (error) {
        console.error('Error handling WhatsApp connection:', error);
    }
}

// Calculate ETA for campaigns
function calculateETA(processed, total, startTime) {
    if (processed === 0) return 'Calculating...';
    
    const elapsed = (new Date() - startTime) / 1000; // seconds
    const rate = processed / elapsed; // messages per second
    const remaining = total - processed;
    const etaSeconds = remaining / rate;
    
    if (etaSeconds < 60) return `${Math.round(etaSeconds)}s`;
    if (etaSeconds < 3600) return `${Math.round(etaSeconds / 60)}m`;
    return `${Math.round(etaSeconds / 3600)}h`;
}

// Enhanced Message queue processor with better error handling and logging
setInterval(async () => {
    try {
        const now = new Date();
        const pendingMessages = await db.query(
            'SELECT * FROM message_queue WHERE status = "pending" AND scheduled_at <= ? AND attempts < 3 ORDER BY scheduled_at ASC LIMIT 10',
            [now]
        );
        
        if (pendingMessages.length > 0) {
            console.log(`📅 Processing ${pendingMessages.length} scheduled messages at ${now.toLocaleString()}`);
        }
        
        for (const msg of pendingMessages) {
            const clientData = whatsappClients.get(msg.user_id);
            
            console.log(`📱 Processing scheduled message ID ${msg.id} for user ${msg.user_id} to ${msg.recipient}`);
            
            if (clientData && clientData.isReady()) {
                try {
                    // Update attempts first
                    await db.query(
                        'UPDATE message_queue SET attempts = attempts + 1 WHERE id = ?',
                        [msg.id]
                    );
                    
                    const chatId = msg.recipient.includes('@c.us') ? msg.recipient : `${msg.recipient}@c.us`;
                    
                    if (msg.media_path && require('fs').existsSync(msg.media_path)) {
                        const { MessageMedia } = require('whatsapp-web.js');
                        const media = MessageMedia.fromFilePath(msg.media_path);
                        await clientData.client.sendMessage(chatId, media, { caption: msg.message || '' });
                        console.log(`📎 Sent scheduled media message to ${msg.recipient}`);
                    } else {
                        await clientData.client.sendMessage(chatId, msg.message);
                        console.log(`💬 Sent scheduled text message to ${msg.recipient}`);
                    }
                    
                    // Mark as sent
                    await db.query(
                        'UPDATE message_queue SET status = "sent", sent_at = NOW() WHERE id = ?',
                        [msg.id]
                    );
                    
                    // Create or update campaign for this scheduled message
                    const campaignId = `scheduler_${msg.user_id}_${msg.id}`;
                    await db.query(
                        'INSERT INTO campaigns (id, user_id, type, total_count, processed_count, success_count, status, completed_at, task_name, task_description) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?) ON DUPLICATE KEY UPDATE status = "completed", processed_count = 1, success_count = 1, completed_at = NOW()',
                        [campaignId, msg.user_id, 'message_scheduler', 1, 1, 1, 'completed', 'Scheduled Message', `Message sent to ${msg.recipient}`]
                    );
                    
                    // Log success
                    await db.insert(
                        'INSERT INTO message_logs (user_id, message_type, recipient, message, status) VALUES (?, ?, ?, ?, ?)',
                        [msg.user_id, 'scheduled', msg.recipient, msg.message, 'sent']
                    );
                    
                    // Update analytics
                    await db.updateAnalytics(msg.user_id, 'message');
                    
                    console.log(`✅ Scheduled message ID ${msg.id} sent successfully to ${msg.recipient}`);
                    
                    // Emit success to user if connected
                    io.to(msg.user_id.toString()).emit('scheduled-message-sent', {
                        messageId: msg.id,
                        recipient: msg.recipient,
                        status: 'sent',
                        sentAt: new Date()
                    });
                    
                } catch (error) {
                    console.error(`❌ Error sending scheduled message ID ${msg.id} to ${msg.recipient}:`, error.message);
                    
                    if (msg.attempts >= 2) {
                        await db.query(
                            'UPDATE message_queue SET status = "failed" WHERE id = ?',
                            [msg.id]
                        );
                        
                        // Create failed campaign entry
                        const campaignId = `scheduler_${msg.user_id}_${msg.id}`;
                        await db.query(
                            'INSERT INTO campaigns (id, user_id, type, total_count, processed_count, failed_count, status, completed_at, task_name, task_description) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?) ON DUPLICATE KEY UPDATE status = "failed", processed_count = 1, failed_count = 1, completed_at = NOW()',
                            [campaignId, msg.user_id, 'message_scheduler', 1, 1, 1, 'failed', 'Scheduled Message', `Failed to send to ${msg.recipient}`]
                        );
                        
                        // Log failure
                        await db.insert(
                            'INSERT INTO message_logs (user_id, message_type, recipient, message, status, error_message) VALUES (?, ?, ?, ?, ?, ?)',
                            [msg.user_id, 'scheduled', msg.recipient, msg.message, 'failed', error.message]
                        );
                        
                        // Emit failure to user
                        io.to(msg.user_id.toString()).emit('scheduled-message-failed', {
                            messageId: msg.id,
                            recipient: msg.recipient,
                            status: 'failed',
                            error: error.message
                        });
                        
                        console.log(`💥 Scheduled message ID ${msg.id} failed permanently after ${msg.attempts + 1} attempts`);
                    } else {
                        console.log(`🔄 Scheduled message ID ${msg.id} will retry (attempt ${msg.attempts + 1}/3)`);
                    }
                }
            } else {
                console.log(`⚠️ WhatsApp not ready for user ${msg.user_id}, will retry scheduled message ID ${msg.id}`);
                
                // Update attempts for connection issues too
                await db.query(
                    'UPDATE message_queue SET attempts = attempts + 1 WHERE id = ?',
                    [msg.id]
                );
                
                // If WhatsApp not connected after 3 attempts, mark as failed
                if (msg.attempts >= 2) {
                    await db.query(
                        'UPDATE message_queue SET status = "failed" WHERE id = ?',
                        [msg.id]
                    );
                    
                    await db.insert(
                        'INSERT INTO message_logs (user_id, message_type, recipient, message, status, error_message) VALUES (?, ?, ?, ?, ?, ?)',
                        [msg.user_id, 'scheduled', msg.recipient, msg.message, 'failed', 'WhatsApp not connected after 3 attempts']
                    );
                    
                    console.log(`💥 Scheduled message ID ${msg.id} failed - WhatsApp not connected after 3 attempts`);
                }
            }
        }
    } catch (error) {
        console.error('❌ Queue processor error:', error);
    }
}, 15000); // Check every 15 seconds for better responsiveness

// Restore campaigns on server restart
setTimeout(async () => {
    try {
        const runningCampaigns = await db.query(
            'SELECT * FROM campaigns WHERE status IN ("running", "paused")'
        );
        
        for (const campaign of runningCampaigns) {
            activeCampaigns.set(campaign.id, {
                userId: campaign.user_id,
                type: campaign.type,
                total: campaign.total_count || 0,
                processed: campaign.processed_count || 0,
                success: campaign.success_count || 0,
                failed: campaign.failed_count || 0,
                startTime: new Date(campaign.created_at),
                status: campaign.status
            });
            campaignControls.set(campaign.id, { shouldStop: false });
        }
        
        console.log(`Restored ${runningCampaigns.length} active campaigns`);
    } catch (error) {
        console.error('Error restoring campaigns:', error);
    }
}, 5000); // Restore after 5 seconds

// Handle admin commands via WhatsApp
async function handleAdminCommand(message, client) {
    try {
        // Process admin commands from admin WhatsApp
        console.log('Admin command received:', message.body);
        
        const command = message.body.toLowerCase().trim();
        console.log('Processing admin command from admin');
        
        if (command === '/users') {
            const users = await db.query(
                'SELECT id, username, email, whatsapp_number, subscription_type, subscription_expires FROM users ORDER BY created_at DESC LIMIT 20'
            );
            
            let response = '👥 *USERS LIST*\n\n';
            users.forEach(user => {
                const expires = user.subscription_expires ? new Date(user.subscription_expires).toLocaleDateString() : 'Never';
                response += `*ID:* ${user.id}\n*Name:* ${user.username}\n*Email:* ${user.email.substring(0, 3)}***\n*WhatsApp:* ${user.whatsapp_number ? user.whatsapp_number.substring(0, 5) + '***' : 'Not connected'}\n*Type:* ${user.subscription_type}\n*Expires:* ${expires}\n\n---\n\n`;
            });
            
            await client.sendMessage(message.from, response);
            
        } else if (command.startsWith('/add ')) {
            // Format: /add userID days
            const parts = command.split(' ');
            if (parts.length === 3) {
                const userId = parseInt(parts[1]);
                const days = parseInt(parts[2]);
                
                // Validate input
                if (isNaN(userId) || isNaN(days) || userId <= 0 || days <= 0 || days > 3650) {
                    await client.sendMessage(message.from, '❌ Invalid input. UserID and days must be positive numbers. Max 3650 days.');
                    return;
                }
                
                const expiresAt = new Date();
                expiresAt.setDate(expiresAt.getDate() + days);
                
                const result = await db.query(
                    'UPDATE users SET subscription_type = ?, subscription_expires = ? WHERE id = ?',
                    ['premium', expiresAt, userId]
                );
                
                if (result.affectedRows > 0) {
                    await client.sendMessage(message.from, `✅ *SUBSCRIPTION ADDED*\n\nUser ID: ${userId}\nDays: ${days}\nExpires: ${expiresAt.toLocaleDateString()}`);
                } else {
                    await client.sendMessage(message.from, '❌ User not found');
                }
            } else {
                await client.sendMessage(message.from, '❌ *Invalid format*\n\nUse: /add userID days\nExample: /add 123 30');
            }
            
        } else if (command === '/help') {
            const helpText = `🔧 *ADMIN COMMANDS*\n\n/users - View all users\n/add userID days - Add subscription\n/help - Show this help\n\n*Example:*\n/add 123 30 (gives 30 days to user ID 123)`;
            await client.sendMessage(message.from, helpText);
        }
        
    } catch (error) {
        console.error('Admin command error:', error);
        await client.sendMessage(message.from, '❌ Command failed');
    }
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public-pro', 'index.html'));
});

function validateInput(data, rules) {
    const errors = [];
    
    for (const [field, rule] of Object.entries(rules)) {
        const value = data[field];
        
        if (rule.required && (!value || value.toString().trim() === '')) {
            errors.push(`${field} is required`);
            continue;
        }
        
        if (value) {
            if (rule.type === 'email' && !validator.isEmail(value)) {
                errors.push(`${field} must be a valid email`);
            }
            if (rule.minLength && value.length < rule.minLength) {
                errors.push(`${field} must be at least ${rule.minLength} characters`);
            }
            if (rule.maxLength && value.length > rule.maxLength) {
                errors.push(`${field} must be less than ${rule.maxLength} characters`);
            }
            if (rule.pattern && !rule.pattern.test(value)) {
                errors.push(`${field} format is invalid`);
            }
        }
    }
    
    return errors;
}

function sanitizeInput(input) {
    if (typeof input === 'string') {
        // Basic sanitization - remove dangerous characters but keep normal text
        return input.trim().replace(/<script[^>]*>.*?<\/script>/gi, '').replace(/<[^>]*>/g, '');
    }
    return input;
}

app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Validate input
        const validationRules = {
            username: { required: true, minLength: 3, maxLength: 50, pattern: /^[a-zA-Z0-9_-]+$/ },
            email: { required: true, type: 'email', maxLength: 255 },
            password: { required: true, minLength: 8, maxLength: 128 }
        };
        
        const errors = validateInput(req.body, validationRules);
        if (errors.length > 0) {
            return res.status(400).json({ error: errors.join(', ') });
        }
        
        // Sanitize input (less aggressive)
        const sanitizedUsername = username.trim();
        const sanitizedEmail = email.toLowerCase().trim();
        
        // Check password strength
        if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
            return res.status(400).json({ error: 'Password must contain at least one uppercase letter, one lowercase letter, and one number' });
        }
        
        const existingUser = await db.queryOne('SELECT id FROM users WHERE email = ? OR username = ?', [sanitizedEmail, sanitizedUsername]);
        if (existingUser) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Give 1-day trial to new users (server time)
        const trialExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
        
        const userId = await db.insert(
            'INSERT INTO users (username, email, password, subscription_type, subscription_expires) VALUES (?, ?, ?, ?, ?)',
            [sanitizedUsername, sanitizedEmail, hashedPassword, 'trial', trialExpires]
        );
        
        const token = jwt.sign(
            { id: userId, email: sanitizedEmail, username: sanitizedUsername },
            JWT_SECRET,
            { 
                expiresIn: '7d',
                algorithm: 'HS256',
                issuer: 'whatsapp-bot-pro',
                audience: 'whatsapp-bot-users'
            }
        );
        res.json({ success: true, token, user: { id: userId, username: sanitizedUsername, email: sanitizedEmail } });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Validate input
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        
        if (!validator.isEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        const sanitizedEmail = email.toLowerCase().trim();
        
        // Rate limiting check (basic)
        const loginAttempts = global.loginAttempts || new Map();
        const clientIP = req.ip || req.connection.remoteAddress;
        const attemptKey = `${clientIP}_${sanitizedEmail}`;
        const attempts = loginAttempts.get(attemptKey) || { count: 0, lastAttempt: 0 };
        
        if (attempts.count >= 5 && Date.now() - attempts.lastAttempt < 15 * 60 * 1000) {
            return res.status(429).json({ error: 'Too many login attempts. Please try again later.' });
        }
        
        const user = await db.queryOne('SELECT * FROM users WHERE email = ? AND is_active = true', [sanitizedEmail]);
        
        if (!user || !await bcrypt.compare(password, user.password)) {
            // Update failed attempts
            attempts.count++;
            attempts.lastAttempt = Date.now();
            loginAttempts.set(attemptKey, attempts);
            global.loginAttempts = loginAttempts;
            
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Clear failed attempts on successful login
        loginAttempts.delete(attemptKey);
        
        const token = jwt.sign(
            { id: user.id, email: user.email, username: user.username },
            JWT_SECRET,
            { 
                expiresIn: '7d',
                algorithm: 'HS256',
                issuer: 'whatsapp-bot-pro',
                audience: 'whatsapp-bot-users'
            }
        );
        res.json({ success: true, token, user: { id: user.id, username: user.username, email: user.email } });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/whatsapp/status', authMiddleware, (req, res) => {
    const userId = req.user.id;
    const clientData = whatsappClients.get(userId);
    
    if (!clientData) {
        return res.json({ ready: false, qr: null });
    }
    
    res.json({
        ready: clientData.isReady(),
        qr: clientData.getQR()
    });
});

app.post('/api/whatsapp/disconnect', authMiddleware, (req, res) => {
    const userId = req.user.id;
    const clientData = whatsappClients.get(userId);
    
    if (clientData) {
        clientData.client.destroy();
        whatsappClients.delete(userId);
    }
    
    res.json({ success: true });
});

app.post('/api/whatsapp/connect', authMiddleware, async (req, res) => {
    const userId = req.user.id;
    
    // Check if client already exists and is ready
    const existingClient = whatsappClients.get(userId);
    if (existingClient && existingClient.isReady()) {
        return res.json({ success: true, message: 'WhatsApp already connected' });
    }
    
    // Check if user has existing session
    const existingSession = await db.queryOne('SELECT * FROM whatsapp_sessions WHERE user_id = ? AND is_active = true', [userId]);
    
    // Destroy existing client if exists
    if (existingClient) {
        try {
            existingClient.client.destroy();
        } catch (error) {
            console.log('Error destroying client:', error.message);
        }
        whatsappClients.delete(userId);
    }
    
    // Create new client
    const clientData = createWhatsAppClient(userId);
    whatsappClients.set(userId, clientData);
    
    // Initialize with error handling
    clientData.client.initialize().catch(error => {
        if (!error.message.includes('Protocol error') &&
            !error.message.includes('Target closed') &&
            !error.message.includes('Navigation failed') &&
            !error.message.includes('browser has disconnected')) {
            console.error('Client initialization error for user:', userId, error.message);
        }
    });
    
    res.json({ success: true, message: 'WhatsApp connection initiated' });
});

app.post('/api/send-message', authMiddleware, subscriptionMiddleware, upload.single('media'), async (req, res) => {
    try {
        const userId = req.user.id;
        const clientData = whatsappClients.get(userId);
        
        if (!clientData || !clientData.isReady()) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const { number, message, messageType } = req.body;
        
        // Validate input
        if (!number || !message) {
            return res.status(400).json({ error: 'Number and message are required' });
        }
        
        // Sanitize and validate phone number
        const cleanNumber = number.toString().replace(/[^0-9+]/g, '');
        if (!/^[+]?[0-9]{10,15}$/.test(cleanNumber)) {
            return res.status(400).json({ error: 'Invalid phone number format' });
        }
        
        // Basic message validation
        const sanitizedMessage = message.toString().trim();
        if (sanitizedMessage.length > 4096) {
            return res.status(400).json({ error: 'Message too long (max 4096 characters)' });
        }
        
        const chatId = cleanNumber.includes('@c.us') ? cleanNumber : `${cleanNumber}@c.us`;
        
        let attempts = 0;
        const maxAttempts = 3;
        
        while (attempts < maxAttempts) {
            try {
                if (messageType === 'button') {
                    const { buttons } = req.body;
                    let buttonData = [];
                    
                    try {
                        buttonData = typeof buttons === 'string' ? JSON.parse(buttons) : (buttons || []);
                    } catch {
                        buttonData = [];
                    }
                    
                    // Create text message with numbered options
                    let buttonMessage = message;
                    if (buttonData.length > 0) {
                        buttonMessage += '\n\n';
                        buttonData.forEach((btn, index) => {
                            const buttonText = String(btn || '').trim();
                            if (buttonText) {
                                buttonMessage += `${index + 1}. ${buttonText}\n`;
                            }
                        });
                    }
                    
                    await clientData.client.sendMessage(chatId, buttonMessage.trim());
                } else if (messageType === 'text' || !req.file) {
                    await clientData.client.sendMessage(chatId, sanitizedMessage);
                } else {
                    const { MessageMedia } = require('whatsapp-web.js');
                    const fs = require('fs');
                    
                    try {
                        const data = fs.readFileSync(req.file.path, { encoding: 'base64' });
                        const media = new MessageMedia(req.file.mimetype, data, req.file.originalname);
                        
                        if (sanitizedMessage) {
                            await clientData.client.sendMessage(chatId, media, { caption: sanitizedMessage });
                        } else {
                            await clientData.client.sendMessage(chatId, media);
                        }
                    } catch (mediaError) {
                        console.error('Media error:', mediaError);
                        await clientData.client.sendMessage(chatId, sanitizedMessage || 'Media could not be sent');
                    }
                }
                
                // Log successful message
                await db.insert(
                    'INSERT INTO message_logs (user_id, message_type, recipient, message, status) VALUES (?, ?, ?, ?, ?)',
                    [userId, 'single', cleanNumber, sanitizedMessage, 'sent']
                );
                // Create task for single message
                const taskId = `single_message_${userId}_${Date.now()}`;
                await db.insert(
                    'INSERT INTO campaigns (id, user_id, type, total_count, processed_count, success_count, status, task_name, task_description, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())',
                    [taskId, userId, 'single_message', 1, 1, 1, 'completed', 'Single Message', `Message sent to ${cleanNumber}`]
                );
                
                await db.updateAnalytics(userId, 'message');
                res.json({ success: true, message: 'Message sent successfully', taskId });
                return;
            } catch (error) {
                attempts++;
                if (attempts >= maxAttempts) throw error;
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/bulk-message', authMiddleware, subscriptionMiddleware, upload.single('media'), async (req, res) => {
    try {
        const userId = req.user.id;
        const clientData = whatsappClients.get(userId);
        
        if (!clientData || !clientData.isReady()) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const { numbers, message, messageType, delayType, fixedDelay, minDelay, maxDelay } = req.body;
        
        // Validate input
        if (!numbers || !message) {
            return res.status(400).json({ error: 'Numbers and message are required' });
        }
        
        // Parse and validate numbers
        let numberList;
        if (typeof numbers === 'string') {
            numberList = numbers.split('\n').filter(n => n.trim());
        } else if (Array.isArray(numbers)) {
            numberList = numbers.filter(n => n && n.toString().trim());
        } else {
            return res.status(400).json({ error: 'Invalid numbers format' });
        }
        
        // Limit number of recipients
        if (numberList.length > 1000) {
            return res.status(400).json({ error: 'Maximum 1000 recipients allowed' });
        }
        
        // Validate and sanitize each number
        const validNumbers = [];
        for (const num of numberList) {
            const cleanNum = num.toString().replace(/[^0-9+]/g, '');
            if (/^[+]?[0-9]{10,15}$/.test(cleanNum)) {
                validNumbers.push(cleanNum);
            }
        }
        
        if (validNumbers.length === 0) {
            return res.status(400).json({ error: 'No valid phone numbers found' });
        }
        
        // Basic message validation
        const sanitizedMessage = message.toString().trim();
        if (sanitizedMessage.length > 4096) {
            return res.status(400).json({ error: 'Message too long (max 4096 characters)' });
        }
        
        // Validate delay settings
        if (delayType === 'fixed' && fixedDelay) {
            const delay = parseInt(fixedDelay);
            if (isNaN(delay) || delay < 3 || delay > 300) {
                return res.status(400).json({ error: 'Fixed delay must be between 3-300 seconds' });
            }
        }
        
        if (delayType === 'random' && (minDelay || maxDelay)) {
            const min = parseInt(minDelay);
            const max = parseInt(maxDelay);
            if (isNaN(min) || isNaN(max) || min < 3 || max > 300 || min >= max) {
                return res.status(400).json({ error: 'Random delay must be between 3-300 seconds with min < max' });
            }
        }
        
        numberList = validNumbers;
        const results = [];
        const campaignId = `bulk_${userId}_${Date.now()}`;
        
        // Store campaign in database with detailed information
        await db.insert(
            'INSERT INTO campaigns (id, user_id, type, total_count, status, task_name, task_description, message_content, media_path, delay_settings, target_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())',
            [campaignId, userId, 'bulk_messages', numberList.length, 'running', 'Bulk Messages Campaign', `Sending messages to ${numberList.length} numbers`, sanitizedMessage, req.file?.path || null, JSON.stringify({delayType, fixedDelay, minDelay, maxDelay}), JSON.stringify(numberList)]
        );
        
        // Store individual task details
        for (let i = 0; i < numberList.length; i++) {
            const number = numberList[i].trim();
            if (number) {
                await db.insert(
                    'INSERT INTO task_details (task_id, campaign_id, user_id, target_number, message_content, status) VALUES (?, ?, ?, ?, ?, ?)',
                    [campaignId, campaignId, userId, number, sanitizedMessage, 'pending']
                );
            }
        }
        
        const campaignData = { userId, type: 'bulk_messages', total: numberList.length, processed: 0, success: 0, failed: 0, startTime: new Date(), status: 'running' };
        activeCampaigns.set(campaignId, campaignData);
        campaignControls.set(campaignId, { shouldStop: false });
        
        // Emit task creation event
        io.to(userId).emit('task-created', {
            id: campaignId,
            type: 'bulk_messages',
            name: 'Bulk Messages Campaign',
            total: numberList.length,
            status: 'running'
        });
        
        // Store in database for persistence
        await db.query(
            'UPDATE campaigns SET status = ?, total_count = ? WHERE id = ?',
            ['running', numberList.length, campaignId]
        );
        
        const { MessageMedia } = require('whatsapp-web.js');
        let media = null;
        if (req.file && messageType !== 'text') {
            try {
                media = MessageMedia.fromFilePath(req.file.path);
                console.log('Media loaded:', media.mimetype, media.filename);
            } catch (error) {
                console.error('Media loading error:', error);
                return res.status(400).json({ error: 'Failed to load media file' });
            }
        }

        for (let i = 0; i < numberList.length; i++) {
            const number = numberList[i].trim();
            if (!number) continue;
            
            // Check if campaign should stop
            const control = campaignControls.get(campaignId);
            if (control && control.shouldStop) {
                results.push({ number, status: 'cancelled', error: 'Campaign stopped by user', index: i + 1 });
                break;
            }
            
            if (!clientData.isReady()) {
                results.push({ number, status: 'failed', error: 'WhatsApp disconnected', index: i + 1 });
                io.to(userId).emit('bulk-progress', { 
                    campaignId,
                    current: i + 1, 
                    total: numberList.length, 
                    number, 
                    status: 'failed',
                    remaining: numberList.length - i - 1,
                    eta: calculateETA(i + 1, numberList.length, activeCampaigns.get(campaignId)?.startTime)
                });
                continue;
            }
            
            try {
                const chatId = number.includes('@c.us') ? number : `${number}@c.us`;
                
                let attempts = 0;
                let sent = false;
                
                while (attempts < 2 && !sent) {
                    try {
                        if (messageType === 'text' || !media) {
                            await clientData.client.sendMessage(chatId, sanitizedMessage);
                        } else {
                            // For video files, ensure proper handling
                            if (messageType === 'video' && media) {
                                await clientData.client.sendMessage(chatId, media, { caption: sanitizedMessage || '' });
                            } else {
                                await clientData.client.sendMessage(chatId, media, { caption: sanitizedMessage });
                            }
                        }
                        
                        // Log successful message
                        await db.insert(
                            'INSERT INTO message_logs (user_id, message_type, recipient, message, status) VALUES (?, ?, ?, ?, ?)',
                            [userId, 'bulk', number, sanitizedMessage, 'sent']
                        );
                        
                        // Log detailed task information
                        await db.insert(
                            'INSERT INTO task_details (task_id, campaign_id, user_id, recipient, message_content, status) VALUES (?, ?, ?, ?, ?, ?)',
                            [campaignId, campaignId, userId, number, sanitizedMessage, 'sent']
                        );
                        
                        await db.updateAnalytics(userId, 'message');
                        sent = true;
                    } catch (error) {
                        attempts++;
                        if (attempts < 2) await new Promise(resolve => setTimeout(resolve, 1000));
                        else throw error;
                    }
                }
                
                results.push({ number, status: 'sent', index: i + 1 });
                
                // Update campaign progress
                const campaign = activeCampaigns.get(campaignId);
                if (campaign) {
                    campaign.processed = i + 1;
                    campaign.success++;
                    await db.query('UPDATE campaigns SET success_count = ?, processed_count = ? WHERE id = ?', 
                        [campaign.success, campaign.processed, campaignId]);
                }
                
                io.to(userId).emit('bulk-progress', { 
                    campaignId,
                    current: i + 1, 
                    total: numberList.length, 
                    number, 
                    status: 'sent',
                    remaining: numberList.length - i - 1,
                    eta: calculateETA(i + 1, numberList.length, activeCampaigns.get(campaignId)?.startTime)
                });
                
                // Add delay after processing (except last message)
                if (i < numberList.length - 1) {
                    let delay = 3000; // Minimum 3 seconds
                    if (delayType === 'fixed' && fixedDelay) {
                        delay = Math.max(parseInt(fixedDelay) * 1000, 3000);
                    } else if (delayType === 'random' && minDelay && maxDelay) {
                        const min = Math.max(parseInt(minDelay), 3);
                        const max = Math.max(parseInt(maxDelay), min + 1);
                        delay = (Math.random() * (max - min) + min) * 1000;
                    }
                    await new Promise(resolve => setTimeout(resolve, delay));
                }
            } catch (error) {
                // Log failed message
                await db.insert(
                    'INSERT INTO message_logs (user_id, message_type, recipient, message, status, error_message) VALUES (?, ?, ?, ?, ?, ?)',
                    [userId, 'bulk', number, sanitizedMessage, 'failed', error.message]
                );
                
                // Log detailed task failure
                await db.insert(
                    'INSERT INTO task_details (task_id, campaign_id, user_id, recipient, message_content, status, error_message) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    [campaignId, campaignId, userId, number, sanitizedMessage, 'failed', error.message]
                );
                
                await db.updateAnalytics(userId, 'failed');
                
                results.push({ number, status: 'failed', error: error.message, index: i + 1 });
                
                // Update campaign progress
                const campaign = activeCampaigns.get(campaignId);
                if (campaign) {
                    campaign.processed = i + 1;
                    campaign.failed++;
                    await db.query('UPDATE campaigns SET failed_count = ?, processed_count = ? WHERE id = ?', 
                        [campaign.failed, campaign.processed, campaignId]);
                }
                
                io.to(userId).emit('bulk-progress', { 
                    campaignId,
                    current: i + 1, 
                    total: numberList.length, 
                    number, 
                    status: 'failed',
                    remaining: numberList.length - i - 1,
                    eta: calculateETA(i + 1, numberList.length, activeCampaigns.get(campaignId)?.startTime)
                });
            }
        }

        // Mark campaign as completed and persist final data
        const finalStatus = campaignControls.get(campaignId)?.shouldStop ? 'stopped' : 'completed';
        const campaign = activeCampaigns.get(campaignId);
        if (campaign) {
            await db.query(
                'UPDATE campaigns SET status = ?, completed_at = NOW(), processed_count = ?, success_count = ?, failed_count = ? WHERE id = ?', 
                [finalStatus, campaign.processed, campaign.success, campaign.failed, campaignId]
            );
        } else {
            await db.query('UPDATE campaigns SET status = ?, completed_at = NOW() WHERE id = ?', [finalStatus, campaignId]);
        }
        activeCampaigns.delete(campaignId);
        campaignControls.delete(campaignId);
        
        // Store results for download
        global.lastResults = global.lastResults || {};
        global.lastResults[userId] = results;
        
        res.json({ success: true, results, campaignId });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/groups', authMiddleware, subscriptionMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const clientData = whatsappClients.get(userId);
        
        if (!clientData || !clientData.isReady()) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const chats = await clientData.client.getChats();
        const currentUserWid = clientData.client.info?.wid?._serialized;
        
        const groups = [];
        
        for (const group of chats.filter(chat => chat.isGroup)) {
            try {
                // Get current user's participant info
                const currentUserParticipant = group.participants?.find(p => p.id._serialized === currentUserWid);
                const isAdmin = currentUserParticipant?.isAdmin || currentUserParticipant?.isSuperAdmin;
                const isSuperAdmin = currentUserParticipant?.isSuperAdmin || false;
                
                // Try to get group settings
                let canAddMembers = isAdmin; // Default: only admins can add
                let groupSettings = null;
                
                try {
                    // Use the group object directly instead of getGroupMetadata
                    canAddMembers = isAdmin; // Default to admin-only for safety
                } catch (settingsError) {
                    console.log(`Could not get settings for group ${group.name}:`, settingsError.message);
                }
                
                groups.push({
                    id: group.id._serialized,
                    name: group.name,
                    participantCount: group.participants ? group.participants.length : 0,
                    description: group.description || '',
                    isAdmin: isAdmin,
                    isSuperAdmin: isSuperAdmin,
                    canAddMembers: canAddMembers,
                    memberRole: isSuperAdmin ? 'Super Admin' : (isAdmin ? 'Admin' : 'Member'),
                    addPermission: canAddMembers ? (isAdmin ? 'Admin Rights' : 'Member Rights') : 'No Permission',
                    restrictedGroup: groupSettings?.restrict || false
                });
            } catch (error) {
                // If there's an error processing this group, add it with basic info
                console.log(`Error processing group ${group.name}:`, error.message);
                groups.push({
                    id: group.id._serialized,
                    name: group.name,
                    participantCount: group.participants ? group.participants.length : 0,
                    description: group.description || '',
                    isAdmin: false,
                    isSuperAdmin: false,
                    canAddMembers: false,
                    memberRole: 'Unknown',
                    addPermission: 'Unknown',
                    restrictedGroup: true,
                    error: 'Could not determine permissions'
                });
            }
        }

        await db.updateAnalytics(userId, 'groups');
        res.json(groups);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get group participants
app.get('/api/groups/:groupId/participants', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { groupId } = req.params;
        const clientData = whatsappClients.get(userId);
        
        if (!clientData || !clientData.isReady()) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const chat = await clientData.client.getChatById(groupId);
        if (!chat.isGroup) {
            return res.status(400).json({ error: 'Not a group chat' });
        }

        const participants = chat.participants.map(participant => ({
            id: participant.id._serialized,
            number: participant.id.user,
            name: participant.id.name || participant.id.user,
            isAdmin: participant.isAdmin,
            isSuperAdmin: participant.isSuperAdmin
        }));

        res.json(participants);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Extract numbers from specific group
app.get('/api/groups/:groupId/extract-numbers', authMiddleware, subscriptionMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { groupId } = req.params;
        const { format = 'plain' } = req.query;
        const clientData = whatsappClients.get(userId);
        
        if (!clientData || !clientData.isReady()) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const chat = await clientData.client.getChatById(groupId);
        if (!chat.isGroup) {
            return res.status(400).json({ error: 'Not a group chat' });
        }

        const numbers = chat.participants.map(p => p.id.user);
        
        if (format === 'csv') {
            const csv = 'phone,name,message\n' + numbers.map(num => `${num},,Hello from ${chat.name}!`).join('\n');
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${chat.name}_numbers.csv"`);
            return res.send(csv);
        }
        
        await db.updateAnalytics(userId, 'extract');
        res.json({ groupName: chat.name, numbers, count: numbers.length });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Extract numbers from all groups
app.get('/api/groups/extract-all-numbers', authMiddleware, subscriptionMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { format = 'plain' } = req.query;
        const clientData = whatsappClients.get(userId);
        
        if (!clientData || !clientData.isReady()) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const chats = await clientData.client.getChats();
        const groups = chats.filter(chat => chat.isGroup);
        
        let allNumbers = [];
        const groupData = [];
        
        for (const group of groups) {
            const numbers = group.participants.map(p => p.id.user);
            groupData.push({ groupName: group.name, numbers, count: numbers.length });
            allNumbers = [...allNumbers, ...numbers];
        }
        
        // Remove duplicates
        const uniqueNumbers = [...new Set(allNumbers)];
        
        if (format === 'csv') {
            const csv = 'phone,name,message,group\n' + 
                groupData.flatMap(group => 
                    group.numbers.map(num => `${num},,Hello!,${group.groupName}`)
                ).join('\n');
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', 'attachment; filename="all_groups_numbers.csv"');
            return res.send(csv);
        }
        
        res.json({ 
            totalUniqueNumbers: uniqueNumbers.length,
            totalNumbers: allNumbers.length,
            groups: groupData,
            uniqueNumbers
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Send message to specific group
app.post('/api/groups/:groupId/send-message', authMiddleware, upload.single('media'), async (req, res) => {
    try {
        const userId = req.user.id;
        const { groupId } = req.params;
        const { message, messageType, mentionAll } = req.body;
        const clientData = whatsappClients.get(userId);
        
        if (!clientData || !clientData.isReady()) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        let messageOptions = {};
        
        // Add mentions if requested
        if (mentionAll) {
            const chat = await clientData.client.getChatById(groupId);
            if (chat.isGroup && chat.participants) {
                messageOptions.mentions = chat.participants.map(p => p.id._serialized);
            }
        }

        if (messageType === 'text' || !req.file) {
            await clientData.client.sendMessage(groupId, message, messageOptions);
        } else {
            const { MessageMedia } = require('whatsapp-web.js');
            try {
                const media = MessageMedia.fromFilePath(req.file.path);
                console.log('Group message media:', media.mimetype, req.file.originalname);
                
                messageOptions.caption = message || '';
                if (messageType === 'video') {
                    await clientData.client.sendMessage(groupId, media, messageOptions);
                } else {
                    await clientData.client.sendMessage(groupId, media, messageOptions);
                }
            } catch (mediaError) {
                console.error('Group media processing error:', mediaError);
                throw new Error('Failed to process media file for group');
            }
        }
        
        await db.insert(
            'INSERT INTO message_logs (user_id, message_type, recipient, message, status) VALUES (?, ?, ?, ?, ?)',
            [userId, 'group', groupId, message, 'sent']
        );
        await db.updateAnalytics(userId, 'message');
        
        res.json({ success: true, message: 'Message sent to group successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create new WhatsApp group
app.post('/api/groups/create', authMiddleware, subscriptionMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { groupName, numbers } = req.body;
        const clientData = whatsappClients.get(userId);
        
        if (!clientData || !clientData.isReady()) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        if (!groupName || !numbers || numbers.length === 0) {
            return res.status(400).json({ error: 'Group name and numbers are required' });
        }

        // Format numbers for WhatsApp
        const participants = numbers.map(num => {
            const cleanNum = num.replace(/[^0-9]/g, '');
            return cleanNum.includes('@c.us') ? cleanNum : `${cleanNum}@c.us`;
        });

        // Create group
        const group = await clientData.client.createGroup(groupName, participants);
        
        res.json({ 
            success: true, 
            groupId: group.gid._serialized,
            groupName: groupName,
            participantCount: participants.length,
            message: 'Group created successfully' 
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Broadcast message to all groups
app.post('/api/groups/broadcast', authMiddleware, subscriptionMiddleware, upload.single('media'), async (req, res) => {
    try {
        const userId = req.user.id;
        const { message, messageType, selectedGroups, delayType, fixedDelay, minDelay, maxDelay, mentionAll } = req.body;
        const clientData = whatsappClients.get(userId);
        
        if (!clientData || !clientData.isReady()) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const chats = await clientData.client.getChats();
        let targetGroups = chats.filter(chat => chat.isGroup);
        
        // Filter selected groups if specified
        if (selectedGroups && selectedGroups.length > 0) {
            targetGroups = targetGroups.filter(group => selectedGroups.includes(group.id._serialized));
        }
        
        // Create task for group broadcast
        const campaignId = `group_broadcast_${userId}_${Date.now()}`;
        await db.insert(
            'INSERT INTO campaigns (id, user_id, type, total_count, status, created_at, task_name, task_description) VALUES (?, ?, ?, ?, ?, NOW(), ?, ?)',
            [campaignId, userId, 'group_broadcast', targetGroups.length, 'running', 'Group Broadcast Campaign', `Broadcasting to ${targetGroups.length} groups`]
        );
        
        const campaignData = { userId, type: 'group_broadcast', total: targetGroups.length, processed: 0, success: 0, failed: 0, startTime: new Date(), status: 'running' };
        activeCampaigns.set(campaignId, campaignData);
        campaignControls.set(campaignId, { shouldStop: false });
        
        io.to(userId).emit('task-created', {
            id: campaignId,
            type: 'group_broadcast',
            name: 'Group Broadcast Campaign',
            total: targetGroups.length,
            status: 'running'
        });
        
        const results = [];
        const { MessageMedia } = require('whatsapp-web.js');
        let media = null;
        if (req.file && messageType !== 'text') {
            try {
                media = MessageMedia.fromFilePath(req.file.path);
                console.log('Broadcast media loaded:', media.mimetype, req.file.originalname);
            } catch (error) {
                console.error('Broadcast media loading error:', error);
                return res.status(400).json({ error: 'Failed to load media file for broadcast' });
            }
        }

        for (let i = 0; i < targetGroups.length; i++) {
            const group = targetGroups[i];
            
            try {
                let messageOptions = {};
                
                // Add mentions if requested
                if (mentionAll) {
                    const chat = await clientData.client.getChatById(group.id._serialized);
                    if (chat.isGroup && chat.participants) {
                        messageOptions.mentions = chat.participants.map(p => p.id._serialized);
                    }
                }
                
                if (messageType === 'text' || !media) {
                    await clientData.client.sendMessage(group.id._serialized, message, messageOptions);
                } else {
                    messageOptions.caption = message || '';
                    if (messageType === 'video') {
                        await clientData.client.sendMessage(group.id._serialized, media, messageOptions);
                    } else {
                        await clientData.client.sendMessage(group.id._serialized, media, messageOptions);
                    }
                }
                
                await db.insert(
                    'INSERT INTO message_logs (user_id, message_type, recipient, message, status) VALUES (?, ?, ?, ?, ?)',
                    [userId, 'group_broadcast', group.id._serialized, message, 'sent']
                );
                
                // Log detailed task information
                await db.insert(
                    'INSERT INTO task_details (task_id, campaign_id, user_id, recipient, message_content, status) VALUES (?, ?, ?, ?, ?, ?)',
                    [campaignId, campaignId, userId, group.name, message, 'sent']
                );
                
                await db.updateAnalytics(userId, 'group_broadcast');
                
                results.push({ groupId: group.id._serialized, groupName: group.name, status: 'sent' });
                
                // Update campaign progress
                const campaign = activeCampaigns.get(campaignId);
                if (campaign) {
                    campaign.processed = i + 1;
                    campaign.success++;
                    await db.query('UPDATE campaigns SET success_count = ?, processed_count = ? WHERE id = ?', 
                        [campaign.success, campaign.processed, campaignId]);
                }
                
                io.to(userId).emit('broadcast-progress', {
                    campaignId,
                    current: i + 1,
                    total: targetGroups.length,
                    groupName: group.name,
                    status: 'sent'
                });
                
                io.to(userId).emit('task-progress', {
                    id: campaignId,
                    processed: i + 1,
                    total: targetGroups.length,
                    status: 'running'
                });
                
                // Add delay between messages
                if (i < targetGroups.length - 1) {
                    let delay = 3000;
                    if (delayType === 'fixed' && fixedDelay) {
                        delay = Math.max(parseInt(fixedDelay) * 1000, 3000);
                    } else if (delayType === 'random' && minDelay && maxDelay) {
                        const min = Math.max(parseInt(minDelay), 3);
                        const max = Math.max(parseInt(maxDelay), min + 1);
                        delay = (Math.random() * (max - min) + min) * 1000;
                    }
                    await new Promise(resolve => setTimeout(resolve, delay));
                }
                
            } catch (error) {
                // Update campaign progress for failed
                const campaign = activeCampaigns.get(campaignId);
                if (campaign) {
                    campaign.processed = i + 1;
                    campaign.failed++;
                    await db.query('UPDATE campaigns SET failed_count = ?, processed_count = ? WHERE id = ?', 
                        [campaign.failed, campaign.processed, campaignId]);
                }
                
                results.push({ groupId: group.id._serialized, groupName: group.name, status: 'failed', error: error.message });
                io.to(userId).emit('broadcast-progress', {
                    campaignId,
                    current: i + 1,
                    total: targetGroups.length,
                    groupName: group.name,
                    status: 'failed'
                });
                
                io.to(userId).emit('task-progress', {
                    id: campaignId,
                    processed: i + 1,
                    total: targetGroups.length,
                    status: 'running'
                });
            }
        }

        // Mark campaign as completed
        const finalStatus = campaignControls.get(campaignId)?.shouldStop ? 'stopped' : 'completed';
        await db.query('UPDATE campaigns SET status = ?, completed_at = NOW() WHERE id = ?', [finalStatus, campaignId]);
        activeCampaigns.delete(campaignId);
        campaignControls.delete(campaignId);
        
        io.to(userId).emit('task-completed', {
            id: campaignId,
            status: finalStatus,
            results: results.length
        });
        
        res.json({ success: true, results, totalGroups: targetGroups.length, campaignId });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/contacts', authMiddleware, subscriptionMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const clientData = whatsappClients.get(userId);
        
        if (!clientData || !clientData.isReady()) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const chats = await clientData.client.getChats();
        const contacts = chats.filter(chat => !chat.isGroup).map(chat => ({
            id: chat.id._serialized,
            name: chat.name,
            number: chat.id.user
        }));

        await db.updateAnalytics(userId, 'contacts');
        res.json(contacts);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Broadcast to all contacts
app.post('/api/contacts/broadcast', authMiddleware, subscriptionMiddleware, upload.single('media'), async (req, res) => {
    try {
        const userId = req.user.id;
        const { message, messageType, delayType, fixedDelay, minDelay, maxDelay } = req.body;
        const clientData = whatsappClients.get(userId);
        
        if (!clientData || !clientData.isReady()) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const chats = await clientData.client.getChats();
        const contacts = chats.filter(chat => !chat.isGroup);
        
        // Create task for contact broadcast
        const campaignId = `contact_broadcast_${userId}_${Date.now()}`;
        await db.insert(
            'INSERT INTO campaigns (id, user_id, type, total_count, status, created_at, task_name, task_description) VALUES (?, ?, ?, ?, ?, NOW(), ?, ?)',
            [campaignId, userId, 'contact_broadcast', contacts.length, 'running', 'Contact Broadcast Campaign', `Broadcasting to ${contacts.length} contacts`]
        );
        
        const campaignData = { userId, type: 'contact_broadcast', total: contacts.length, processed: 0, success: 0, failed: 0, startTime: new Date(), status: 'running' };
        activeCampaigns.set(campaignId, campaignData);
        campaignControls.set(campaignId, { shouldStop: false });
        
        io.to(userId).emit('task-created', {
            id: campaignId,
            type: 'contact_broadcast',
            name: 'Contact Broadcast Campaign',
            total: contacts.length,
            status: 'running'
        });
        
        const results = [];
        
        const { MessageMedia } = require('whatsapp-web.js');
        let media = null;
        if (req.file && messageType !== 'text') {
            try {
                media = MessageMedia.fromFilePath(req.file.path);
            } catch (error) {
                return res.status(400).json({ error: 'Failed to load media file' });
            }
        }

        for (let i = 0; i < contacts.length; i++) {
            const contact = contacts[i];
            
            try {
                if (messageType === 'text' || !media) {
                    await clientData.client.sendMessage(contact.id._serialized, message);
                } else {
                    if (messageType === 'video') {
                        await clientData.client.sendMessage(contact.id._serialized, media, { caption: message || '' });
                    } else {
                        await clientData.client.sendMessage(contact.id._serialized, media, { caption: message });
                    }
                }
                
                results.push({ contactName: contact.name, status: 'sent' });
                
                // Log detailed task information
                await db.insert(
                    'INSERT INTO task_details (task_id, campaign_id, user_id, recipient, message_content, status) VALUES (?, ?, ?, ?, ?, ?)',
                    [campaignId, campaignId, userId, contact.name || contact.id.user, message, 'sent']
                );
                
                await db.updateAnalytics(userId, 'contact_broadcast');
                io.to(userId).emit('contact-broadcast-progress', {
                    current: i + 1,
                    total: contacts.length,
                    contactName: contact.name,
                    status: 'sent'
                });
                
                if (i < contacts.length - 1) {
                    let delay = 3000;
                    if (delayType === 'fixed' && fixedDelay) {
                        delay = Math.max(parseInt(fixedDelay) * 1000, 3000);
                    } else if (delayType === 'random' && minDelay && maxDelay) {
                        const min = Math.max(parseInt(minDelay), 3);
                        const max = Math.max(parseInt(maxDelay), min + 1);
                        delay = (Math.random() * (max - min) + min) * 1000;
                    }
                    await new Promise(resolve => setTimeout(resolve, delay));
                }
                
            } catch (error) {
                results.push({ contactName: contact.name, status: 'failed', error: error.message });
                
                // Log detailed task failure
                await db.insert(
                    'INSERT INTO task_details (task_id, campaign_id, user_id, recipient, message_content, status, error_message) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    [campaignId, campaignId, userId, contact.name || contact.id.user, message, 'failed', error.message]
                );
                
                io.to(userId).emit('contact-broadcast-progress', {
                    current: i + 1,
                    total: contacts.length,
                    contactName: contact.name,
                    status: 'failed'
                });
            }
        }

        res.json({ success: true, results, totalContacts: contacts.length });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Export contacts to Google Contacts format
app.get('/api/contacts/export-google', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const clientData = whatsappClients.get(userId);
        
        if (!clientData || !clientData.isReady()) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const chats = await clientData.client.getChats();
        const contacts = chats.filter(chat => !chat.isGroup);
        
        // Google Contacts CSV format
        const csvHeader = 'Name,Given Name,Additional Name,Family Name,Yomi Name,Given Name Yomi,Additional Name Yomi,Family Name Yomi,Name Prefix,Name Suffix,Initials,Nickname,Short Name,Maiden Name,Birthday,Gender,Location,Billing Information,Directory Server,Mileage,Occupation,Hobby,Sensitivity,Priority,Subject,Notes,Language,Photo,Group Membership,Phone 1 - Type,Phone 1 - Value';
        
        const csvRows = contacts.map(contact => {
            const name = contact.name || contact.id.user;
            const phone = contact.id.user;
            return `"${name}","${name}",,,,,,,,,,,,,,,,,,,,,,,,,,,,"Mobile","${phone}"`;
        });
        
        const csv = csvHeader + '\n' + csvRows.join('\n');
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="whatsapp_contacts_google.csv"');
        res.send(csv);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Chat bot message handler
async function handleIncomingMessage(userId, message, client) {
    try {
        const rules = await db.query('SELECT * FROM bot_rules WHERE user_id = ?', [userId]);
        if (rules.length === 0) return;
        
        const messageText = message.body.toLowerCase().trim();
        let response = null;
        
        // Check exact match rules first
        for (const rule of rules.filter(r => r.rule_type === 'exact')) {
            if (messageText === rule.question.toLowerCase()) {
                response = rule.answer;
                break;
            }
        }
        
        // Check keyword rules if no exact match
        if (!response) {
            for (const rule of rules.filter(r => r.rule_type === 'keyword')) {
                const keywords = JSON.parse(rule.keywords || '[]');
                if (keywords.some(keyword => messageText.includes(keyword.toLowerCase()))) {
                    response = rule.answer;
                    break;
                }
            }
        }
        
        if (response) {
            await client.sendMessage(message.from, response);
            await db.updateAnalytics(userId, 'bot_response');
            
            // Emit bot activity
            io.to(userId).emit('bot-response', {
                from: message.from,
                question: message.body,
                answer: response,
                timestamp: new Date()
            });
        }
        
        // Auto-add to groups feature
        const autoAddSettings = await db.queryOne('SELECT * FROM auto_add_settings WHERE user_id = ? AND is_enabled = true', [userId]);
        if (autoAddSettings && autoAddSettings.keywords) {
            const keywords = JSON.parse(autoAddSettings.keywords);
            const shouldAutoAdd = keywords.some(keyword => messageText.includes(keyword.toLowerCase()));
            
            if (shouldAutoAdd) {
                try {
                    const chats = await client.getChats();
                    const adminGroups = chats.filter(chat => {
                        if (!chat.isGroup) return false;
                        const currentUserWid = client.info?.wid?._serialized;
                        const currentUserParticipant = chat.participants?.find(p => p.id._serialized === currentUserWid);
                        return currentUserParticipant?.isAdmin || currentUserParticipant?.isSuperAdmin;
                    });
                    
                    for (const group of adminGroups) {
                        try {
                            await group.addParticipants([message.from]);
                            console.log(`Auto-added ${message.from} to ${group.name}`);
                        } catch (error) {
                            if (!error.message.includes('already')) {
                                console.log(`Failed to auto-add ${message.from} to ${group.name}: ${error.message}`);
                            }
                        }
                    }
                } catch (error) {
                    console.error('Auto-add error:', error.message);
                }
            }
        }
    } catch (error) {
        console.error('Bot handler error:', error);
    }
}

// Chat bot API endpoints
app.get('/api/chatbot/rules', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const rules = await db.query('SELECT * FROM bot_rules WHERE user_id = ? AND is_enabled = true', [userId]);
        
        const exactRules = rules.filter(r => r.rule_type === 'exact').map(r => ({
            question: r.question,
            answer: r.answer
        }));
        
        const keywordRules = rules.filter(r => r.rule_type === 'keyword').map(r => ({
            keywords: JSON.parse(r.keywords),
            answer: r.answer
        }));
        
        // Get auto-add settings
        const autoAddSettings = await db.queryOne('SELECT * FROM auto_add_settings WHERE user_id = ?', [userId]);
        
        res.json({
            enabled: rules.length > 0,
            exactRules,
            keywordRules,
            autoAdd: {
                enabled: autoAddSettings?.is_enabled || false,
                keywords: autoAddSettings?.keywords ? JSON.parse(autoAddSettings.keywords) : ['thank', 'thanks']
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/chatbot/rules', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { enabled, exactRules, keywordRules, autoAdd } = req.body;
        
        // Clear existing rules
        await db.query('DELETE FROM bot_rules WHERE user_id = ?', [userId]);
        
        if (enabled) {
            // Insert exact rules
            for (const rule of exactRules || []) {
                await db.insert(
                    'INSERT INTO bot_rules (user_id, rule_type, question, answer) VALUES (?, ?, ?, ?)',
                    [userId, 'exact', rule.question, rule.answer]
                );
            }
            
            // Insert keyword rules
            for (const rule of keywordRules || []) {
                await db.insert(
                    'INSERT INTO bot_rules (user_id, rule_type, keywords, answer) VALUES (?, ?, ?, ?)',
                    [userId, 'keyword', JSON.stringify(rule.keywords), rule.answer]
                );
            }
        }
        
        // Update auto-add settings
        if (autoAdd) {
            await db.query(
                'INSERT INTO auto_add_settings (user_id, is_enabled, keywords) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE is_enabled = ?, keywords = ?',
                [userId, autoAdd.enabled, JSON.stringify(autoAdd.keywords), autoAdd.enabled, JSON.stringify(autoAdd.keywords)]
            );
        }
        
        res.json({ success: true, message: 'Chat bot rules updated' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/chatbot/rules/:id', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { id } = req.params;
        
        await db.query('DELETE FROM bot_rules WHERE id = ? AND user_id = ?', [id, userId]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});



// Get user subscription status
app.get('/api/subscription/status', authMiddleware, async (req, res) => {
    try {
        const user = await db.queryOne(
            'SELECT subscription_type, subscription_expires, whatsapp_number FROM users WHERE id = ?', 
            [req.user.id]
        );
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Ensure proper date formatting
        const result = {
            subscription_type: user.subscription_type || 'trial',
            subscription_expires: user.subscription_expires,
            whatsapp_number: user.whatsapp_number
        };
        
        res.json(result);
    } catch (error) {
        console.error('Subscription status error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Stop campaign
app.post('/api/campaigns/stop/:campaignId', authMiddleware, async (req, res) => {
    try {
        const { campaignId } = req.params;
        const userId = req.user.id;
        
        // Check if campaign exists and belongs to user
        const campaign = await db.queryOne(
            'SELECT * FROM campaigns WHERE id = ? AND user_id = ? AND status IN ("running", "paused")',
            [campaignId, userId]
        );
        
        if (!campaign) {
            return res.status(404).json({ error: 'Campaign not found or already stopped' });
        }
        
        // Set stop flag for active campaigns
        const activeCampaign = activeCampaigns.get(campaignId);
        if (activeCampaign) {
            campaignControls.set(campaignId, { shouldStop: true });
            activeCampaigns.delete(campaignId);
            campaignControls.delete(campaignId);
        }
        
        // Update database status
        await db.query(
            'UPDATE campaigns SET status = ?, completed_at = NOW() WHERE id = ? AND user_id = ?', 
            ['stopped', campaignId, userId]
        );
        
        res.json({ success: true, message: 'Campaign stopped successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get active campaigns
app.get('/api/campaigns/active', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Get from database for persistence
        const campaigns = await db.query(
            'SELECT * FROM campaigns WHERE user_id = ? AND status IN ("running", "paused") ORDER BY created_at DESC',
            [userId]
        );
        
        const userCampaigns = campaigns.map(campaign => ({
            id: campaign.id,
            type: campaign.type,
            total: campaign.total_count || 0,
            processed: campaign.processed_count || 0,
            success: campaign.success_count || 0,
            failed: campaign.failed_count || 0,
            startTime: campaign.created_at,
            status: campaign.status,
            eta: calculateETA(campaign.processed_count || 0, campaign.total_count || 0, new Date(campaign.created_at))
        }));
        
        res.json(userCampaigns);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Schedule message
app.post('/api/messages/schedule', authMiddleware, subscriptionMiddleware, upload.single('media'), async (req, res) => {
    try {
        const userId = req.user.id;
        const { recipient, message, messageType, scheduledAt } = req.body;
        
        let mediaPath = null;
        if (req.file) {
            mediaPath = req.file.path;
        }
        
        const queueId = await db.insert(
            'INSERT INTO message_queue (user_id, recipient, message, message_type, media_path, scheduled_at) VALUES (?, ?, ?, ?, ?, ?)',
            [userId, recipient, message, messageType || 'text', mediaPath, scheduledAt]
        );
        
        // Create task for scheduled message
        const taskId = `message_scheduler_${userId}_${Date.now()}`;
        await db.insert(
            'INSERT INTO campaigns (id, user_id, type, total_count, status, task_name, task_description) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [taskId, userId, 'message_scheduler', 1, 'running', 'Scheduled Message', `Message scheduled for ${new Date(scheduledAt).toLocaleString()}`]
        );
        
        res.json({ success: true, queueId, taskId, message: 'Message scheduled successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get scheduled messages
app.get('/api/messages/scheduled', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const scheduled = await db.query(
            'SELECT * FROM message_queue WHERE user_id = ? AND status = "pending" ORDER BY scheduled_at ASC',
            [userId]
        );
        res.json(scheduled);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Cancel scheduled message
app.delete('/api/messages/scheduled/:id', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { id } = req.params;
        
        const result = await db.query('DELETE FROM message_queue WHERE id = ? AND user_id = ? AND status = "pending"', [id, userId]);
        
        if (result.affectedRows > 0) {
            res.json({ success: true, message: 'Scheduled message cancelled' });
        } else {
            res.status(404).json({ error: 'Scheduled message not found or already processed' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Retry failed scheduled message
app.post('/api/messages/scheduled/:id/retry', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { id } = req.params;
        
        // Reset the message to pending status and update scheduled time to now
        const result = await db.query(
            'UPDATE message_queue SET status = "pending", attempts = 0, scheduled_at = NOW() WHERE id = ? AND user_id = ? AND status = "failed"',
            [id, userId]
        );
        
        if (result.affectedRows > 0) {
            res.json({ success: true, message: 'Message queued for retry' });
        } else {
            res.status(404).json({ error: 'Failed message not found' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get scheduled message statistics
app.get('/api/messages/scheduled/stats', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const stats = await db.queryOne(`
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END) as sent,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
            FROM message_queue 
            WHERE user_id = ?
        `, [userId]);
        
        res.json(stats || { total: 0, pending: 0, sent: 0, failed: 0 });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all scheduled messages with status grouping
app.get('/api/messages/scheduled/all', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { status } = req.query;
        
        let query = 'SELECT * FROM message_queue WHERE user_id = ?';
        let params = [userId];
        
        if (status) {
            query += ' AND status = ?';
            params.push(status);
        }
        
        query += ' ORDER BY scheduled_at DESC';
        
        const messages = await db.query(query, params);
        res.json(messages);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Import contacts from CSV
app.post('/api/contacts/import', authMiddleware, subscriptionMiddleware, upload.single('csvFile'), async (req, res) => {
    try {
        const userId = req.user.id;
        const csvFile = req.file;
        
        if (!csvFile) {
            return res.status(400).json({ error: 'CSV file required' });
        }
        
        const fs = require('fs');
        const csv = require('csv-parser');
        const contacts = [];
        const errors = [];
        
        fs.createReadStream(csvFile.path)
            .pipe(csv())
            .on('data', (row) => {
                const phone = row.phone || row.number || row.Phone || row.Number;
                const name = row.name || row.Name || phone;
                
                if (phone && phone.match(/^[+]?[0-9]{10,15}$/)) {
                    contacts.push({ name, phone: phone.replace(/[^+0-9]/g, '') });
                } else {
                    errors.push({ row, error: 'Invalid phone number' });
                }
            })
            .on('end', async () => {
                let imported = 0;
                let duplicates = 0;
                
                for (const contact of contacts) {
                    try {
                        await db.insert(
                            'INSERT IGNORE INTO contacts (user_id, name, phone_number) VALUES (?, ?, ?)',
                            [userId, contact.name, contact.phone]
                        );
                        imported++;
                    } catch (error) {
                        if (error.code === 'ER_DUP_ENTRY') {
                            duplicates++;
                        }
                    }
                }
                
                fs.unlinkSync(csvFile.path); // Clean up file
                
                res.json({
                    success: true,
                    imported,
                    duplicates,
                    errors: errors.length,
                    errorDetails: errors.slice(0, 10) // First 10 errors
                });
            });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create contact group
app.post('/api/contacts/groups', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { name, description } = req.body;
        
        const groupId = await db.insert(
            'INSERT INTO contact_groups (user_id, name, description) VALUES (?, ?, ?)',
            [userId, name, description]
        );
        
        res.json({ success: true, groupId, message: 'Contact group created' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get contact groups
app.get('/api/contacts/groups', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const groups = await db.query(
            'SELECT g.*, COUNT(m.contact_id) as member_count FROM contact_groups g LEFT JOIN contact_group_members m ON g.id = m.group_id WHERE g.user_id = ? GROUP BY g.id',
            [userId]
        );
        res.json(groups);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add contacts to group
app.post('/api/contacts/groups/:groupId/members', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { groupId } = req.params;
        const { contactIds } = req.body;
        
        for (const contactId of contactIds) {
            await db.query(
                'INSERT IGNORE INTO contact_group_members (group_id, contact_id) VALUES (?, ?)',
                [groupId, contactId]
            );
        }
        
        res.json({ success: true, message: 'Contacts added to group' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add tags to contact
app.post('/api/contacts/:contactId/tags', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { contactId } = req.params;
        const { tags } = req.body;
        
        await db.query(
            'UPDATE contacts SET tags = ? WHERE id = ? AND user_id = ?',
            [JSON.stringify(tags), contactId, userId]
        );
        
        res.json({ success: true, message: 'Tags added successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Deduplicate contacts
app.post('/api/contacts/deduplicate', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Find duplicates and keep the most recent one
        const result = await db.query(`
            DELETE c1 FROM contacts c1
            INNER JOIN contacts c2 
            WHERE c1.user_id = ? AND c2.user_id = ? 
            AND c1.phone_number = c2.phone_number 
            AND c1.id < c2.id
        `, [userId, userId]);
        
        res.json({ success: true, duplicatesRemoved: result.affectedRows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Download campaign report
app.get('/api/campaigns/download-report', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const results = global.lastResults?.[userId] || [];
        
        if (results.length === 0) {
            return res.status(404).json({ error: 'No results to download' });
        }
        
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const csvContent = [
            'Number,Status,Error,Index,Timestamp',
            ...results.map(result => 
                `"${result.number}","${result.status}","${result.error || ''}","${result.index}","${new Date().toLocaleString()}"`
            )
        ].join('\n');
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="bulk-campaign-report-${timestamp}.csv"`);
        res.send(csvContent);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get campaign status
app.get('/api/campaigns/status', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const campaigns = await db.query(
            'SELECT * FROM campaigns WHERE user_id = ? ORDER BY created_at DESC LIMIT 10',
            [userId]
        );
        res.json(campaigns);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});



// Add numbers to groups - Enhanced version with proper permission checking
app.post('/api/groups/add-numbers', authMiddleware, subscriptionMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { numbers, selectedGroups, delayType, fixedDelay, minDelay, maxDelay } = req.body;
        const clientData = whatsappClients.get(userId);
        
        if (!clientData || !clientData.isReady()) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        // Create task for group adder
        const campaignId = `group_adder_${userId}_${Date.now()}`;
        const totalOperations = numbers.length * selectedGroups.length;
        
        await db.insert(
            'INSERT INTO campaigns (id, user_id, type, total_count, status, created_at, task_name, task_description) VALUES (?, ?, ?, ?, ?, NOW(), ?, ?)',
            [campaignId, userId, 'group_adder', totalOperations, 'running', 'Group Adder Campaign', `Adding ${numbers.length} numbers to ${selectedGroups.length} groups`]
        );
        
        const campaignData = { userId, type: 'group_adder', total: totalOperations, processed: 0, success: 0, failed: 0, startTime: new Date(), status: 'running' };
        activeCampaigns.set(campaignId, campaignData);
        campaignControls.set(campaignId, { shouldStop: false });
        
        io.to(userId).emit('task-created', {
            id: campaignId,
            type: 'group_adder',
            name: 'Group Adder Campaign',
            total: totalOperations,
            status: 'running'
        });

        const results = [];
        let operationCount = 0;
        
        // Get current user's WhatsApp ID for permission checking
        const currentUserWid = clientData.client.info?.wid?._serialized;
        
        for (let i = 0; i < numbers.length; i++) {
            const number = numbers[i].trim();
            if (!number) continue;
            
            const cleanNumber = number.replace(/[^0-9]/g, '');
            const formattedNumber = cleanNumber.includes('@c.us') ? cleanNumber : `${cleanNumber}@c.us`;
            
            for (let j = 0; j < selectedGroups.length; j++) {
                const groupId = selectedGroups[j];
                
                operationCount++;
                
                // Check if campaign should stop
                const control = campaignControls.get(campaignId);
                if (control && control.shouldStop) {
                    results.push({ number, groupName: 'Unknown', status: 'cancelled', error: 'Campaign stopped by user' });
                    break;
                }
                
                try {
                    const chat = await clientData.client.getChatById(groupId);
                    if (!chat || !chat.isGroup) {
                        throw new Error('Invalid group or group not found');
                    }
                    
                    const groupName = chat.name || 'Unknown Group';
                    const currentUserParticipant = chat.participants?.find(p => p.id._serialized === currentUserWid);
                    const isAdmin = currentUserParticipant?.isAdmin || currentUserParticipant?.isSuperAdmin;
                    
                    let addSuccess = false;
                    let finalStatus = 'failed';
                    let errorMsg = '';
                    
                    // Try direct add first
                    try {
                        await chat.addParticipants([formattedNumber]);
                        
                        // Verify the member was actually added
                        await new Promise(resolve => setTimeout(resolve, 2000));
                        const updatedChat = await clientData.client.getChatById(groupId);
                        const memberExists = updatedChat.participants.some(p => p.id.user === cleanNumber);
                        
                        if (memberExists) {
                            addSuccess = true;
                            finalStatus = 'added';
                            console.log(`✅ Verified: ${number} successfully added to ${groupName}`);
                        } else {
                            // Member not added, try invite link
                            throw new Error('Member not actually added');
                        }
                    } catch (addError) {
                        console.log(`Add error for ${number} to ${groupName}:`, addError.message);
                        if (addError.message.includes('participant already exists') || 
                            addError.message.includes('already a participant') ||
                            addError.message.includes('already in group')) {
                            addSuccess = true;
                            finalStatus = 'already_member';
                        } else if (addError.message.includes('no admin rights')) {
                            // Try invite link method for non-admin users
                            console.log(`Trying invite link method for ${number}`);
                            try {
                                const inviteCode = await chat.getInviteCode();
                                const inviteLink = `https://chat.whatsapp.com/${inviteCode}`;
                                const inviteMessage = `Join "${groupName}" group: ${inviteLink}`;
                                
                                await clientData.client.sendMessage(formattedNumber, inviteMessage);
                                addSuccess = true;
                                finalStatus = 'invite_sent';
                                console.log(`✅ Invite sent to ${number} for ${groupName}`);
                            } catch (inviteError) {
                                console.log(`Invite failed for ${number}: ${inviteError.message}`);
                                errorMsg = 'Cannot send invite - no admin rights';
                            }
                        } else {
                            // For any other error including silent failures, try invite link
                            console.log(`Trying invite link method for ${number}`);
                            try {
                                const inviteCode = await chat.getInviteCode();
                                const inviteLink = `https://chat.whatsapp.com/${inviteCode}`;
                                const inviteMessage = `Join "${groupName}" group: ${inviteLink}`;
                                
                                await clientData.client.sendMessage(formattedNumber, inviteMessage);
                                addSuccess = true;
                                finalStatus = 'invite_sent';
                                console.log(`✅ Invite sent to ${number} for ${groupName}`);
                            } catch (inviteError) {
                                console.log(`Invite failed for ${number}: ${inviteError.message}`);
                                errorMsg = addError.message;
                            }
                        }
                    }
                    

                    
                    if (!addSuccess) {
                        console.log(`❌ Failed to add ${number} to ${groupName}: ${errorMsg}`);
                        throw new Error(errorMsg || 'Failed to add member');
                    }
                        
                    let statusText = finalStatus === 'added' ? 'Successfully Added' : 
                                   finalStatus === 'already_member' ? 'Already Member' : 'Invite Sent';
                    
                    results.push({ 
                        number: number, 
                        groupName: groupName, 
                        status: finalStatus,
                        statusText: statusText,
                        method: isAdmin ? 'Admin Rights' : 'Member Rights'
                    });
                        
                    // Log detailed task information
                    await db.insert(
                        'INSERT INTO task_details (task_id, campaign_id, user_id, recipient, message_content, status) VALUES (?, ?, ?, ?, ?, ?)',
                        [campaignId, campaignId, userId, `${number} -> ${groupName}`, `Added to group: ${groupName} (${finalStatus})`, 'sent']
                    );
                    
                    // Update success count
                    const campaign = activeCampaigns.get(campaignId);
                    if (campaign) {
                        campaign.processed = operationCount;
                        campaign.success++;
                        await db.query('UPDATE campaigns SET success_count = ?, processed_count = ? WHERE id = ?', 
                            [campaign.success, campaign.processed, campaignId]);
                    }
                    
                } catch (error) {
                    let groupName = 'Unknown Group';
                    try {
                        const chat = await clientData.client.getChatById(selectedGroups[j]);
                        groupName = chat.name || 'Unknown Group';
                    } catch {}
                    
                    results.push({ 
                        number: number, 
                        groupName: groupName, 
                        status: 'failed', 
                        error: error.message,
                        statusText: 'Failed'
                    });
                    
                    await db.insert(
                        'INSERT INTO task_details (task_id, campaign_id, user_id, recipient, message_content, status, error_message) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        [campaignId, campaignId, userId, `${number} -> ${groupName}`, `Failed to add to group`, 'failed', error.message]
                    );
                    
                    // Update failed count
                    const campaign = activeCampaigns.get(campaignId);
                    if (campaign) {
                        campaign.processed = operationCount;
                        campaign.failed++;
                        await db.query('UPDATE campaigns SET failed_count = ?, processed_count = ? WHERE id = ?', 
                            [campaign.failed, campaign.processed, campaignId]);
                    }
                }
                
                // Emit progress
                const lastResult = results[results.length - 1];
                io.to(userId).emit('group-adder-progress', {
                    campaignId,
                    current: operationCount,
                    total: totalOperations,
                    number,
                    groupName: lastResult?.groupName || 'Unknown',
                    status: lastResult?.status || 'failed',
                    statusText: lastResult?.statusText || 'Failed',
                    method: lastResult?.method || 'Unknown'
                });
                
                io.to(userId).emit('task-progress', {
                    id: campaignId,
                    processed: operationCount,
                    total: totalOperations,
                    status: 'running'
                });
                
                // Add delay between operations
                if (i < numbers.length - 1 || j < selectedGroups.length - 1) {
                    let delay = 3000;
                    if (delayType === 'fixed' && fixedDelay) {
                        delay = Math.max(parseInt(fixedDelay) * 1000, 3000);
                    } else if (delayType === 'random' && minDelay && maxDelay) {
                        const min = Math.max(parseInt(minDelay), 3);
                        const max = Math.max(parseInt(maxDelay), min + 1);
                        delay = (Math.random() * (max - min) + min) * 1000;
                    }
                    await new Promise(resolve => setTimeout(resolve, delay));
                }
            }
        }
        
        // Mark campaign as completed
        const finalStatus = campaignControls.get(campaignId)?.shouldStop ? 'stopped' : 'completed';
        await db.query('UPDATE campaigns SET status = ?, completed_at = NOW() WHERE id = ?', [finalStatus, campaignId]);
        activeCampaigns.delete(campaignId);
        campaignControls.delete(campaignId);
        
        io.to(userId).emit('task-completed', {
            id: campaignId,
            status: finalStatus,
            results: results.length
        });
        
        res.json({ success: true, results, campaignId });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Stop all campaigns for user
app.post('/api/campaigns/stop-all', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const campaigns = await db.query(
            'SELECT id FROM campaigns WHERE user_id = ? AND status IN ("running", "paused")',
            [userId]
        );
        
        let stoppedCount = 0;
        
        for (const campaign of campaigns) {
            const activeCampaign = activeCampaigns.get(campaign.id);
            if (activeCampaign) {
                campaignControls.set(campaign.id, { shouldStop: true });
                activeCampaigns.delete(campaign.id);
                campaignControls.delete(campaign.id);
            }
            stoppedCount++;
        }
        
        await db.query(
            'UPDATE campaigns SET status = ?, completed_at = NOW() WHERE user_id = ? AND status IN ("running", "paused")',
            ['stopped', userId]
        );
        
        res.json({ success: true, message: `Stopped ${stoppedCount} campaigns`, count: stoppedCount });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// OTP System
const otpStore = new Map(); // Store OTPs temporarily

// Send OTP via admin WhatsApp
app.post('/api/send-otp', async (req, res) => {
    try {
        const { whatsappNumber, adminNumber, purpose } = req.body;
        
        if (!whatsappNumber || !adminNumber) {
            return res.status(400).json({ error: 'WhatsApp number and admin number required' });
        }
        
        // Generate 4-digit OTP
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        
        // Store OTP with expiration (5 minutes)
        otpStore.set(whatsappNumber, {
            otp: otp,
            expires: Date.now() + 5 * 60 * 1000,
            purpose: purpose
        });
        
        // Find ONLY admin client with number 923170973410
        let senderClient = null;
        for (const [userId, clientData] of whatsappClients) {
            if (clientData.isReady()) {
                try {
                    const phoneNumber = clientData.client.info?.wid?.user;
                    console.log('Checking client phone:', phoneNumber);
                    if (phoneNumber === '923170973410') {
                        senderClient = clientData.client;
                        console.log('Found admin client:', phoneNumber);
                        break;
                    }
                } catch (error) {
                    console.log('Error checking client info:', error.message);
                }
            }
        }
        
        if (senderClient) {
            try {
                const message = `🔐 OTP Verification\n\nYour OTP for ${purpose}:\n🔢 ${otp}\n\n⏰ Valid for 5 minutes\n\nFrom: Admin (923170973410)`;
                const chatId = whatsappNumber.includes('@c.us') ? whatsappNumber : `${whatsappNumber}@c.us`;
                
                await senderClient.sendMessage(chatId, message);
                console.log(`OTP ${otp} sent from admin 923170973410 to ${whatsappNumber}`);
                res.json({ success: true, message: 'OTP sent from admin number' });
            } catch (error) {
                console.error('Failed to send OTP from admin:', error);
                res.json({ success: true, message: 'OTP generated. Use demo OTP: 1234' });
            }
        } else {
            console.log(`Admin 923170973410 not connected. Demo OTP: ${otp}`);
            res.json({ success: true, message: 'OTP generated. Use demo OTP: 1234' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Verify OTP
app.post('/api/verify-otp', async (req, res) => {
    try {
        const { whatsappNumber, otp } = req.body;
        
        const storedOtp = otpStore.get(whatsappNumber);
        
        if (!storedOtp) {
            return res.status(400).json({ error: 'No OTP found for this number' });
        }
        
        if (Date.now() > storedOtp.expires) {
            otpStore.delete(whatsappNumber);
            return res.status(400).json({ error: 'OTP expired' });
        }
        
        // Accept demo OTP '1234' or generated OTP
        if (storedOtp.otp !== otp && otp !== '1234') {
            return res.status(400).json({ error: 'Invalid OTP' });
        }
        
        // OTP verified, remove from store
        otpStore.delete(whatsappNumber);
        res.json({ success: true, message: 'OTP verified successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Change password with OTP
app.post('/api/change-password', authMiddleware, async (req, res) => {
    try {
        const { currentPassword, newPassword, whatsappNumber, otp } = req.body;
        const userId = req.user.id;
        
        // Verify OTP first (accept demo OTP '1234' or generated OTP)
        const storedOtp = otpStore.get(whatsappNumber);
        if (!storedOtp || (storedOtp.otp !== otp && otp !== '1234') || Date.now() > storedOtp.expires) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }
        
        // Get user and verify current password
        const user = await db.queryOne('SELECT password FROM users WHERE id = ?', [userId]);
        if (!user || !await bcrypt.compare(currentPassword, user.password)) {
            return res.status(400).json({ error: 'Current password is incorrect' });
        }
        
        // Update password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        await db.query('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, userId]);
        
        // Remove OTP
        otpStore.delete(whatsappNumber);
        
        res.json({ success: true, message: 'Password changed successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Task Manager APIs

// Get all tasks for user
app.get('/api/tasks', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { status, type } = req.query;
        
        let query = 'SELECT * FROM campaigns WHERE user_id = ?';
        let params = [userId];
        
        if (status) {
            query += ' AND status = ?';
            params.push(status);
        }
        
        if (type) {
            query += ' AND type = ?';
            params.push(type);
        }
        
        query += ' ORDER BY created_at DESC';
        
        const tasks = await db.query(query, params);
        
        const formattedTasks = tasks.map(task => ({
            id: task.id,
            type: task.type,
            status: task.status,
            total: task.total_count || 0,
            processed: task.processed_count || 0,
            success: task.success_count || 0,
            failed: task.failed_count || 0,
            startTime: task.created_at,
            completedTime: task.completed_at,
            eta: task.status === 'running' ? calculateETA(task.processed_count || 0, task.total_count || 0, new Date(task.created_at)) : null,
            progress: task.total_count > 0 ? Math.round((task.processed_count / task.total_count) * 100) : 0
        }));
        
        res.json(formattedTasks);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all tasks (active and history)
app.get('/api/tasks', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { status, type, limit = 50 } = req.query;
        
        let query = 'SELECT * FROM campaigns WHERE user_id = ?';
        let params = [userId];
        
        if (status) {
            query += ' AND status = ?';
            params.push(status);
        }
        
        if (type) {
            query += ' AND type = ?';
            params.push(type);
        }
        
        query += ' ORDER BY created_at DESC LIMIT ?';
        params.push(parseInt(limit));
        
        const tasks = await db.query(query, params);
        
        res.json(tasks.map(task => ({
            id: task.id,
            type: task.type,
            status: task.status,
            name: task.task_name || task.type,
            total: task.total_count || 0,
            processed: task.processed_count || 0,
            success: task.success_count || 0,
            failed: task.failed_count || 0,
            startTime: task.created_at,
            completedTime: task.completed_at,
            canRestart: ['completed', 'failed', 'stopped'].includes(task.status)
        })));
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Stop task
app.post('/api/tasks/:taskId/stop', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { taskId } = req.params;
        
        const activeCampaign = activeCampaigns.get(taskId);
        if (activeCampaign) {
            campaignControls.set(taskId, { shouldStop: true });
            activeCampaigns.delete(taskId);
            campaignControls.delete(taskId);
        }
        
        await db.query(
            'UPDATE campaigns SET status = ?, completed_at = NOW() WHERE id = ? AND user_id = ?',
            ['stopped', taskId, userId]
        );
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Restart task
app.post('/api/tasks/:taskId/restart', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { taskId } = req.params;
        
        const task = await db.queryOne(
            'SELECT * FROM campaigns WHERE id = ? AND user_id = ?',
            [taskId, userId]
        );
        
        if (!task) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        const newTaskId = `${task.type}_restart_${Date.now()}`;
        
        await db.insert(
            'INSERT INTO campaigns (id, user_id, type, total_count, status, task_name, task_description, message_content, target_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [newTaskId, userId, task.type, task.total_count, 'running', `${task.task_name} (Restarted)`, 'Restarted task', task.message_content, task.target_data]
        );
        
        activeCampaigns.set(newTaskId, {
            userId,
            type: task.type,
            total: task.total_count,
            processed: 0,
            success: 0,
            failed: 0,
            startTime: new Date(),
            status: 'running'
        });
        
        res.json({ success: true, newTaskId });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Pause task
app.post('/api/tasks/:taskId/pause', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { taskId } = req.params;
        
        const activeCampaign = activeCampaigns.get(taskId);
        if (activeCampaign) {
            activeCampaign.status = 'paused';
        }
        
        await db.query(
            'UPDATE campaigns SET status = ? WHERE id = ? AND user_id = ?',
            ['paused', taskId, userId]
        );
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Resume task
app.post('/api/tasks/:taskId/resume', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { taskId } = req.params;
        
        const task = await db.queryOne(
            'SELECT * FROM campaigns WHERE id = ? AND user_id = ?',
            [taskId, userId]
        );
        
        if (!task) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        activeCampaigns.set(taskId, {
            userId,
            type: task.type,
            total: task.total_count || 0,
            processed: task.processed_count || 0,
            success: task.success_count || 0,
            failed: task.failed_count || 0,
            startTime: new Date(task.created_at),
            status: 'running'
        });
        
        await db.query(
            'UPDATE campaigns SET status = ? WHERE id = ? AND user_id = ?',
            ['running', taskId, userId]
        );
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete task
app.delete('/api/tasks/:taskId', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { taskId } = req.params;
        
        const activeCampaign = activeCampaigns.get(taskId);
        if (activeCampaign) {
            campaignControls.set(taskId, { shouldStop: true });
            activeCampaigns.delete(taskId);
            campaignControls.delete(taskId);
        }
        
        await db.query(
            'DELETE FROM campaigns WHERE id = ? AND user_id = ?',
            [taskId, userId]
        );
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get task history
app.get('/api/tasks/history', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { limit = 50, offset = 0, type } = req.query;
        
        let query = 'SELECT * FROM campaigns WHERE user_id = ?';
        let params = [userId];
        
        if (type) {
            query += ' AND type = ?';
            params.push(type);
        }
        
        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        params.push(parseInt(limit), parseInt(offset));
        
        const history = await db.query(query, params);
        
        const formattedHistory = history.map(task => ({
            id: task.id,
            type: task.type,
            status: task.status,
            total: task.total_count || 0,
            processed: task.processed_count || 0,
            success: task.success_count || 0,
            failed: task.failed_count || 0,
            startTime: task.created_at,
            completedTime: task.completed_at,
            duration: task.completed_at ? 
                Math.round((new Date(task.completed_at) - new Date(task.created_at)) / 1000) : null
        }));
        
        res.json(formattedHistory);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get task details
app.get('/api/tasks/:taskId/details', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { taskId } = req.params;
        
        const task = await db.queryOne(
            'SELECT * FROM campaigns WHERE id = ? AND user_id = ?',
            [taskId, userId]
        );
        
        if (!task) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        const details = await db.query(
            'SELECT * FROM task_details WHERE campaign_id = ? OR task_id = ? ORDER BY created_at DESC LIMIT 100',
            [taskId, taskId]
        );
        
        res.json({
            task: task,
            details: details || []
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get task statistics
app.get('/api/tasks/stats', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const stats = await db.query(`
            SELECT 
                COUNT(*) as totalTasks,
                SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as runningTasks,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completedTasks,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failedTasks,
                SUM(CASE WHEN status = 'stopped' THEN 1 ELSE 0 END) as stoppedTasks,
                SUM(total_count) as totalMessages,
                SUM(success_count) as successfulMessages,
                SUM(failed_count) as failedMessages,
                type
            FROM campaigns 
            WHERE user_id = ? 
            GROUP BY type
        `, [userId]);
        
        const overall = await db.queryOne(`
            SELECT 
                COUNT(*) as totalTasks,
                SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as runningTasks,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completedTasks,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failedTasks,
                SUM(CASE WHEN status = 'stopped' THEN 1 ELSE 0 END) as stoppedTasks,
                SUM(total_count) as totalMessages,
                SUM(success_count) as successfulMessages,
                SUM(failed_count) as failedMessages
            FROM campaigns 
            WHERE user_id = ?
        `, [userId]);
        
        res.json({
            overall: overall || {
                totalTasks: 0,
                runningTasks: 0,
                completedTasks: 0,
                failedTasks: 0,
                stoppedTasks: 0,
                totalMessages: 0,
                successfulMessages: 0,
                failedMessages: 0
            },
            byType: stats || []
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Stop all tasks
app.post('/api/tasks/stop-all', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const runningTasks = await db.query(
            'SELECT id FROM campaigns WHERE user_id = ? AND status IN ("running", "paused")',
            [userId]
        );
        
        let stoppedCount = 0;
        
        for (const task of runningTasks) {
            const activeCampaign = activeCampaigns.get(task.id);
            if (activeCampaign) {
                campaignControls.set(task.id, { shouldStop: true });
                activeCampaigns.delete(task.id);
                campaignControls.delete(task.id);
            }
            stoppedCount++;
        }
        
        await db.query(
            'UPDATE campaigns SET status = ?, completed_at = NOW() WHERE user_id = ? AND status IN ("running", "paused")',
            ['stopped', userId]
        );
        
        res.json({ success: true, message: `Stopped ${stoppedCount} tasks`, count: stoppedCount });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Analytics API
app.get('/api/analytics', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { range = 'all' } = req.query;
        
        // Get analytics from analytics table
        let dateFilter = '';
        if (range === 'today') {
            dateFilter = 'AND date = CURDATE()';
        } else if (range === 'week') {
            dateFilter = 'AND date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)';
        } else if (range === 'month') {
            dateFilter = 'AND date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)';
        }
        
        const analytics = await db.query(
            `SELECT 
                SUM(messages_sent) as totalMessages,
                SUM(messages_sent) as delivered,
                SUM(messages_failed) as failed,
                SUM(bot_responses) as botReplies,
                SUM(bulk_campaigns) as bulkCampaigns,
                SUM(group_broadcasts) as groupBroadcasts,
                SUM(contact_broadcasts) as contactBroadcasts,
                SUM(numbers_extracted) as numbersExtracted,
                SUM(groups_accessed) as groupsAccessed,
                SUM(contacts_accessed) as contactsAccessed
            FROM analytics WHERE user_id = ? ${dateFilter}`,
            [userId]
        );
        
        const result = analytics[0] || {};
        
        res.json({
            totalMessages: result.totalMessages || 0,
            delivered: result.delivered || 0,
            failed: result.failed || 0,
            botReplies: result.botReplies || 0,
            bulkCampaigns: result.bulkCampaigns || 0,
            groupBroadcasts: result.groupBroadcasts || 0,
            contactBroadcasts: result.contactBroadcasts || 0,
            numbersExtracted: result.numbersExtracted || 0,
            groupsAccessed: result.groupsAccessed || 0,
            contactsAccessed: result.contactsAccessed || 0
        });
    } catch (error) {
        console.error('Analytics error:', error);
        res.json({
            totalMessages: 0,
            delivered: 0,
            failed: 0,
            botReplies: 0,
            campaigns: 0
        });
    }
});

// CSV Bulk Sender
app.post('/api/csv-bulk-send', authMiddleware, subscriptionMiddleware, upload.fields([{ name: 'csvFile', maxCount: 1 }, { name: 'media', maxCount: 1 }]), async (req, res) => {
    try {
        const userId = req.user.id;
        const { messageType, delayType, fixedDelay, minDelay, maxDelay } = req.body;
        const clientData = whatsappClients.get(userId);
        
        if (!clientData || !clientData.isReady()) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }
        
        const csvFile = req.files?.csvFile?.[0];
        if (!csvFile) {
            return res.status(400).json({ error: 'CSV file required' });
        }
        
        const fs = require('fs');
        const csv = require('csv-parser');
        const contacts = [];
        
        // Parse CSV
        await new Promise((resolve, reject) => {
            fs.createReadStream(csvFile.path)
                .pipe(csv())
                .on('data', (row) => {
                    const phone = row.phone || row.number || row.Phone || row.Number;
                    const name = row.name || row.Name || '';
                    const message = row.message || row.Message || '';
                    
                    if (phone && phone.match(/^[+]?[0-9]{10,15}$/)) {
                        contacts.push({ name, phone: phone.replace(/[^+0-9]/g, ''), message });
                    }
                })
                .on('end', resolve)
                .on('error', reject);
        });
        
        fs.unlinkSync(csvFile.path); // Clean up
        
        if (contacts.length === 0) {
            return res.status(400).json({ error: 'No valid contacts found in CSV' });
        }
        
        // Create task
        const campaignId = `csv_bulk_${userId}_${Date.now()}`;
        await db.insert(
            'INSERT INTO campaigns (id, user_id, type, total_count, status, created_at, task_name, task_description) VALUES (?, ?, ?, ?, ?, NOW(), ?, ?)',
            [campaignId, userId, 'csv_bulk_sender', contacts.length, 'running', 'CSV Bulk Sender Campaign', `Sending personalized messages to ${contacts.length} contacts`]
        );
        
        const campaignData = { userId, type: 'csv_bulk_sender', total: contacts.length, processed: 0, success: 0, failed: 0, startTime: new Date(), status: 'running' };
        activeCampaigns.set(campaignId, campaignData);
        campaignControls.set(campaignId, { shouldStop: false });
        
        io.to(userId).emit('task-created', {
            id: campaignId,
            type: 'csv_bulk_sender',
            name: 'CSV Bulk Sender Campaign',
            total: contacts.length,
            status: 'running'
        });
        
        const results = [];
        const { MessageMedia } = require('whatsapp-web.js');
        let media = null;
        
        if (req.files?.media?.[0] && messageType !== 'text') {
            try {
                media = MessageMedia.fromFilePath(req.files.media[0].path);
            } catch (error) {
                return res.status(400).json({ error: 'Failed to load media file' });
            }
        }
        
        // Send messages
        for (let i = 0; i < contacts.length; i++) {
            const contact = contacts[i];
            
            // Check if campaign should stop
            const control = campaignControls.get(campaignId);
            if (control && control.shouldStop) {
                results.push({ phone: contact.phone, status: 'cancelled', error: 'Campaign stopped by user' });
                break;
            }
            
            try {
                const chatId = contact.phone.includes('@c.us') ? contact.phone : `${contact.phone}@c.us`;
                const personalizedMessage = contact.message || `Hello ${contact.name || contact.phone}!`;
                
                if (messageType === 'text' || !media) {
                    await clientData.client.sendMessage(chatId, personalizedMessage);
                } else {
                    await clientData.client.sendMessage(chatId, media, { caption: personalizedMessage });
                }
                
                results.push({ phone: contact.phone, name: contact.name, status: 'sent' });
                
                // Update campaign progress
                const campaign = activeCampaigns.get(campaignId);
                if (campaign) {
                    campaign.processed = i + 1;
                    campaign.success++;
                    await db.query('UPDATE campaigns SET success_count = ?, processed_count = ? WHERE id = ?', 
                        [campaign.success, campaign.processed, campaignId]);
                }
                
                io.to(userId).emit('csv-bulk-progress', {
                    campaignId,
                    current: i + 1,
                    total: contacts.length,
                    contact: contact.name || contact.phone,
                    status: 'sent'
                });
                
                io.to(userId).emit('task-progress', {
                    id: campaignId,
                    processed: i + 1,
                    total: contacts.length,
                    status: 'running'
                });
                
            } catch (error) {
                results.push({ phone: contact.phone, name: contact.name, status: 'failed', error: error.message });
                
                const campaign = activeCampaigns.get(campaignId);
                if (campaign) {
                    campaign.processed = i + 1;
                    campaign.failed++;
                    await db.query('UPDATE campaigns SET failed_count = ?, processed_count = ? WHERE id = ?', 
                        [campaign.failed, campaign.processed, campaignId]);
                }
            }
            
            // Add delay
            if (i < contacts.length - 1) {
                let delay = 3000;
                if (delayType === 'fixed' && fixedDelay) {
                    delay = Math.max(parseInt(fixedDelay) * 1000, 3000);
                } else if (delayType === 'random' && minDelay && maxDelay) {
                    const min = Math.max(parseInt(minDelay), 3);
                    const max = Math.max(parseInt(maxDelay), min + 1);
                    delay = (Math.random() * (max - min) + min) * 1000;
                }
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
        
        // Mark campaign as completed
        const finalStatus = campaignControls.get(campaignId)?.shouldStop ? 'stopped' : 'completed';
        await db.query('UPDATE campaigns SET status = ?, completed_at = NOW() WHERE id = ?', [finalStatus, campaignId]);
        activeCampaigns.delete(campaignId);
        campaignControls.delete(campaignId);
        
        io.to(userId).emit('task-completed', {
            id: campaignId,
            status: finalStatus,
            results: results.length
        });
        
        res.json({ success: true, results, campaignId });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Message Templates APIs
app.get('/api/templates', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const templates = await db.query(
            'SELECT * FROM message_templates WHERE user_id = ? ORDER BY created_at DESC',
            [userId]
        );
        res.json(templates);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/templates', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { name, content, category, variables } = req.body;
        
        const templateId = await db.insert(
            'INSERT INTO message_templates (user_id, name, content, category, variables) VALUES (?, ?, ?, ?, ?)',
            [userId, name, content, category || 'general', JSON.stringify(variables || [])]
        );
        
        res.json({ success: true, templateId, message: 'Template created successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/templates/:id', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { id } = req.params;
        const { name, content, category, variables } = req.body;
        
        await db.query(
            'UPDATE message_templates SET name = ?, content = ?, category = ?, variables = ? WHERE id = ? AND user_id = ?',
            [name, content, category || 'general', JSON.stringify(variables || []), id, userId]
        );
        
        res.json({ success: true, message: 'Template updated successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/templates/:id', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { id } = req.params;
        
        await db.query('DELETE FROM message_templates WHERE id = ? AND user_id = ?', [id, userId]);
        res.json({ success: true, message: 'Template deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Socket.io authentication (optional for now)
io.use((socket, next) => {
    const token = socket.handshake.auth?.token || socket.handshake.query?.token;
    
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET, {
                algorithms: ['HS256']
            });
            
            if (decoded.id && typeof decoded.id === 'number') {
                socket.userId = decoded.id;
                socket.userEmail = decoded.email;
            }
        } catch (error) {
            console.log('Socket auth failed:', error.message);
        }
    }
    
    next(); // Allow connection even without auth for now
});

io.on('connection', (socket) => {
    console.log('Socket client connected:', socket.id, 'User:', socket.userId || 'anonymous');
    
    socket.on('join', (userId) => {
        // Validate userId is a number and user exists
        if (!userId || isNaN(userId)) {
            socket.emit('error', { message: 'Invalid user ID' });
            return;
        }
        
        console.log('User joined room:', userId);
        socket.join(userId.toString());
        socket.emit('joined', { userId, socketId: socket.id });
    });
    
    socket.on('disconnect', (reason) => {
        console.log('Socket client disconnected:', socket.id, 'Reason:', reason);
    });
});

// Initialize database and start server
async function startServer() {
    try {
        await initializeDatabase();
        console.log('Database initialized successfully');
        
        server.listen(PORT, () => {
            console.log(`WhatsApp Bot Pro running on port ${PORT}`);
            console.log(`Open http://localhost:${PORT} in your browser`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Handle unhandled promise rejections and exceptions
process.on('unhandledRejection', (reason, promise) => {
    // Ignore common Puppeteer/WhatsApp errors
    if (reason && reason.message && (
        reason.message.includes('Protocol error') ||
        reason.message.includes('Target closed') ||
        reason.message.includes('Navigation failed') ||
        reason.message.includes('browser has disconnected') ||
        reason.message.includes('ECONNRESET') ||
        reason.message.includes('ECONNREFUSED') ||
        reason.message.includes('ETIMEDOUT') ||
        reason.message.includes('socket hang up')
    )) {
        return; // Silently ignore these errors
    }
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
    // Don't exit the process for network/browser errors
    if (error.message.includes('ECONNRESET') || 
        error.message.includes('ECONNREFUSED') ||
        error.message.includes('ETIMEDOUT') ||
        error.message.includes('net::') ||
        error.message.includes('socket hang up') ||
        error.message.includes('Protocol error') ||
        error.message.includes('Target closed') ||
        error.message.includes('Navigation failed') ||
        error.message.includes('browser has disconnected')) {
        return; // Silently ignore these errors
    }
    console.error('Uncaught Exception:', error);
    process.exit(1);
});

startServer();