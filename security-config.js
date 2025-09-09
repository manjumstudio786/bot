// Security Configuration
const crypto = require('crypto');

const securityConfig = {
    // JWT Configuration
    jwt: {
        algorithm: 'HS256',
        expiresIn: '7d',
        issuer: 'whatsapp-bot-pro',
        audience: 'whatsapp-bot-users'
    },
    
    // Password Policy
    password: {
        minLength: 8,
        maxLength: 128,
        requireUppercase: true,
        requireLowercase: true,
        requireNumbers: true,
        requireSpecialChars: false
    },
    
    // Rate Limiting
    rateLimits: {
        login: {
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 5 // 5 attempts per window
        },
        general: {
            windowMs: 15 * 60 * 1000,
            max: 100 // 100 requests per window
        },
        upload: {
            windowMs: 60 * 60 * 1000, // 1 hour
            max: 20 // 20 uploads per hour
        }
    },
    
    // File Upload Security
    upload: {
        maxFileSize: 10 * 1024 * 1024, // 10MB
        maxFiles: 1,
        allowedMimeTypes: {
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
        },
        uploadDir: 'uploads',
        generateSecureFilename: () => {
            return crypto.randomBytes(16).toString('hex');
        }
    },
    
    // Input Validation
    validation: {
        maxMessageLength: 4096,
        maxRecipientsPerBulk: 1000,
        maxUsernameLength: 50,
        maxEmailLength: 255,
        phoneNumberPattern: /^[+]?[0-9]{10,15}$/,
        usernamePattern: /^[a-zA-Z0-9_-]+$/
    },
    
    // Security Headers
    headers: {
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                scriptSrc: ["'self'"],
                imgSrc: ["'self'", "data:", "blob:"],
                connectSrc: ["'self'", "ws:", "wss:"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"]
            }
        }
    },
    
    // Database Security
    database: {
        maxQueryParams: 50,
        maxParamLength: 10000,
        allowedTables: [
            'users', 'campaigns', 'message_logs', 'contacts', 
            'analytics', 'bot_rules', 'whatsapp_sessions', 
            'whatsapp_numbers', 'message_queue', 'contact_groups', 
            'contact_group_members', 'task_details', 'message_templates'
        ]
    },
    
    // Session Security
    session: {
        maxLoginAttempts: 5,
        lockoutDuration: 15 * 60 * 1000, // 15 minutes
        sessionTimeout: 7 * 24 * 60 * 60 * 1000 // 7 days
    }
};

module.exports = securityConfig;