// Security Middleware
const validator = require('validator');
const securityConfig = require('./security-config');

// Input sanitization
function sanitizeInput(input) {
    if (typeof input === 'string') {
        return validator.escape(input.trim());
    }
    return input;
}

// Input validation
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

// Password validation
function validatePassword(password) {
    const config = securityConfig.password;
    const errors = [];
    
    if (password.length < config.minLength) {
        errors.push(`Password must be at least ${config.minLength} characters`);
    }
    
    if (password.length > config.maxLength) {
        errors.push(`Password must be less than ${config.maxLength} characters`);
    }
    
    if (config.requireUppercase && !/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }
    
    if (config.requireLowercase && !/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }
    
    if (config.requireNumbers && !/\\d/.test(password)) {
        errors.push('Password must contain at least one number');
    }
    
    if (config.requireSpecialChars && !/[!@#$%^&*(),.?\":{}|<>]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }
    
    return errors;
}

// Phone number validation
function validatePhoneNumber(phone) {
    const cleanPhone = phone.toString().replace(/[^0-9+]/g, '');
    return securityConfig.validation.phoneNumberPattern.test(cleanPhone);
}

// File validation
function validateFile(file) {
    const config = securityConfig.upload;
    const errors = [];
    
    if (file.size > config.maxFileSize) {
        errors.push(`File size must be less than ${config.maxFileSize / (1024 * 1024)}MB`);
    }
    
    if (!config.allowedMimeTypes[file.mimetype]) {
        errors.push(`File type ${file.mimetype} is not allowed`);
    }
    
    const expectedExt = config.allowedMimeTypes[file.mimetype];
    const actualExt = require('path').extname(file.originalname).toLowerCase();
    
    if (expectedExt && expectedExt !== actualExt) {
        errors.push('File extension does not match MIME type');
    }
    
    return errors;
}

// SQL injection prevention
function validateSqlQuery(sql) {
    const dangerousPatterns = [
        /\\b(DROP|DELETE|TRUNCATE|ALTER|CREATE|GRANT|REVOKE)\\b/i,
        /--/,
        /\\/\\*/,
        /\\*\\//,
        /;.*\\w/
    ];
    
    const allowedPatterns = [
        /^SELECT\\b/i,
        /^INSERT\\b/i,
        /^UPDATE\\b/i,
        /^DELETE FROM (users|campaigns|message_logs|contacts|analytics|bot_rules|whatsapp_sessions|whatsapp_numbers|message_queue|contact_groups|contact_group_members|task_details|message_templates)\\b/i
    ];
    
    const isAllowed = allowedPatterns.some(pattern => pattern.test(sql.trim()));
    const isDangerous = dangerousPatterns.some(pattern => pattern.test(sql));
    
    return !(isDangerous && !isAllowed);
}

// XSS prevention
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// CSRF token generation
function generateCsrfToken() {
    return require('crypto').randomBytes(32).toString('hex');
}

// Rate limiting helper
function createRateLimiter(windowMs, max, message) {
    const attempts = new Map();
    
    return (req, res, next) => {
        const key = req.ip || req.connection.remoteAddress;
        const now = Date.now();
        const windowStart = now - windowMs;
        
        // Clean old entries
        for (const [ip, data] of attempts.entries()) {
            if (data.resetTime < now) {
                attempts.delete(ip);
            }
        }
        
        const current = attempts.get(key) || { count: 0, resetTime: now + windowMs };
        
        if (current.count >= max) {
            return res.status(429).json({ error: message || 'Too many requests' });
        }
        
        current.count++;
        attempts.set(key, current);
        next();
    };
}

module.exports = {
    sanitizeInput,
    validateInput,
    validatePassword,
    validatePhoneNumber,
    validateFile,
    validateSqlQuery,
    escapeHtml,
    generateCsrfToken,
    createRateLimiter
};