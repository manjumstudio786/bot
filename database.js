const mysql = require('mysql2/promise');
require('dotenv').config();

// Database connection configuration
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'whatsapp_bot_pro',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

// Create connection pool
const pool = mysql.createPool(dbConfig);

// Initialize database and create tables
async function initializeDatabase() {
    try {
        // Create database if it doesn't exist
        const connection = await mysql.createConnection({
            host: dbConfig.host,
            user: dbConfig.user,
            password: dbConfig.password,
            port: dbConfig.port
        });
        
        await connection.execute(`CREATE DATABASE IF NOT EXISTS ${dbConfig.database}`);
        await connection.end();
        
        console.log('Database created/verified successfully');
        
        // Create tables
        await createTables();
        
        // Add subscription columns if they don't exist
        await addSubscriptionColumns();
        
        // Add analytics columns if they don't exist
        await addAnalyticsColumns();
        
        // Add contact tracking columns if they don't exist
        await addContactColumns();
        
        // Update campaigns table structure
        await updateCampaignsTable();
        
        // Create task details table
        await createTaskDetailsTable();
        
        // Update task details table structure
        await updateTaskDetailsTable();
        
    } catch (error) {
        console.error('Database initialization error:', error);
        throw error;
    }
}

// Create all required tables
async function createTables() {
    const tables = [
        // Users table
        `CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            whatsapp_number VARCHAR(50) NULL,
            subscription_type ENUM('trial', 'premium', 'expired') DEFAULT 'trial',
            subscription_expires TIMESTAMP NULL,
            is_active BOOLEAN DEFAULT true,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )`,
        
        // WhatsApp numbers table (to track used numbers)
        `CREATE TABLE IF NOT EXISTS whatsapp_numbers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            phone_number VARCHAR(50) UNIQUE NOT NULL,
            first_user_id INT NOT NULL,
            trial_used BOOLEAN DEFAULT false,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (first_user_id) REFERENCES users(id) ON DELETE CASCADE
        )`,
        
        // WhatsApp sessions table
        `CREATE TABLE IF NOT EXISTS whatsapp_sessions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            session_id VARCHAR(255) UNIQUE NOT NULL,
            is_active BOOLEAN DEFAULT false,
            last_connected TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`,
        
        // Bot rules table
        `CREATE TABLE IF NOT EXISTS bot_rules (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            rule_type ENUM('exact', 'keyword') NOT NULL,
            question TEXT,
            keywords JSON,
            answer TEXT NOT NULL,
            is_enabled BOOLEAN DEFAULT true,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`,
        
        // Message logs table
        `CREATE TABLE IF NOT EXISTS message_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            message_type ENUM('single', 'bulk', 'bot_response') NOT NULL,
            recipient VARCHAR(50) NOT NULL,
            message TEXT NOT NULL,
            status ENUM('sent', 'failed', 'pending') DEFAULT 'pending',
            error_message TEXT NULL,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`,
        
        // Contacts table
        `CREATE TABLE IF NOT EXISTS contacts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            name VARCHAR(255),
            phone_number VARCHAR(50) NOT NULL,
            is_group BOOLEAN DEFAULT false,
            group_id VARCHAR(255) NULL,
            participant_count INT DEFAULT 0,
            last_message_at TIMESTAMP NULL,
            response_count INT DEFAULT 0,
            message_count INT DEFAULT 0,
            status ENUM('active', 'blocked', 'inactive') DEFAULT 'active',
            tags JSON NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE KEY unique_user_phone (user_id, phone_number)
        )`,
        
        // Analytics table
        `CREATE TABLE IF NOT EXISTS analytics (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            date DATE NOT NULL,
            messages_sent INT DEFAULT 0,
            messages_failed INT DEFAULT 0,
            bot_responses INT DEFAULT 0,
            bulk_campaigns INT DEFAULT 0,
            group_broadcasts INT DEFAULT 0,
            contact_broadcasts INT DEFAULT 0,
            numbers_extracted INT DEFAULT 0,
            groups_accessed INT DEFAULT 0,
            contacts_accessed INT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_user_date (user_id, date),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`,
        
        // Campaigns table
        `CREATE TABLE IF NOT EXISTS campaigns (
            id VARCHAR(255) PRIMARY KEY,
            user_id INT NOT NULL,
            type ENUM('bulk_messages', 'csv_bulk_sender', 'group_broadcast', 'contact_broadcast', 'group_adder', 'single_message', 'message_scheduler', 'auto_chat_bot') NOT NULL,
            task_name VARCHAR(255) NULL,
            task_description TEXT NULL,
            total_count INT NOT NULL,
            processed_count INT DEFAULT 0,
            success_count INT DEFAULT 0,
            failed_count INT DEFAULT 0,
            status ENUM('running', 'paused', 'completed', 'failed', 'stopped') DEFAULT 'running',
            message_content TEXT NULL,
            media_path VARCHAR(500) NULL,
            delay_settings JSON NULL,
            target_data JSON NULL,
            error_details JSON NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`,
        
        // Task details table for comprehensive tracking
        `CREATE TABLE IF NOT EXISTS task_details (
            id INT AUTO_INCREMENT PRIMARY KEY,
            task_id VARCHAR(255) NOT NULL,
            campaign_id VARCHAR(255) NULL,
            user_id INT NOT NULL,
            recipient VARCHAR(100) NOT NULL,
            target_number VARCHAR(50) NULL,
            target_name VARCHAR(255) NULL,
            message_content TEXT NULL,
            status ENUM('pending', 'sent', 'failed', 'skipped', 'cancelled') DEFAULT 'pending',
            error_message TEXT NULL,
            attempt_count INT DEFAULT 0,
            attempt_number INT DEFAULT 1,
            processed_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_task_id (task_id),
            INDEX idx_campaign_id (campaign_id),
            INDEX idx_user_task (user_id, task_id)
        )`,
        
        // Message templates table
        `CREATE TABLE IF NOT EXISTS message_templates (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            name VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            category VARCHAR(100) DEFAULT 'general',
            variables JSON NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`,
        
        // Message queue table
        `CREATE TABLE IF NOT EXISTS message_queue (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            recipient VARCHAR(50) NOT NULL,
            message TEXT NOT NULL,
            message_type ENUM('text', 'image', 'video', 'audio', 'document') DEFAULT 'text',
            media_path VARCHAR(500) NULL,
            scheduled_at TIMESTAMP NOT NULL,
            status ENUM('pending', 'sent', 'failed') DEFAULT 'pending',
            attempts INT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            sent_at TIMESTAMP NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`,
        
        // Contact groups table
        `CREATE TABLE IF NOT EXISTS contact_groups (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            name VARCHAR(100) NOT NULL,
            description TEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`,
        
        // Contact group members table
        `CREATE TABLE IF NOT EXISTS contact_group_members (
            id INT AUTO_INCREMENT PRIMARY KEY,
            group_id INT NOT NULL,
            contact_id INT NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (group_id) REFERENCES contact_groups(id) ON DELETE CASCADE,
            FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE,
            UNIQUE KEY unique_group_contact (group_id, contact_id)
        )`,
        
        // Auto-add settings table
        `CREATE TABLE IF NOT EXISTS auto_add_settings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            is_enabled BOOLEAN DEFAULT false,
            keywords JSON NOT NULL DEFAULT '[]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE KEY unique_user (user_id)
        )`
    ];
    
    for (const table of tables) {
        await pool.execute(table);
    }
    
    console.log('All database tables created/verified successfully');
}

// Add subscription columns to existing users table
async function addSubscriptionColumns() {
    try {
        // Check if columns exist first
        const [columns] = await pool.execute('SHOW COLUMNS FROM users LIKE \'subscription_type\'');
        
        if (columns.length === 0) {
            await pool.execute('ALTER TABLE users ADD COLUMN whatsapp_number VARCHAR(50) NULL');
            await pool.execute('ALTER TABLE users ADD COLUMN subscription_type ENUM(\'trial\', \'premium\', \'expired\') DEFAULT \'trial\'');
            await pool.execute('ALTER TABLE users ADD COLUMN subscription_expires TIMESTAMP NULL');
            console.log('Subscription columns added successfully');
        } else {
            console.log('Subscription columns already exist');
        }
    } catch (error) {
        console.error('Error adding subscription columns:', error.message);
    }
}

// Add analytics columns to existing analytics table
async function addAnalyticsColumns() {
    try {
        const [columns] = await pool.execute('SHOW COLUMNS FROM analytics LIKE \'group_broadcasts\'');
        
        if (columns.length === 0) {
            await pool.execute('ALTER TABLE analytics ADD COLUMN group_broadcasts INT DEFAULT 0');
            await pool.execute('ALTER TABLE analytics ADD COLUMN contact_broadcasts INT DEFAULT 0');
            await pool.execute('ALTER TABLE analytics ADD COLUMN numbers_extracted INT DEFAULT 0');
            await pool.execute('ALTER TABLE analytics ADD COLUMN groups_accessed INT DEFAULT 0');
            await pool.execute('ALTER TABLE analytics ADD COLUMN contacts_accessed INT DEFAULT 0');
            console.log('Analytics columns added successfully');
        } else {
            console.log('Analytics columns already exist');
        }
    } catch (error) {
        console.error('Error adding analytics columns:', error.message);
    }
}

// Add contact tracking columns to existing contacts table
async function addContactColumns() {
    try {
        const [columns] = await pool.execute('SHOW COLUMNS FROM contacts LIKE \'last_message_at\'');
        
        if (columns.length === 0) {
            await pool.execute('ALTER TABLE contacts ADD COLUMN last_message_at TIMESTAMP NULL');
            await pool.execute('ALTER TABLE contacts ADD COLUMN response_count INT DEFAULT 0');
            await pool.execute('ALTER TABLE contacts ADD COLUMN message_count INT DEFAULT 0');
            await pool.execute('ALTER TABLE contacts ADD COLUMN status ENUM(\'active\', \'blocked\', \'inactive\') DEFAULT \'active\'');
            await pool.execute('ALTER TABLE contacts ADD COLUMN tags JSON NULL');
            await pool.execute('ALTER TABLE contacts ADD UNIQUE KEY unique_user_phone (user_id, phone_number)');
            console.log('Contact tracking columns added successfully');
        } else {
            console.log('Contact tracking columns already exist');
        }
    } catch (error) {
        console.error('Error adding contact columns:', error.message);
    }
}

// Update campaigns table structure
async function updateCampaignsTable() {
    try {
        const [taskNameColumns] = await pool.execute('SHOW COLUMNS FROM campaigns LIKE \'task_name\'');
        
        if (taskNameColumns.length === 0) {
            await pool.execute('ALTER TABLE campaigns ADD COLUMN task_name VARCHAR(255) NULL');
            await pool.execute('ALTER TABLE campaigns ADD COLUMN task_description TEXT NULL');
            console.log('Campaign task columns added successfully');
        }
        
        // Add new detailed tracking columns
        const [messageContentColumns] = await pool.execute('SHOW COLUMNS FROM campaigns LIKE \'message_content\'');
        if (messageContentColumns.length === 0) {
            await pool.execute('ALTER TABLE campaigns ADD COLUMN message_content TEXT NULL');
            await pool.execute('ALTER TABLE campaigns ADD COLUMN media_path VARCHAR(500) NULL');
            await pool.execute('ALTER TABLE campaigns ADD COLUMN delay_settings JSON NULL');
            await pool.execute('ALTER TABLE campaigns ADD COLUMN target_data JSON NULL');
            await pool.execute('ALTER TABLE campaigns ADD COLUMN error_details JSON NULL');
            console.log('Campaign detail columns added successfully');
        }
        
        await pool.execute(`ALTER TABLE campaigns MODIFY COLUMN type ENUM('bulk_messages', 'csv_bulk_sender', 'group_broadcast', 'contact_broadcast', 'group_adder', 'single_message', 'message_scheduler', 'auto_chat_bot', 'bulk') NOT NULL`);
        await pool.execute(`ALTER TABLE campaigns MODIFY COLUMN status ENUM('running', 'paused', 'completed', 'failed', 'stopped') DEFAULT 'running'`);
        
        console.log('Campaigns table updated successfully');
    } catch (error) {
        console.error('Error updating campaigns table:', error.message);
    }
}

// Create task details table
async function createTaskDetailsTable() {
    try {
        const [tables] = await pool.execute('SHOW TABLES LIKE \'task_details\'');
        
        if (tables.length === 0) {
            await pool.execute(`
                CREATE TABLE task_details (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    task_id VARCHAR(255) NOT NULL,
                    campaign_id VARCHAR(255) NULL,
                    user_id INT NOT NULL,
                    recipient VARCHAR(100) NOT NULL,
                    target_number VARCHAR(50) NULL,
                    target_name VARCHAR(255) NULL,
                    message_content TEXT NULL,
                    status ENUM('pending', 'sent', 'failed', 'skipped', 'cancelled') DEFAULT 'pending',
                    error_message TEXT NULL,
                    attempt_count INT DEFAULT 0,
                    attempt_number INT DEFAULT 1,
                    processed_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    INDEX idx_task_id (task_id),
                    INDEX idx_campaign_id (campaign_id),
                    INDEX idx_user_task (user_id, task_id)
                )
            `);
            console.log('Task details table created successfully');
        } else {
            console.log('Task details table already exists');
        }
    } catch (error) {
        console.error('Error creating task details table:', error.message);
    }
}

// Update task details table structure
async function updateTaskDetailsTable() {
    try {
        // Check if task_id column exists
        const [taskIdColumns] = await pool.execute('SHOW COLUMNS FROM task_details LIKE \'task_id\'');
        
        if (taskIdColumns.length === 0) {
            // Add task_id column if it doesn't exist
            await pool.execute('ALTER TABLE task_details ADD COLUMN task_id VARCHAR(255) NOT NULL AFTER id');
            await pool.execute('ALTER TABLE task_details ADD INDEX idx_task_id (task_id)');
            console.log('task_id column added to task_details table');
        }
        
        // Check if recipient column exists
        const [recipientColumns] = await pool.execute('SHOW COLUMNS FROM task_details LIKE \'recipient\'');
        
        if (recipientColumns.length === 0) {
            await pool.execute('ALTER TABLE task_details ADD COLUMN recipient VARCHAR(100) NOT NULL AFTER user_id');
            console.log('recipient column added to task_details table');
        }
        
        // Update status enum to include all values
        await pool.execute('ALTER TABLE task_details MODIFY COLUMN status ENUM(\'pending\', \'sent\', \'failed\', \'skipped\', \'cancelled\') DEFAULT \'pending\'');
        
        console.log('Task details table structure updated successfully');
    } catch (error) {
        console.error('Error updating task details table:', error.message);
    }
}

// Enhanced database helper functions with security
const db = {
    // Execute query with retry logic and validation
    async query(sql, params = []) {
        // Basic SQL injection prevention (less restrictive)
        const dangerousPatterns = [
            /\b(DROP|TRUNCATE|ALTER|GRANT|REVOKE)\b/i,
            /--.*$/m,
            /\/\*.*?\*\//g,
            /;\s*(DROP|DELETE|UPDATE|INSERT)\b/i
        ];
        
        // Allow most common operations
        const allowedPatterns = [
            /^SELECT\b/i,
            /^INSERT\b/i,
            /^UPDATE\b/i,
            /^DELETE\b/i,
            /^SHOW\b/i,
            /^DESCRIBE\b/i
        ];
        
        const isAllowed = allowedPatterns.some(pattern => pattern.test(sql.trim()));
        const isDangerous = dangerousPatterns.some(pattern => pattern.test(sql));
        
        if (isDangerous && !isAllowed) {
            console.warn('Potentially dangerous SQL operation blocked:', sql.substring(0, 100));
            throw new Error('Potentially dangerous SQL operation blocked');
        }
        
        // Validate parameters
        if (params && params.length > 50) {
            throw new Error('Too many parameters');
        }
        
        for (const param of params) {
            if (typeof param === 'string' && param.length > 10000) {
                throw new Error('Parameter too long');
            }
        }
        
        let retries = 3;
        while (retries > 0) {
            try {
                const [rows] = await pool.execute(sql, params);
                return rows;
            } catch (error) {
                if ((error.code === 'ECONNRESET' || 
                     error.code === 'PROTOCOL_CONNECTION_LOST' ||
                     error.code === 'ECONNREFUSED') && retries > 1) {
                    console.log(`Database connection error, retrying... (${retries - 1} attempts left)`);
                    retries--;
                    await new Promise(resolve => setTimeout(resolve, 1000));
                    continue;
                }
                console.error('Database query error:', error.message);
                throw error;
            }
        }
    },
    
    // Get single row
    async queryOne(sql, params = []) {
        const rows = await this.query(sql, params);
        return rows[0] || null;
    },
    
    // Insert and return ID with validation
    async insert(sql, params = []) {
        // Validate it's actually an INSERT or INSERT IGNORE
        if (!/^INSERT\b/i.test(sql.trim())) {
            throw new Error('Only INSERT operations allowed');
        }
        
        try {
            const [result] = await pool.execute(sql, params);
            return result.insertId;
        } catch (error) {
            console.error('Database insert error:', error.message);
            throw error;
        }
    },
    
    // Update analytics
    async updateAnalytics(userId, type) {
        const today = new Date().toISOString().split('T')[0];
        const fields = {
            'message': 'messages_sent',
            'failed': 'messages_failed', 
            'bot': 'bot_responses',
            'bulk': 'bulk_campaigns',
            'group_broadcast': 'group_broadcasts',
            'contact_broadcast': 'contact_broadcasts',
            'extract': 'numbers_extracted',
            'groups': 'groups_accessed',
            'contacts': 'contacts_accessed'
        };
        
        const field = fields[type] || 'messages_sent';
        
        await this.query(`
            INSERT INTO analytics (user_id, date, ${field}) 
            VALUES (?, ?, 1)
            ON DUPLICATE KEY UPDATE ${field} = ${field} + 1
        `, [userId, today]);
    }
};

module.exports = { initializeDatabase, db };