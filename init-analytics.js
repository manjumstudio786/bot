const { initializeDatabase, db } = require('./database');

async function initializeAnalytics() {
    try {
        await initializeDatabase();
        
        // Add some sample analytics data for testing
        const users = await db.query('SELECT id FROM users');
        
        for (const user of users) {
            const today = new Date().toISOString().split('T')[0];
            
            // Check if analytics entry exists for today
            const existing = await db.queryOne(
                'SELECT id FROM analytics WHERE user_id = ? AND date = ?',
                [user.id, today]
            );
            
            if (!existing) {
                await db.insert(
                    'INSERT INTO analytics (user_id, date, messages_sent, messages_failed, bot_responses, bulk_campaigns) VALUES (?, ?, ?, ?, ?, ?)',
                    [user.id, today, 0, 0, 0, 0]
                );
            }
        }
        
        console.log('Analytics initialized successfully');
        process.exit(0);
    } catch (error) {
        console.error('Failed to initialize analytics:', error);
        process.exit(1);
    }
}

initializeAnalytics();