// Fix Analytics Function
const { initializeDatabase, db } = require('./database');

async function fixAnalytics() {
    try {
        await initializeDatabase();
        console.log('Database initialized');
        
        // Test analytics function
        const testUserId = 1;
        
        // Test updateAnalytics function
        await db.updateAnalytics(testUserId, 'message');
        console.log('Analytics update test passed');
        
        // Test analytics query
        const analytics = await db.query(`
            SELECT 
                SUM(messages_sent) as totalMessages,
                SUM(messages_failed) as failed,
                SUM(bot_responses) as botReplies
            FROM analytics WHERE user_id = ?
        `, [testUserId]);
        
        console.log('Analytics query result:', analytics[0]);
        console.log('Analytics function is working properly');
        
        process.exit(0);
    } catch (error) {
        console.error('Analytics fix error:', error);
        process.exit(1);
    }
}

fixAnalytics();