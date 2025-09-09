// Test Analytics Endpoint
const express = require('express');
const { initializeDatabase, db } = require('./database');

async function testAnalytics() {
    try {
        await initializeDatabase();
        console.log('Database initialized');
        
        // Test the analytics query directly
        const userId = 1;
        const analytics = await db.query(`
            SELECT 
                COALESCE(SUM(messages_sent), 0) as totalMessages,
                COALESCE(SUM(messages_sent), 0) as delivered,
                COALESCE(SUM(messages_failed), 0) as failed,
                COALESCE(SUM(bot_responses), 0) as botReplies,
                COALESCE(SUM(bulk_campaigns), 0) as bulkCampaigns,
                COALESCE(SUM(group_broadcasts), 0) as groupBroadcasts,
                COALESCE(SUM(contact_broadcasts), 0) as contactBroadcasts,
                COALESCE(SUM(numbers_extracted), 0) as numbersExtracted,
                COALESCE(SUM(groups_accessed), 0) as groupsAccessed,
                COALESCE(SUM(contacts_accessed), 0) as contactsAccessed
            FROM analytics WHERE user_id = ?
        `, [userId]);
        
        const result = analytics[0] || {};
        console.log('Raw analytics result:', result);
        
        const response = {
            totalMessages: parseInt(result.totalMessages) || 0,
            delivered: parseInt(result.delivered) || 0,
            failed: parseInt(result.failed) || 0,
            botReplies: parseInt(result.botReplies) || 0,
            bulkCampaigns: parseInt(result.bulkCampaigns) || 0,
            groupBroadcasts: parseInt(result.groupBroadcasts) || 0,
            contactBroadcasts: parseInt(result.contactBroadcasts) || 0,
            numbersExtracted: parseInt(result.numbersExtracted) || 0,
            groupsAccessed: parseInt(result.groupsAccessed) || 0,
            contactsAccessed: parseInt(result.contactsAccessed) || 0
        };
        
        console.log('Formatted analytics response:', response);
        console.log('Analytics test completed successfully!');
        
        process.exit(0);
    } catch (error) {
        console.error('Analytics test error:', error);
        process.exit(1);
    }
}

testAnalytics();