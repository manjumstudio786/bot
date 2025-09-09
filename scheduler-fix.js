// Message Scheduler Fix
// This file contains the corrected implementation for the message scheduler

// 1. Enhanced Queue Processor (to replace the existing one in server.js)
const enhancedQueueProcessor = `
// Enhanced Message queue processor with better error handling
setInterval(async () => {
    try {
        const now = new Date();
        const pendingMessages = await db.query(
            'SELECT * FROM message_queue WHERE status = "pending" AND scheduled_at <= ? AND attempts < 3 ORDER BY scheduled_at ASC LIMIT 10',
            [now]
        );
        
        console.log(\`Processing \${pendingMessages.length} scheduled messages...\`);
        
        for (const msg of pendingMessages) {
            const clientData = whatsappClients.get(msg.user_id);
            
            if (clientData && clientData.isReady()) {
                try {
                    let messageToSend = msg.message;
                    
                    // Update attempts first
                    await db.query(
                        'UPDATE message_queue SET attempts = attempts + 1 WHERE id = ?',
                        [msg.id]
                    );
                    
                    if (msg.media_path && require('fs').existsSync(msg.media_path)) {
                        const { MessageMedia } = require('whatsapp-web.js');
                        const media = MessageMedia.fromFilePath(msg.media_path);
                        await clientData.client.sendMessage(msg.recipient, media, { caption: msg.message });
                    } else {
                        await clientData.client.sendMessage(msg.recipient, messageToSend);
                    }
                    
                    // Mark as sent
                    await db.query(
                        'UPDATE message_queue SET status = "sent", sent_at = NOW() WHERE id = ?',
                        [msg.id]
                    );
                    
                    // Update campaign status
                    await db.query(
                        'UPDATE campaigns SET status = "completed", completed_at = NOW(), processed_count = 1, success_count = 1 WHERE user_id = ? AND type = "message_scheduler" AND status = "running" ORDER BY created_at DESC LIMIT 1',
                        [msg.user_id]
                    );
                    
                    // Log success
                    await db.insert(
                        'INSERT INTO message_logs (user_id, message_type, recipient, message, status) VALUES (?, ?, ?, ?, ?)',
                        [msg.user_id, 'scheduled', msg.recipient, msg.message, 'sent']
                    );
                    
                    console.log(\`Scheduled message sent to \${msg.recipient}\`);
                    
                } catch (error) {
                    console.error(\`Error sending scheduled message to \${msg.recipient}:\`, error.message);
                    
                    if (msg.attempts >= 2) {
                        await db.query(
                            'UPDATE message_queue SET status = "failed" WHERE id = ?',
                            [msg.id]
                        );
                        
                        // Update campaign status to failed
                        await db.query(
                            'UPDATE campaigns SET status = "failed", completed_at = NOW(), processed_count = 1, failed_count = 1 WHERE user_id = ? AND type = "message_scheduler" AND status = "running" ORDER BY created_at DESC LIMIT 1',
                            [msg.user_id]
                        );
                        
                        // Log failure
                        await db.insert(
                            'INSERT INTO message_logs (user_id, message_type, recipient, message, status, error_message) VALUES (?, ?, ?, ?, ?, ?)',
                            [msg.user_id, 'scheduled', msg.recipient, msg.message, 'failed', error.message]
                        );
                    }
                }
            } else {
                console.log(\`WhatsApp not ready for user \${msg.user_id}, skipping scheduled message\`);
                
                // If WhatsApp not connected after 3 attempts, mark as failed
                if (msg.attempts >= 2) {
                    await db.query(
                        'UPDATE message_queue SET status = "failed" WHERE id = ?',
                        [msg.id]
                    );
                }
            }
        }
    } catch (error) {
        console.error('Queue processor error:', error);
    }
}, 30000); // Check every 30 seconds
`;

// 2. Enhanced Frontend Scheduler Functions
const enhancedSchedulerFunctions = \`
function getSchedulerContent() {
    return \\\`
        <div class="card">
            <div class="card-header">
                <h3>⏰ Message Scheduler</h3>
                <button class="btn btn-primary" onclick="showScheduleModal()">
                    <i class="fas fa-plus"></i> Schedule Message
                </button>
            </div>
            <div class="card-body">
                <div class="scheduler-stats" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem;">
                    <div class="stat-card">
                        <div class="stat-icon">
                            <i class="fas fa-clock"></i>
                        </div>
                        <div class="stat-info">
                            <h4 id="pending-scheduled">0</h4>
                            <p>Pending Messages</p>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon">
                            <i class="fas fa-check"></i>
                        </div>
                        <div class="stat-info">
                            <h4 id="sent-scheduled">0</h4>
                            <p>Sent Messages</p>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon">
                            <i class="fas fa-times"></i>
                        </div>
                        <div class="stat-info">
                            <h4 id="failed-scheduled">0</h4>
                            <p>Failed Messages</p>
                        </div>
                    </div>
                </div>
                
                <div id="scheduled-messages">
                    <p>Loading scheduled messages...</p>
                </div>
            </div>
        </div>
    \\\`;
}

function showScheduleModal() {
    const modal = document.createElement('div');
    modal.className = 'modal show';
    modal.innerHTML = \\\`
        <div class="modal-content">
            <div class="modal-header">
                <h3>📅 Schedule Message</h3>
                <button onclick="this.closest('.modal').remove()">×</button>
            </div>
            <div class="modal-body">
                <form id="schedule-form">
                    <div class="form-group">
                        <label>Recipient Number:</label>
                        <input type="text" id="schedule-recipient" placeholder="+1234567890" required>
                        <small>Enter phone number with country code</small>
                    </div>
                    <div class="form-group">
                        <label>Message:</label>
                        <textarea id="schedule-message" rows="4" placeholder="Your message here..." required></textarea>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Schedule Date:</label>
                            <input type="date" id="schedule-date" required>
                        </div>
                        <div class="form-group">
                            <label>Schedule Time:</label>
                            <input type="time" id="schedule-time" required>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Media (Optional):</label>
                        <input type="file" id="schedule-media" accept="image/*,video/*,audio/*,.pdf,.doc,.docx">
                        <small>Optional: Attach image, video, audio, or document</small>
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn btn-outline" onclick="this.closest('.modal').remove()">Cancel</button>
                        <button type="submit" class="btn btn-primary">Schedule Message</button>
                    </div>
                </form>
            </div>
        </div>
    \\\`;
    document.body.appendChild(modal);
    
    // Set minimum datetime to now
    const now = new Date();
    const today = now.toISOString().split('T')[0];
    const currentTime = now.toTimeString().slice(0, 5);
    
    document.getElementById('schedule-date').min = today;
    document.getElementById('schedule-date').value = today;
    document.getElementById('schedule-time').value = currentTime;
    
    document.getElementById('schedule-form').onsubmit = scheduleMessage;
}

async function scheduleMessage(e) {
    e.preventDefault();
    
    const recipient = document.getElementById('schedule-recipient').value.trim();
    const message = document.getElementById('schedule-message').value.trim();
    const date = document.getElementById('schedule-date').value;
    const time = document.getElementById('schedule-time').value;
    const mediaFile = document.getElementById('schedule-media').files[0];
    
    // Validate inputs
    if (!recipient || !message || !date || !time) {
        showToast('Please fill in all required fields', 'error');
        return;
    }
    
    // Create datetime string
    const scheduledDateTime = \\\`\\\${date}T\\\${time}:00\\\`;
    const scheduledDate = new Date(scheduledDateTime);
    
    // Check if scheduled time is in the future
    if (scheduledDate <= new Date()) {
        showToast('Scheduled time must be in the future', 'error');
        return;
    }
    
    // Create task
    const taskId = createTask('Schedule Message', 'scheduler', {
        total: 1,
        canStop: false,
        canPause: false
    });
    
    try {
        const formData = new FormData();
        formData.append('recipient', recipient);
        formData.append('message', message);
        formData.append('scheduledAt', scheduledDateTime);
        
        if (mediaFile) {
            formData.append('media', mediaFile);
            formData.append('messageType', mediaFile.type.startsWith('image/') ? 'image' : 
                                         mediaFile.type.startsWith('video/') ? 'video' : 
                                         mediaFile.type.startsWith('audio/') ? 'audio' : 'document');
        }
        
        const response = await fetch('/api/messages/schedule', {
            method: 'POST',
            headers: { 'Authorization': \\\`Bearer \\\${localStorage.getItem('token')}\\\` },
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            updateTask(taskId, { progress: 100, processed: 1, success: 1 });
            completeTask(taskId, 'completed');
            showToast(\\\`Message scheduled for \\\${scheduledDate.toLocaleString()}!\\\`, 'success');
            document.querySelector('.modal').remove();
            loadScheduledMessages();
        } else {
            updateTask(taskId, { progress: 100, processed: 1, failed: 1 });
            completeTask(taskId, 'error');
            showToast(data.error || 'Failed to schedule message', 'error');
        }
    } catch (error) {
        updateTask(taskId, { progress: 100, processed: 1, failed: 1 });
        completeTask(taskId, 'error');
        showToast('Error scheduling message', 'error');
    }
}

async function loadScheduledMessages() {
    try {
        const response = await fetch('/api/messages/scheduled', {
            headers: { 'Authorization': \\\`Bearer \\\${localStorage.getItem('token')}\\\` }
        });
        
        const messages = await response.json();
        const container = document.getElementById('scheduled-messages');
        
        // Update stats
        const pending = messages.filter(m => m.status === 'pending').length;
        const sent = messages.filter(m => m.status === 'sent').length;
        const failed = messages.filter(m => m.status === 'failed').length;
        
        const pendingEl = document.getElementById('pending-scheduled');
        const sentEl = document.getElementById('sent-scheduled');
        const failedEl = document.getElementById('failed-scheduled');
        
        if (pendingEl) pendingEl.textContent = pending;
        if (sentEl) sentEl.textContent = sent;
        if (failedEl) failedEl.textContent = failed;
        
        if (messages.length === 0) {
            container.innerHTML = '<p>No scheduled messages found. Click "Schedule Message" to create one.</p>';
            return;
        }
        
        // Group messages by status
        const pendingMessages = messages.filter(m => m.status === 'pending');
        const sentMessages = messages.filter(m => m.status === 'sent');
        const failedMessages = messages.filter(m => m.status === 'failed');
        
        container.innerHTML = \\\`
            \\\${pendingMessages.length > 0 ? \\\`
                <div class="message-group">
                    <h4>⏳ Pending Messages (\\\${pendingMessages.length})</h4>
                    \\\${pendingMessages.map(msg => createMessageCard(msg, true)).join('')}
                </div>
            \\\` : ''}
            
            \\\${sentMessages.length > 0 ? \\\`
                <div class="message-group">
                    <h4>✅ Sent Messages (\\\${sentMessages.length})</h4>
                    \\\${sentMessages.slice(0, 5).map(msg => createMessageCard(msg, false)).join('')}
                    \\\${sentMessages.length > 5 ? \\\`<p><small>Showing 5 of \\\${sentMessages.length} sent messages</small></p>\\\` : ''}
                </div>
            \\\` : ''}
            
            \\\${failedMessages.length > 0 ? \\\`
                <div class="message-group">
                    <h4>❌ Failed Messages (\\\${failedMessages.length})</h4>
                    \\\${failedMessages.map(msg => createMessageCard(msg, true)).join('')}
                </div>
            \\\` : ''}
        \\\`;
    } catch (error) {
        document.getElementById('scheduled-messages').innerHTML = '<p>Error loading scheduled messages</p>';
    }
}

function createMessageCard(msg, showActions) {
    const scheduledTime = new Date(msg.scheduled_at);
    const isOverdue = msg.status === 'pending' && scheduledTime < new Date();
    
    return \\\`
        <div class="scheduled-message" style="padding: 1rem; border: 1px solid var(--border); margin: 0.5rem 0; border-radius: 0.5rem; \\\${isOverdue ? 'border-color: #ef4444;' : ''}">
            <div style="display: flex; justify-content: space-between; align-items: start;">
                <div style="flex: 1;">
                    <h4>📱 \\\${msg.recipient}</h4>
                    <p style="margin: 0.5rem 0;">\\\${msg.message.substring(0, 100)}\\\${msg.message.length > 100 ? '...' : ''}</p>
                    <div style="display: flex; gap: 1rem; font-size: 0.8rem; color: var(--text-secondary);">
                        <span>⏰ \\\${scheduledTime.toLocaleString()}</span>
                        <span>📊 Status: \\\${msg.status}</span>
                        \\\${msg.attempts > 0 ? \\\`<span>🔄 Attempts: \\\${msg.attempts}</span>\\\` : ''}
                        \\\${msg.media_path ? '<span>📎 Has media</span>' : ''}
                    </div>
                    \\\${isOverdue ? '<div style="color: #ef4444; font-size: 0.8rem; margin-top: 0.5rem;">⚠️ Overdue - Check WhatsApp connection</div>' : ''}
                </div>
                \\\${showActions ? \\\`
                    <div style="display: flex; gap: 0.5rem;">
                        \\\${msg.status === 'pending' ? \\\`
                            <button class="btn btn-outline btn-small" onclick="editScheduledMessage(\\\${msg.id})">
                                ✏️ Edit
                            </button>
                            <button class="btn btn-outline btn-small" onclick="cancelScheduledMessage(\\\${msg.id})">
                                ❌ Cancel
                            </button>
                        \\\` : ''}
                        \\\${msg.status === 'failed' ? \\\`
                            <button class="btn btn-outline btn-small" onclick="retryScheduledMessage(\\\${msg.id})">
                                🔄 Retry
                            </button>
                        \\\` : ''}
                    </div>
                \\\` : ''}
            </div>
        </div>
    \\\`;
}

async function cancelScheduledMessage(messageId) {
    if (!confirm('Are you sure you want to cancel this scheduled message?')) {
        return;
    }
    
    try {
        const response = await fetch(\\\`/api/messages/scheduled/\\\${messageId}\\\`, {
            method: 'DELETE',
            headers: { 'Authorization': \\\`Bearer \\\${localStorage.getItem('token')}\\\` }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Scheduled message cancelled', 'success');
            loadScheduledMessages();
        } else {
            showToast('Failed to cancel message', 'error');
        }
    } catch (error) {
        showToast('Error cancelling message', 'error');
    }
}

async function retryScheduledMessage(messageId) {
    try {
        const response = await fetch(\\\`/api/messages/scheduled/\\\${messageId}/retry\\\`, {
            method: 'POST',
            headers: { 'Authorization': \\\`Bearer \\\${localStorage.getItem('token')}\\\` }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Message queued for retry', 'success');
            loadScheduledMessages();
        } else {
            showToast('Failed to retry message', 'error');
        }
    } catch (error) {
        showToast('Error retrying message', 'error');
    }
}

// Make functions global
window.showScheduleModal = showScheduleModal;
window.scheduleMessage = scheduleMessage;
window.loadScheduledMessages = loadScheduledMessages;
window.cancelScheduledMessage = cancelScheduledMessage;
window.retryScheduledMessage = retryScheduledMessage;
\`;

console.log('Message Scheduler Fix Ready');
console.log('1. Replace the queue processor in server.js with enhancedQueueProcessor');
console.log('2. Update the frontend scheduler functions');
console.log('3. Add the retry endpoint to server.js');