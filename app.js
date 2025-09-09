// Global variables
let currentUser = null;
let socket = null;
let isAuthMode = true; // true for login, false for register
let currentSection = 'overview';

// HTML escaping function to prevent XSS
function escapeHtml(text) {
    if (typeof text !== 'string') return text;
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    checkAuthStatus();
    setupEventListeners();
});

function checkAuthStatus() {
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('user');
    
    if (token && user) {
        currentUser = JSON.parse(user);
        showDashboard();
        initializeSocket();
    } else {
        showLandingPage();
    }
}

function setupEventListeners() {
    // Auth forms
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('register-form').addEventListener('submit', handleRegister);
    
    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const section = item.dataset.section;
            navigateToSection(section);
        });
    });
    
    // Modal close
    document.getElementById('auth-modal').addEventListener('click', (e) => {
        if (e.target.id === 'auth-modal') {
            hideAuth();
        }
    });
}

// Authentication functions
function showAuth(mode) {
    isAuthMode = mode === 'login';
    updateAuthModal();
    document.getElementById('auth-modal').classList.add('show');
}

function hideAuth() {
    document.getElementById('auth-modal').classList.remove('show');
}

function toggleAuthMode() {
    isAuthMode = !isAuthMode;
    updateAuthModal();
}

function updateAuthModal() {
    const title = document.getElementById('auth-title');
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const switchText = document.getElementById('auth-switch-text');
    const switchBtn = document.getElementById('auth-switch-btn');
    
    if (isAuthMode) {
        title.textContent = 'Login to Your Account';
        loginForm.style.display = 'block';
        registerForm.style.display = 'none';
        switchText.textContent = "Don't have an account?";
        switchBtn.textContent = 'Sign up here';
    } else {
        title.textContent = 'Create Your Account';
        loginForm.style.display = 'none';
        registerForm.style.display = 'block';
        switchText.textContent = 'Already have an account?';
        switchBtn.textContent = 'Login here';
    }
}

async function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    showLoading();
    
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            currentUser = data.user;
            
            hideAuth();
            showDashboard();
            initializeSocket();
            showToast('Login successful!', 'success');
        } else {
            showToast(data.error || 'Login failed', 'error');
        }
    } catch (error) {
        showToast('Network error. Please try again.', 'error');
    }
    
    hideLoading();
}

async function sendOTP() {
    const whatsapp = document.getElementById('register-whatsapp').value;
    
    if (!whatsapp) {
        showToast('Please enter WhatsApp number first', 'error');
        return;
    }
    
    // Validate WhatsApp number format
    const cleanNumber = whatsapp.replace(/[^0-9]/g, '');
    if (cleanNumber.length < 10 || cleanNumber.length > 15) {
        showToast('Please enter WhatsApp number in format: 923001234567 (with country code, no + or spaces)', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/send-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                whatsappNumber: cleanNumber,
                adminNumber: '923400885132',
                purpose: 'registration'
            })
        });
        
        const data = await response.json();
        if (data.success) {
            showToast('OTP sent to your WhatsApp!', 'success');
            document.getElementById('otp-section').style.display = 'block';
            document.getElementById('send-otp-btn').disabled = true;
            document.getElementById('send-otp-btn').textContent = 'OTP Sent';
        } else {
            showToast('Failed to send OTP. Please try again.', 'error');
        }
    } catch (error) {
        showToast('Error sending OTP. Please try again.', 'error');
    }
}

async function handleRegister(e) {
    e.preventDefault();
    
    const username = document.getElementById('register-username').value;
    const email = document.getElementById('register-email').value;
    const whatsapp = document.getElementById('register-whatsapp').value;
    const password = document.getElementById('register-password').value;
    const otp = document.getElementById('register-otp').value;
    
    if (!otp) {
        showToast('Please enter OTP', 'error');
        return;
    }
    
    // Verify OTP first
    try {
        const verifyResponse = await fetch('/api/verify-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                whatsappNumber: whatsapp.replace(/[^0-9]/g, ''),
                otp: otp
            })
        });
        
        const verifyData = await verifyResponse.json();
        if (!verifyData.success) {
            showToast('Invalid OTP', 'error');
            return;
        }
    } catch (error) {
        showToast('Error verifying OTP', 'error');
        return;
    }
    
    showLoading();
    
    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password, whatsapp })
        });
        
        const data = await response.json();
        
        if (data.success) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            currentUser = data.user;
            
            hideAuth();
            showDashboard();
            initializeSocket();
            showToast('Account created successfully!', 'success');
        } else {
            showToast(data.error || 'Registration failed', 'error');
        }
    } catch (error) {
        showToast('Network error. Please try again.', 'error');
    }
    
    hideLoading();
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    currentUser = null;
    
    if (socket) {
        socket.disconnect();
        socket = null;
    }
    
    showLandingPage();
    showToast('Logged out successfully', 'success');
}

// UI functions
function showLandingPage() {
    document.getElementById('landing-page').style.display = 'block';
    document.getElementById('dashboard').style.display = 'none';
}

function showDashboard() {
    document.getElementById('landing-page').style.display = 'none';
    document.getElementById('dashboard').style.display = 'flex';
    
    // Update user info
    document.getElementById('user-name').textContent = currentUser.username;
    document.getElementById('user-email').textContent = currentUser.email;
    
    // Load initial section
    navigateToSection('overview');
    
    // Load analytics immediately
    setTimeout(() => {
        console.log('Loading analytics on dashboard load...');
        loadAnalytics();
    }, 500);
    
    // Auto-connect WhatsApp
    setTimeout(autoConnectWhatsApp, 1000);
    
    // Check for background campaigns
    checkBackgroundCampaigns();
    
    // Restore active campaigns
    restoreActiveCampaigns();
    
    // Check subscription status
    checkSubscriptionStatus();
}

function initializeSocket() {
    if (socket) {
        socket.disconnect();
    }
    
    socket = io({
        transports: ['websocket', 'polling'],
        upgrade: true,
        rememberUpgrade: true
    });
    
    socket.on('connect', () => {
        console.log('Socket connected:', socket.id);
        socket.emit('join', currentUser.id);
    });
    
    socket.on('disconnect', (reason) => {
        console.log('Socket disconnected:', reason);
        if (reason === 'io server disconnect') {
            socket.connect();
        }
    });
    
    socket.on('qr', (qrData) => {
        console.log('QR code received');
        updateQRCode(qrData);
        showToast('QR Code generated! Scan with WhatsApp', 'success');
    });
    
    socket.on('ready', () => {
        console.log('WhatsApp ready');
        updateConnectionStatus(true);
        hideQRCode();
        showToast('WhatsApp connected successfully!', 'success');
    });
    
    socket.on('authenticated', () => {
        console.log('WhatsApp authenticated');
        showToast('WhatsApp authenticated!', 'success');
    });
    
    socket.on('auth_failure', () => {
        console.log('WhatsApp auth failed');
        updateConnectionStatus(false);
        showToast('WhatsApp authentication failed', 'error');
    });
    
    socket.on('disconnected', (data) => {
        console.log('WhatsApp disconnected:', data?.reason);
        updateConnectionStatus(false);
    });
    
    socket.on('connection_error', (data) => {
        console.log('Connection error:', data?.message);
        updateConnectionStatus(false);
    });
    
    socket.on('loading', (data) => {
        console.log('Loading:', data.percent, data.message);
    });
    
    // Check connection status on connect
    checkConnectionStatus();
    
    // Periodic health check every 30 seconds
    setInterval(checkConnectionStatus, 30000);
    
    socket.on('bulk-progress', (data) => {
        updateBulkProgress(data);
    });
    
    socket.on('broadcast-progress', (data) => {
        const progressFill = document.getElementById('broadcast-progress-fill');
        const progressText = document.getElementById('broadcast-progress-text');
        const successCount = document.getElementById('broadcast-success-count');
        const failedCount = document.getElementById('broadcast-failed-count');
        
        // Update Task Manager
        if (window.currentTaskId) {
            const percentage = (data.current / data.total) * 100;
            let currentSuccess = parseInt(successCount?.textContent || '0');
            let currentFailed = parseInt(failedCount?.textContent || '0');
            
            if (data.status === 'sent') currentSuccess++;
            else if (data.status === 'failed') currentFailed++;
            
            updateTask(window.currentTaskId, {
                progress: percentage,
                processed: data.current,
                success: currentSuccess,
                failed: currentFailed
            });
        }
        
        if (progressFill && progressText) {
            const percentage = (data.current / data.total) * 100;
            progressFill.style.width = `${percentage}%`;
            progressText.textContent = `${data.current} / ${data.total} groups`;
            
            if (data.status === 'sent') {
                successCount.textContent = parseInt(successCount.textContent) + 1;
            } else if (data.status === 'failed') {
                failedCount.textContent = parseInt(failedCount.textContent) + 1;
            }
        }
    });
    
    socket.on('contact-broadcast-progress', (data) => {
        const progressFill = document.getElementById('contact-progress-fill');
        const progressText = document.getElementById('contact-progress-text');
        const successCount = document.getElementById('contact-success-count');
        const failedCount = document.getElementById('contact-failed-count');
        
        // Update Task Manager
        if (window.currentTaskId) {
            const percentage = (data.current / data.total) * 100;
            let currentSuccess = parseInt(successCount?.textContent || '0');
            let currentFailed = parseInt(failedCount?.textContent || '0');
            
            if (data.status === 'sent') currentSuccess++;
            else if (data.status === 'failed') currentFailed++;
            
            updateTask(window.currentTaskId, {
                progress: percentage,
                processed: data.current,
                success: currentSuccess,
                failed: currentFailed,
                total: data.total
            });
        }
        
        if (progressFill && progressText) {
            const percentage = (data.current / data.total) * 100;
            progressFill.style.width = `${percentage}%`;
            progressText.textContent = `${data.current} / ${data.total} contacts`;
            
            if (data.status === 'sent') {
                successCount.textContent = parseInt(successCount.textContent) + 1;
            } else if (data.status === 'failed') {
                failedCount.textContent = parseInt(failedCount.textContent) + 1;
            }
        }
    });
    
    socket.on('bot-response', (data) => {
        addBotActivityLog(data);
    });
    
    // Scheduler real-time updates
    socket.on('scheduled-message-sent', (data) => {
        console.log(`✅ Scheduled message sent to ${data.recipient}`);
        showToast(`✅ Scheduled message sent to ${data.recipient}`, 'success');
        
        // Reload scheduled messages if on scheduler page
        if (currentSection === 'scheduler') {
            setTimeout(loadScheduledMessages, 1000);
        }
    });
    
    socket.on('scheduled-message-failed', (data) => {
        console.log(`❌ Scheduled message failed for ${data.recipient}: ${data.error}`);
        showToast(`❌ Scheduled message failed for ${data.recipient}`, 'error');
        
        // Reload scheduled messages if on scheduler page
        if (currentSection === 'scheduler') {
            setTimeout(loadScheduledMessages, 1000);
        }
    });
}

function setupChatBotHandlers() {
    document.getElementById('bot-enabled').addEventListener('change', saveChatBotRules);
    document.getElementById('exact-rule-form').addEventListener('submit', addExactRule);
    document.getElementById('keyword-rule-form').addEventListener('submit', addKeywordRule);
    document.getElementById('test-bot').addEventListener('click', testBot);
    document.getElementById('auto-add-enabled').addEventListener('change', saveChatBotRules);
    document.getElementById('auto-add-keywords').addEventListener('blur', saveChatBotRules);
}

async function testBot() {
    const enabled = document.getElementById('bot-enabled').checked;
    if (!enabled) {
        showToast('Please enable the bot first', 'warning');
        return;
    }
    
    const exactRules = getCurrentExactRules();
    const keywordRules = getCurrentKeywordRules();
    
    if (exactRules.length === 0 && keywordRules.length === 0) {
        showToast('Please add some bot rules first', 'warning');
        return;
    }
    
    // Simulate a test message
    const testMessage = exactRules.length > 0 ? exactRules[0].question : keywordRules[0].keywords[0];
    showToast(`Bot test: Send "${testMessage}" to your WhatsApp to test the bot`, 'success');
}

async function loadChatBotRules() {
    try {
        const response = await fetch('/api/chatbot/rules', {
            headers: { 'Authorization': `Bearer ${localStorage.getToken('token')}` }
        });
        const rules = await response.json();
        
        document.getElementById('bot-enabled').checked = rules.enabled;
        displayExactRules(rules.exactRules || []);
        displayKeywordRules(rules.keywordRules || []);
        
        // Load auto-add settings
        if (rules.autoAdd) {
            document.getElementById('auto-add-enabled').checked = rules.autoAdd.enabled;
            document.getElementById('auto-add-keywords').value = rules.autoAdd.keywords.join(', ');
        }
    } catch (error) {
        console.error('Error loading bot rules:', error);
    }
}

async function saveChatBotRules() {
    const enabled = document.getElementById('bot-enabled').checked;
    const exactRules = getCurrentExactRules();
    const keywordRules = getCurrentKeywordRules();
    
    // Get auto-add settings
    const autoAddEnabled = document.getElementById('auto-add-enabled').checked;
    const autoAddKeywords = document.getElementById('auto-add-keywords').value
        .split(',')
        .map(k => k.trim())
        .filter(k => k);
    
    const autoAdd = {
        enabled: autoAddEnabled,
        keywords: autoAddKeywords
    };
    
    console.log('Saving bot rules:', { enabled, exactRules, keywordRules, autoAdd });
    
    try {
        const response = await fetch('/api/chatbot/rules', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ enabled, exactRules, keywordRules, autoAdd })
        });
        
        const result = await response.json();
        console.log('Save result:', result);
        
        if (response.ok) {
            showToast('Chat bot settings saved!', 'success');
        } else {
            showToast('Error saving bot settings', 'error');
        }
    } catch (error) {
        console.error('Save error:', error);
        showToast('Error saving bot settings', 'error');
    }
}

function addExactRule(e) {
    e.preventDefault();
    const question = document.getElementById('exact-question').value;
    const answer = document.getElementById('exact-answer').value;
    
    const exactRules = getCurrentExactRules();
    exactRules.push({ question, answer });
    displayExactRules(exactRules);
    saveChatBotRules();
    
    document.getElementById('exact-rule-form').reset();
}

function addKeywordRule(e) {
    e.preventDefault();
    const keywordsText = document.getElementById('keyword-words').value;
    const answer = document.getElementById('keyword-answer').value;
    const keywords = keywordsText.split(',').map(k => k.trim()).filter(k => k);
    
    const keywordRules = getCurrentKeywordRules();
    keywordRules.push({ keywords, answer });
    displayKeywordRules(keywordRules);
    saveChatBotRules();
    
    document.getElementById('keyword-rule-form').reset();
}

function getCurrentExactRules() {
    const container = document.getElementById('exact-rules-list');
    const rules = [];
    container.querySelectorAll('.rule-item').forEach(item => {
        const question = item.querySelector('.rule-question').textContent;
        const answer = item.querySelector('.rule-answer').textContent;
        rules.push({ question, answer });
    });
    return rules;
}

function getCurrentKeywordRules() {
    const container = document.getElementById('keyword-rules-list');
    const rules = [];
    container.querySelectorAll('.rule-item').forEach(item => {
        const keywordsText = item.querySelector('.rule-keywords').textContent;
        const keywords = keywordsText.split(', ');
        const answer = item.querySelector('.rule-answer').textContent;
        rules.push({ keywords, answer });
    });
    return rules;
}

function displayExactRules(rules) {
    const container = document.getElementById('exact-rules-list');
    container.innerHTML = rules.map((rule, index) => `
        <div class="rule-item" style="background: var(--surface); padding: 1rem; border-radius: 0.5rem; margin: 0.5rem 0; display: flex; justify-content: space-between; align-items: center;">
            <div>
                <strong>Q:</strong> <span class="rule-question">${escapeHtml(rule.question)}</span><br>
                <strong>A:</strong> <span class="rule-answer">${escapeHtml(rule.answer)}</span>
            </div>
            <button class="btn btn-outline btn-small" onclick="deleteRule('exactRules', ${index})">
                <i class="fas fa-trash"></i>
            </button>
        </div>
    `).join('');
}

function displayKeywordRules(rules) {
    const container = document.getElementById('keyword-rules-list');
    container.innerHTML = rules.map((rule, index) => `
        <div class="rule-item" style="background: var(--surface); padding: 1rem; border-radius: 0.5rem; margin: 0.5rem 0; display: flex; justify-content: space-between; align-items: center;">
            <div>
                <strong>Keywords:</strong> <span class="rule-keywords">${escapeHtml(rule.keywords.join(', '))}</span><br>
                <strong>Answer:</strong> <span class="rule-answer">${escapeHtml(rule.answer)}</span>
            </div>
            <button class="btn btn-outline btn-small" onclick="deleteRule('keywordRules', ${index})">
                <i class="fas fa-trash"></i>
            </button>
        </div>
    `).join('');
}

async function deleteRule(type, index) {
    try {
        // Get current rules and remove the one at index
        const exactRules = getCurrentExactRules();
        const keywordRules = getCurrentKeywordRules();
        
        if (type === 'exactRules') {
            exactRules.splice(index, 1);
        } else {
            keywordRules.splice(index, 1);
        }
        
        // Save updated rules
        const response = await fetch('/api/chatbot/rules', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                enabled: document.getElementById('bot-enabled').checked,
                exactRules, 
                keywordRules 
            })
        });
        
        if (response.ok) {
            displayExactRules(exactRules);
            displayKeywordRules(keywordRules);
            showToast('Rule deleted!', 'success');
        }
    } catch (error) {
        showToast('Error deleting rule', 'error');
    }
}

function addBotActivityLog(data) {
    const container = document.getElementById('bot-activity-log');
    const logEntry = document.createElement('div');
    logEntry.style.cssText = 'padding: 0.75rem; border-left: 3px solid var(--primary-color); background: var(--surface); margin-bottom: 0.5rem; border-radius: 0.25rem;';
    logEntry.innerHTML = `
        <div style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.25rem;">
            ${new Date(data.timestamp).toLocaleString()} - ${escapeHtml(data.from)}
        </div>
        <div><strong>Q:</strong> ${escapeHtml(data.question)}</div>
        <div><strong>A:</strong> ${escapeHtml(data.answer)}</div>
    `;
    
    if (container.firstChild && container.firstChild.tagName === 'P') {
        container.innerHTML = '';
    }
    
    container.insertBefore(logEntry, container.firstChild);
    
    // Keep only last 50 entries
    while (container.children.length > 50) {
        container.removeChild(container.lastChild);
    }
}



function loadSectionContent(section) {
    const contentArea = document.getElementById('content-area');
    
    switch(section) {
        case 'overview':
            contentArea.innerHTML = getOverviewContent();
            setTimeout(() => {
                console.log('Loading analytics for overview...');
                loadAnalytics();
            }, 100);
            break;
        case 'connect':
            contentArea.innerHTML = getConnectContent();
            setupConnectHandlers();
            break;
        case 'single-message':
            contentArea.innerHTML = getSingleMessageContent();
            setupSingleMessageHandlers();
            break;
        case 'bulk-message':
            contentArea.innerHTML = getBulkMessageContent();
            setupBulkMessageHandlers();
            break;
        case 'csv-sender':
            contentArea.innerHTML = getCSVSenderContent();
            setupCSVSenderHandlers();
            break;
        case 'templates':
            contentArea.innerHTML = getTemplatesContent();
            setupTemplatesHandlers();
            loadTemplates();
            break;
        case 'scheduler':
            contentArea.innerHTML = getSchedulerContent();
            setupSchedulerHandlers();
            loadScheduledMessages();
            break;

        case 'contacts':
            contentArea.innerHTML = getContactsContent();
            loadContacts();
            break;
        case 'contact-broadcast':
            contentArea.innerHTML = getContactBroadcastContent();
            setupContactBroadcastHandlers();
            break;
        case 'groups':
            contentArea.innerHTML = getGroupsContent();
            loadGroups();
            break;
        case 'group-broadcast':
            contentArea.innerHTML = getGroupBroadcastContent();
            setupGroupBroadcastHandlers();
            loadGroupsForBroadcast();
            break;
        case 'group-adder':
            contentArea.innerHTML = getGroupAdderContent();
            setupGroupAdderHandlers();
            loadGroupsForAdder();
            break;
        case 'chatbot':
            contentArea.innerHTML = getChatBotContent();
            setupChatBotHandlers();
            loadChatBotRules();
            break;
        case 'analytics':
            contentArea.innerHTML = getAnalyticsContent();
            setTimeout(() => {
                console.log('Loading analytics for analytics page...');
                loadAnalytics();
            }, 100);
            break;
        case 'scheduler':
            contentArea.innerHTML = getSchedulerContent();
            setTimeout(loadScheduledMessages, 100);
            break;
        case 'contact-us':
            contentArea.innerHTML = getContactUsContent();
            setTimeout(loadSubscriptionDetails, 100);
            break;
        case 'task-manager':
            contentArea.innerHTML = getTaskManagerContent();
            setTimeout(loadTasks, 100);
            break;
        case 'message-history':
            contentArea.innerHTML = getMessageHistoryContent();
            setTimeout(loadMessageHistory, 100);
            break;
        case 'link-generator':
            contentArea.innerHTML = getLinkGeneratorContent();
            break;
        case 'profile':
            contentArea.innerHTML = getProfileContent();
            setTimeout(() => {
                loadUserProfile();
                setupProfileHandlers();
            }, 100);
            break;
        default:
            contentArea.innerHTML = '<div class="card"><div class="card-body"><p>Section coming soon...</p></div></div>';
    }
}

function getOverviewContent() {
    return `
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-paper-plane"></i>
                </div>
                <div class="stat-info">
                    <h4 id="total-messages">0</h4>
                    <p>Messages Sent</p>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-users"></i>
                </div>
                <div class="stat-info">
                    <h4 id="total-contacts">0</h4>
                    <p>Contacts</p>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-chart-line"></i>
                </div>
                <div class="stat-info">
                    <h4 id="success-rate">0%</h4>
                    <p>Success Rate</p>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-clock"></i>
                </div>
                <div class="stat-info">
                    <h4 id="campaigns-today">0</h4>
                    <p>Campaigns Today</p>
                </div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h3>Quick Actions</h3>
            </div>
            <div class="card-body">
                <div class="features-grid">
                    <button class="feature-card" onclick="navigateToSection('connect')" style="border: none; cursor: pointer;">
                        <div class="feature-icon">
                            <i class="fas fa-link"></i>
                        </div>
                        <h3>Connect WhatsApp</h3>
                        <p>Connect your WhatsApp account to start sending messages</p>
                    </button>
                    <button class="feature-card" onclick="navigateToSection('single-message')" style="border: none; cursor: pointer;">
                        <div class="feature-icon">
                            <i class="fas fa-comment"></i>
                        </div>
                        <h3>Single Message</h3>
                        <p>Send text, images, videos, or documents to one contact</p>
                    </button>
                    <button class="feature-card" onclick="navigateToSection('bulk-message')" style="border: none; cursor: pointer;">
                        <div class="feature-icon">
                            <i class="fas fa-paper-plane"></i>
                        </div>
                        <h3>Bulk Messages</h3>
                        <p>Send messages to multiple contacts with media support</p>
                    </button>
                </div>
            </div>
        </div>
    `;
}

function getConnectContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>Connect Your WhatsApp Account</h3>
            </div>
            <div class="card-body">
                <div id="connection-area">
                    <div class="qr-container">
                        <div id="qr-placeholder" class="qr-placeholder">
                            <i class="fas fa-qrcode"></i>
                            <p>Click "Connect WhatsApp" to generate QR code</p>
                        </div>
                        <img id="qr-code" class="qr-code" style="display: none;" alt="QR Code">
                    </div>
                    <div style="text-align: center; margin-top: 2rem;">
                        <button id="connect-btn" class="btn btn-primary btn-large">
                            <i class="fas fa-link"></i> Connect WhatsApp
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function getCSVSenderContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>📊 CSV Bulk Message Sender</h3>
                <p>Upload CSV file with contacts and personalized messages</p>
            </div>
            <div class="card-body">
                <div class="csv-upload-section">
                    <div class="form-group">
                        <label>📁 Upload CSV File</label>
                        <input type="file" id="csv-file" accept=".csv" class="csv-input">
                        <div class="csv-format-info">
                            <h4>📋 Required CSV Format:</h4>
                            <div class="format-example">
                                <code>phone,name,message</code><br>
                                <code>1234567890,John,Hello John! Special offer for you</code><br>
                                <code>0987654321,Sarah,Hi Sarah! Check our new products</code>
                            </div>
                            <a href="#" id="download-template" class="btn btn-outline btn-small">
                                📥 Download Template
                            </a>
                        </div>
                    </div>
                    
                    <div id="csv-preview" style="display: none;">
                        <h4>📋 CSV Preview</h4>
                        <div class="csv-table-container">
                            <table id="csv-table" class="csv-table"></table>
                        </div>
                        <div class="csv-stats">
                            <span class="stat-item">📞 Total Contacts: <strong id="csv-total">0</strong></span>
                            <span class="stat-item">✅ Valid Numbers: <strong id="csv-valid">0</strong></span>
                            <span class="stat-item">❌ Invalid Numbers: <strong id="csv-invalid">0</strong></span>
                        </div>
                    </div>
                </div>
                
                <div class="timing-controls">
                    <h4>⏱️ Timing Settings</h4>
                    <div class="timing-options">
                        <div class="timing-option">
                            <input type="radio" id="csv-fixed-delay" name="csvDelayType" value="fixed" checked>
                            <label for="csv-fixed-delay">Fixed Delay</label>
                        </div>
                        <div class="timing-option">
                            <input type="radio" id="csv-random-delay" name="csvDelayType" value="random">
                            <label for="csv-random-delay">Random Delay</label>
                        </div>
                    </div>
                    
                    <div class="delay-inputs">
                        <div class="form-group" id="csv-fixed-delay-input">
                            <label>Delay (seconds)</label>
                            <input type="number" id="csv-fixed-delay-value" min="2" max="300" value="5">
                        </div>
                        <div class="form-group" id="csv-random-delay-inputs" style="display: none;">
                            <label>Min Delay (seconds)</label>
                            <input type="number" id="csv-min-delay" min="2" max="300" value="3">
                        </div>
                        <div class="form-group" id="csv-random-delay-inputs-max" style="display: none;">
                            <label>Max Delay (seconds)</label>
                            <input type="number" id="csv-max-delay" min="2" max="300" value="10">
                        </div>
                    </div>
                </div>
                
                <button id="send-csv-messages" class="btn btn-primary btn-large" disabled>
                    <i class="fas fa-paper-plane"></i> Send CSV Messages
                </button>
                
                <div id="csv-progress" style="display: none;">
                    <div class="progress-container">
                        <div class="progress-header">
                            <h4>📤 Sending CSV Messages...</h4>
                            <button id="stop-csv-campaign" class="btn btn-outline btn-small">Stop</button>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" id="csv-progress-fill"></div>
                        </div>
                        <div class="progress-stats">
                            <div class="progress-text" id="csv-progress-text">0 / 0 messages sent</div>
                            <div class="progress-details">
                                <span class="success-count">✅ <span id="csv-success-count">0</span></span>
                                <span class="failed-count">❌ <span id="csv-failed-count">0</span></span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div id="csv-results" style="display: none;">
                    <div class="results-header">
                        <h4>📊 CSV Campaign Results</h4>
                        <div class="results-summary">
                            <span class="total-sent">Total: <span id="csv-total-sent">0</span></span>
                            <span class="success-rate">Success Rate: <span id="csv-final-success-rate">0%</span></span>
                        </div>
                    </div>
                    <div id="csv-results-list"></div>
                    <button id="download-csv-results" class="btn btn-outline">📥 Download Report</button>
                </div>
            </div>
        </div>
    `;
}

function getBulkMessageContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>Advanced Bulk Message Sender</h3>
            </div>
            <div class="card-body">
                <form id="bulk-message-form" enctype="multipart/form-data">
                    <div class="form-group">
                        <label>Message Type</label>
                        <div class="message-type-tabs">
                            <button type="button" class="tab-btn active" data-type="text">📝 Text</button>
                            <button type="button" class="tab-btn" data-type="image">🖼️ Image</button>
                            <button type="button" class="tab-btn" data-type="video">🎥 Video</button>
                            <button type="button" class="tab-btn" data-type="audio">🎵 Audio</button>
                            <button type="button" class="tab-btn" data-type="document">📄 Document</button>
                            <button type="button" class="tab-btn" data-type="button">🔘 Button</button>
                        </div>
                    </div>
                    
                    <div id="media-upload" style="display: none;">
                        <div class="form-group">
                            <label>Select Media File</label>
                            <input type="file" id="media-file" accept="*/*">
                            <div class="file-info" id="file-info" style="display: none;"></div>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label>Phone Numbers (one per line)</label>
                        <textarea id="bulk-numbers" rows="6" placeholder="1234567890&#10;0987654321&#10;+1234567890&#10;..." required></textarea>
                        <small>Supports formats: 1234567890, +1234567890, 91-1234567890</small>
                    </div>
                    
                    <div class="form-group">
                        <label id="message-label">Message</label>
                        <textarea id="bulk-message" rows="4" placeholder="Enter your message..." required></textarea>
                        <small>For media messages, this will be used as caption</small>
                    </div>
                    
                    <div class="timing-controls">
                        <h4>⏱️ Timing Controls</h4>
                        <div class="timing-options">
                            <div class="timing-option">
                                <input type="radio" id="fixed-delay" name="delayType" value="fixed" checked>
                                <label for="fixed-delay">Fixed Delay</label>
                            </div>
                            <div class="timing-option">
                                <input type="radio" id="random-delay" name="delayType" value="random">
                                <label for="random-delay">Random Delay</label>
                            </div>
                        </div>
                        
                        <div class="delay-inputs">
                            <div class="form-group" id="fixed-delay-input">
                                <label>Delay (seconds)</label>
                                <input type="number" id="fixed-delay-value" min="2" max="300" value="5">
                            </div>
                            <div class="form-group" id="random-delay-inputs" style="display: none;">
                                <label>Min Delay (seconds)</label>
                                <input type="number" id="min-delay" min="2" max="300" value="3">
                            </div>
                            <div class="form-group" id="random-delay-inputs-max" style="display: none;">
                                <label>Max Delay (seconds)</label>
                                <input type="number" id="max-delay" min="2" max="300" value="10">
                            </div>
                        </div>
                    </div>
                    
                    <div class="advanced-options">
                        <h4>📊 Campaign Settings</h4>
                        <div class="form-row">
                            <div class="form-group">
                                <label>Campaign Name (Optional)</label>
                                <input type="text" id="campaign-name" placeholder="My Campaign">
                            </div>
                            <div class="form-group">
                                <input type="checkbox" id="save-campaign" style="width: auto;">
                                <label for="save-campaign">Save as template</label>
                            </div>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary btn-large">
                        <i class="fas fa-paper-plane"></i> Send Bulk Messages
                    </button>
                </form>
                
                <div id="bulk-progress" style="display: none;">
                    <div class="progress-container">
                        <div class="progress-header">
                            <h4>📤 Sending Messages...</h4>
                            <button id="stop-campaign" class="btn btn-outline btn-small" onclick="stopCampaign()">Stop Campaign</button>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" id="progress-fill"></div>
                        </div>
                        <div class="progress-stats">
                            <div class="progress-text" id="progress-text">0 / 0 messages sent</div>
                            <div class="progress-details">
                                <span class="success-count">✅ <span id="success-count">0</span></span>
                                <span class="failed-count">❌ <span id="failed-count">0</span></span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div id="bulk-results" style="display: none;">
                    <div class="results-header">
                        <h4>📊 Campaign Results</h4>
                        <div class="results-summary">
                            <span class="total-sent">Total: <span id="total-sent">0</span></span>
                            <span class="success-rate">Success Rate: <span id="final-success-rate">0%</span></span>
                        </div>
                    </div>
                    <div id="results-list"></div>
                    <button id="download-results" class="btn btn-outline" onclick="downloadBulkReport()">📥 Download Report</button>
                </div>
            </div>
        </div>
    `;
}

function getContactsContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>📱 Contact Management</h3>
                <div class="contact-actions">
                    <button class="btn btn-primary" onclick="showImportModal()">
                        📁 Import CSV
                    </button>
                    <button class="btn btn-outline" onclick="deduplicateContacts()">
                        🧹 Remove Duplicates
                    </button>
                    <button class="btn btn-outline" onclick="exportToGoogleContacts()">
                        📥 Export to Google
                    </button>
                </div>
            </div>
            <div class="card-body">
                <div id="contacts-list">
                    <p>Loading contacts...</p>
                </div>
            </div>
        </div>
    `;
}

function getGroupsContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>👥 Group Management</h3>
                <div class="group-actions">
                    <button class="btn btn-primary" onclick="extractAllNumbers()">
                        📥 Extract All Numbers
                    </button>
                    <button class="btn btn-outline" onclick="downloadAllNumbersCSV()">
                        📄 Download CSV
                    </button>
                </div>
            </div>
            <div class="card-body">
                <div id="groups-list">
                    <p>Loading groups...</p>
                </div>
            </div>
        </div>
        
        <div class="card" id="extracted-numbers" style="display: none;">
            <div class="card-header">
                <h3>📱 Extracted Numbers</h3>
            </div>
            <div class="card-body">
                <div id="numbers-display"></div>
            </div>
        </div>
    `;
}

function getGroupBroadcastContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>📢 Group Broadcast</h3>
                <p>Send messages to multiple groups at once</p>
                <div class="group-actions" style="margin-top: 1rem;">
                    <button class="btn btn-primary" onclick="showCreateGroupModal()">
                        <i class="fas fa-plus"></i> Create New Group
                    </button>
                </div>
            </div>
            <div class="card-body">
                <form id="group-broadcast-form" enctype="multipart/form-data">
                    <div class="form-group">
                        <label>Select Groups</label>
                        <div class="group-selection">
                            <div class="select-all-groups">
                                <input type="checkbox" id="select-all-groups">
                                <label for="select-all-groups">Select All Groups</label>
                            </div>
                            <div id="groups-checkboxes">
                                <p>Loading groups...</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label>Message Type</label>
                        <div class="message-type-tabs">
                            <button type="button" class="tab-btn active" data-type="text">📝 Text</button>
                            <button type="button" class="tab-btn" data-type="image">🖼️ Image</button>
                            <button type="button" class="tab-btn" data-type="video">🎥 Video</button>
                            <button type="button" class="tab-btn" data-type="audio">🎵 Audio</button>
                            <button type="button" class="tab-btn" data-type="document">📄 Document</button>
                            <button type="button" class="tab-btn" data-type="button">🔘 Button</button>
                        </div>
                    </div>
                    
                    <div id="broadcast-media-upload" style="display: none;">
                        <div class="form-group">
                            <label>Select Media File</label>
                            <input type="file" id="broadcast-media-file" accept="*/*">
                            <div class="file-info" id="broadcast-file-info" style="display: none;"></div>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label id="broadcast-message-label">Message</label>
                        <textarea id="broadcast-message" rows="4" placeholder="Enter your broadcast message..." required></textarea>
                        <small>This message will be sent to all selected groups</small>
                    </div>
                    
                    <div class="form-group">
                        <input type="checkbox" id="mention-all-broadcast" style="width: auto;">
                        <label for="mention-all-broadcast">Mention all group members (@everyone)</label>
                        <small>This will mention all members in each group</small>
                    </div>
                    
                    <div class="timing-controls">
                        <h4>⏱️ Timing Controls</h4>
                        <div class="timing-options">
                            <div class="timing-option">
                                <input type="radio" id="broadcast-fixed-delay" name="broadcastDelayType" value="fixed" checked>
                                <label for="broadcast-fixed-delay">Fixed Delay</label>
                            </div>
                            <div class="timing-option">
                                <input type="radio" id="broadcast-random-delay" name="broadcastDelayType" value="random">
                                <label for="broadcast-random-delay">Random Delay</label>
                            </div>
                        </div>
                        
                        <div class="delay-inputs">
                            <div class="form-group" id="broadcast-fixed-delay-input">
                                <label>Delay (seconds)</label>
                                <input type="number" id="broadcast-fixed-delay-value" min="2" max="300" value="5">
                            </div>
                            <div class="form-group" id="broadcast-random-delay-inputs" style="display: none;">
                                <label>Min Delay (seconds)</label>
                                <input type="number" id="broadcast-min-delay" min="2" max="300" value="3">
                            </div>
                            <div class="form-group" id="broadcast-random-delay-inputs-max" style="display: none;">
                                <label>Max Delay (seconds)</label>
                                <input type="number" id="broadcast-max-delay" min="2" max="300" value="10">
                            </div>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary btn-large">
                        <i class="fas fa-bullhorn"></i> Send Broadcast
                    </button>
                </form>
                
                <div id="broadcast-progress" style="display: none;">
                    <div class="progress-container">
                        <div class="progress-header">
                            <h4>📢 Broadcasting...</h4>
                            <button id="stop-broadcast" class="btn btn-outline btn-small">Stop</button>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" id="broadcast-progress-fill"></div>
                        </div>
                        <div class="progress-stats">
                            <div class="progress-text" id="broadcast-progress-text">0 / 0 groups</div>
                            <div class="progress-details">
                                <span class="success-count">✅ <span id="broadcast-success-count">0</span></span>
                                <span class="failed-count">❌ <span id="broadcast-failed-count">0</span></span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div id="broadcast-results" style="display: none;">
                    <div class="results-header">
                        <h4>📊 Broadcast Results</h4>
                    </div>
                    <div id="broadcast-results-list"></div>
                </div>
            </div>
        </div>
    `;
}

function getChatBotContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>Auto Chat Bot Settings</h3>
                <div style="display: flex; align-items: center; gap: 1rem;">
                    <label style="margin: 0;">Enable Bot:</label>
                    <input type="checkbox" id="bot-enabled" style="width: auto;">
                </div>
            </div>
            <div class="card-body">
                <div class="timing-controls">
                    <h4>Exact Match Rules</h4>
                    <p>Bot will respond only when the message exactly matches the question.</p>
                    <form id="exact-rule-form">
                        <div style="display: grid; grid-template-columns: 1fr 1fr auto; gap: 1rem; align-items: end;">
                            <div class="form-group">
                                <label>Question</label>
                                <input type="text" id="exact-question" placeholder="Hello" required>
                            </div>
                            <div class="form-group">
                                <label>Answer</label>
                                <input type="text" id="exact-answer" placeholder="Hi! How can I help you?" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Add Rule</button>
                        </div>
                    </form>
                    <div id="exact-rules-list"></div>
                </div>
                
                <div class="timing-controls">
                    <h4>Keyword Match Rules</h4>
                    <p>Bot will respond when any of the keywords are found in the message.</p>
                    <form id="keyword-rule-form">
                        <div style="display: grid; grid-template-columns: 1fr 1fr auto; gap: 1rem; align-items: end;">
                            <div class="form-group">
                                <label>Keywords (comma separated)</label>
                                <input type="text" id="keyword-words" placeholder="price, cost, payment" required>
                            </div>
                            <div class="form-group">
                                <label>Answer</label>
                                <input type="text" id="keyword-answer" placeholder="Our prices start from $10" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Add Rule</button>
                        </div>
                    </form>
                    <div id="keyword-rules-list"></div>
                </div>
                
                <div class="timing-controls">
                    <h4>🎯 Auto Group Adder</h4>
                    <p>Automatically add users to your admin groups when they send specific keywords.</p>
                    <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
                        <label style="margin: 0;">Enable Auto-Add:</label>
                        <input type="checkbox" id="auto-add-enabled" style="width: auto;">
                    </div>
                    <div class="form-group">
                        <label>Trigger Keywords (comma separated)</label>
                        <input type="text" id="auto-add-keywords" placeholder="thank, thanks, thank you" value="thank, thanks">
                        <small>When someone sends a message containing these keywords, they'll be added to all your admin groups</small>
                    </div>
                </div>
                
                <div class="card" style="margin-top: 2rem;">
                    <div class="card-header">
                        <h3>Bot Activity Log</h3>
                    </div>
                    <div class="card-body">
                        <div id="bot-activity-log">
                            <p>No bot responses yet...</p>
                        </div>
                        <div style="margin-top: 1rem;">
                            <button id="test-bot" class="btn btn-secondary">
                                <i class="fas fa-play"></i> Test Bot
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function getTemplatesContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>📋 Message Templates</h3>
                <p>Create and manage reusable message templates</p>
            </div>
            <div class="card-body">
                <form id="template-form">
                    <div class="form-row">
                        <div class="form-group">
                            <label>Template Name</label>
                            <input type="text" id="template-name" placeholder="Welcome Message" required>
                        </div>
                        <div class="form-group">
                            <label>Category</label>
                            <select id="template-category">
                                <option value="marketing">Marketing</option>
                                <option value="support">Support</option>
                                <option value="notification">Notification</option>
                                <option value="greeting">Greeting</option>
                                <option value="other">Other</option>
                            </select>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label>Message Template</label>
                        <textarea id="template-message" rows="4" placeholder="Hello {name}, welcome to our service! Use code {code} for 20% off." required></textarea>
                        <small>Use {name}, {phone}, {code} for personalization</small>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i> Save Template
                    </button>
                </form>
                
                <div class="templates-list">
                    <h4>📋 Saved Templates</h4>
                    <div id="templates-container">
                        <p>No templates found. Create your first template above.</p>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function getSchedulerContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>📅 Message Scheduler</h3>
                <p>Schedule messages to be sent at specific times</p>
            </div>
            <div class="card-body">
                <form id="scheduler-form">
                    <div class="form-group">
                        <label>Recipients (one per line)</label>
                        <textarea id="schedule-numbers" rows="4" placeholder="1234567890\n0987654321" required></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>Message</label>
                        <textarea id="schedule-message" rows="3" placeholder="Your scheduled message..." required></textarea>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label>Schedule Date</label>
                            <input type="date" id="schedule-date" required>
                        </div>
                        <div class="form-group">
                            <label>Schedule Time</label>
                            <input type="time" id="schedule-time" required>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label>Repeat</label>
                        <select id="schedule-repeat">
                            <option value="none">No Repeat</option>
                            <option value="daily">Daily</option>
                            <option value="weekly">Weekly</option>
                            <option value="monthly">Monthly</option>
                        </select>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-clock"></i> Schedule Message
                    </button>
                </form>
                
                <div class="scheduled-messages">
                    <h4>📅 Scheduled Messages</h4>
                    <div id="scheduled-list">
                        <p>No scheduled messages found.</p>
                    </div>
                </div>
            </div>
        </div>
    `;
}



function getAnalyticsContent() {
    return `
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-paper-plane"></i>
                </div>
                <div class="stat-info">
                    <h4 id="analytics-total-messages">0</h4>
                    <p>Total Messages</p>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-users"></i>
                </div>
                <div class="stat-info">
                    <h4 id="analytics-bulk-campaigns">0</h4>
                    <p>Bulk Campaigns</p>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-bullhorn"></i>
                </div>
                <div class="stat-info">
                    <h4 id="analytics-group-broadcasts">0</h4>
                    <p>Group Broadcasts</p>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-broadcast-tower"></i>
                </div>
                <div class="stat-info">
                    <h4 id="analytics-contact-broadcasts">0</h4>
                    <p>Contact Broadcasts</p>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-download"></i>
                </div>
                <div class="stat-info">
                    <h4 id="analytics-numbers-extracted">0</h4>
                    <p>Numbers Extracted</p>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-robot"></i>
                </div>
                <div class="stat-info">
                    <h4 id="analytics-bot-replies">0</h4>
                    <p>Bot Replies</p>
                </div>
            </div>
        </div>
        

    `;
}

// Section-specific handlers
function setupConnectHandlers() {
    document.getElementById('connect-btn').addEventListener('click', connectWhatsApp);
}

function setupBulkMessageHandlers() {
    document.getElementById('bulk-message-form').addEventListener('submit', sendBulkMessages);
    
    // Message type tabs
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            switchMessageType(btn.dataset.type);
        });
    });
    
    // File upload handler
    document.getElementById('media-file').addEventListener('change', handleFileSelect);
    
    // Delay type toggle
    document.querySelectorAll('input[name="delayType"]').forEach(radio => {
        radio.addEventListener('change', toggleDelayInputs);
    });
}

function toggleDelayInputs() {
    const delayType = document.querySelector('input[name="delayType"]:checked').value;
    const fixedInput = document.getElementById('fixed-delay-input');
    const randomInputs = document.getElementById('random-delay-inputs');
    const randomInputsMax = document.getElementById('random-delay-inputs-max');
    
    if (delayType === 'fixed') {
        fixedInput.style.display = 'block';
        randomInputs.style.display = 'none';
        randomInputsMax.style.display = 'none';
    } else {
        fixedInput.style.display = 'none';
        randomInputs.style.display = 'block';
        randomInputsMax.style.display = 'block';
    }
}

async function connectWhatsApp() {
    const connectBtn = document.getElementById('connect-btn');
    connectBtn.disabled = true;
    connectBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Connecting...';
    
    try {
        const response = await fetch('/api/whatsapp/connect', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Initializing WhatsApp connection...', 'success');
            
            const placeholder = document.getElementById('qr-placeholder');
            if (placeholder) {
                placeholder.innerHTML = `
                    <i class="fas fa-spinner fa-spin"></i>
                    <p>Generating QR Code...</p>
                `;
            }
        } else {
            showToast(data.error || 'Failed to connect', 'error');
            resetConnectButton();
        }
    } catch (error) {
        showToast('Connection error', 'error');
        resetConnectButton();
    }
}

function resetConnectButton() {
    const connectBtn = document.getElementById('connect-btn');
    if (connectBtn) {
        connectBtn.disabled = false;
        connectBtn.innerHTML = '<i class="fas fa-link"></i> Connect WhatsApp';
    }
}

function switchMessageType(type) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector(`[data-type="${type}"]`).classList.add('active');
    
    const mediaUpload = document.getElementById('media-upload');
    const messageLabel = document.getElementById('message-label');
    const mediaFile = document.getElementById('media-file');
    
    if (type === 'text') {
        mediaUpload.style.display = 'none';
        messageLabel.textContent = 'Message';
        mediaFile.removeAttribute('accept');
    } else {
        mediaUpload.style.display = 'block';
        messageLabel.textContent = 'Caption (Optional)';
        
        switch(type) {
            case 'image':
                mediaFile.setAttribute('accept', 'image/*');
                break;
            case 'video':
                mediaFile.setAttribute('accept', 'video/*');
                break;
            case 'audio':
                mediaFile.setAttribute('accept', 'audio/*');
                break;
            case 'document':
                mediaFile.setAttribute('accept', '.pdf,.doc,.docx,.txt,.xlsx,.ppt');
                break;
        }
    }
}

function handleFileSelect(e) {
    const file = e.target.files[0];
    const fileInfo = document.getElementById('file-info');
    
    if (file) {
        const size = (file.size / 1024 / 1024).toFixed(2);
        fileInfo.innerHTML = `
            <div class="file-preview">
                <i class="fas fa-file"></i>
                <span>${file.name}</span>
                <small>(${size} MB)</small>
            </div>
        `;
        fileInfo.style.display = 'block';
    } else {
        fileInfo.style.display = 'none';
    }
}

async function sendSingleMessage(e) {
    e.preventDefault();
    
    const number = document.getElementById('single-number').value.trim();
    const message = document.getElementById('single-message').value;
    const messageType = document.querySelector('.tab-btn.active').dataset.type;
    const mediaFile = document.getElementById('single-media-file').files[0];
    
    if (!number) {
        showToast('Please enter a phone number', 'error');
        return;
    }
    
    if (messageType !== 'text' && messageType !== 'button' && !mediaFile) {
        showToast('Please select a media file', 'error');
        return;
    }
    
    // Create task
    const taskId = createTask('Single Message', 'single_message', {
        total: 1,
        canStop: false,
        canPause: false
    });
    window.currentTaskId = taskId;
    
    try {
        const formData = new FormData();
        formData.append('number', number);
        formData.append('message', message);
        formData.append('messageType', messageType);
        
        if (messageType === 'button') {
            const buttons = [];
            const btn1 = document.getElementById('button1-text')?.value?.trim();
            const btn2 = document.getElementById('button2-text')?.value?.trim();
            const btn3 = document.getElementById('button3-text')?.value?.trim();
            
            if (btn1) buttons.push(btn1);
            if (btn2) buttons.push(btn2);
            if (btn3) buttons.push(btn3);
            
            formData.append('buttons', JSON.stringify(buttons));
        }
        
        if (mediaFile) {
            formData.append('media', mediaFile);
        }
        
        const response = await fetch('/api/send-message', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            updateTask(taskId, { progress: 100, processed: 1, success: 1 });
            completeTask(taskId, 'completed');
            showToast('Message sent successfully! ✅', 'success');
            document.getElementById('single-message-form').reset();
            switchSingleMessageType('text');
        } else {
            updateTask(taskId, { progress: 100, processed: 1, failed: 1 });
            completeTask(taskId, 'error');
            showToast(data.error || 'Failed to send message', 'error');
        }
    } catch (error) {
        console.error('Send message error:', error);
        updateTask(taskId, { progress: 100, processed: 1, failed: 1 });
        completeTask(taskId, 'error');
        showToast('Error sending message', 'error');
    }
}

async function sendBulkMessages(e) {
    e.preventDefault();
    
    const numbersText = document.getElementById('bulk-numbers').value;
    const message = document.getElementById('bulk-message').value;
    const numbers = numbersText.split('\n').filter(n => n.trim());
    const messageType = document.querySelector('.tab-btn.active').dataset.type;
    const mediaFile = document.getElementById('media-file').files[0];
    
    // Store numbers for progress tracking
    window.currentBulkNumbers = numbers;
    
    const delayType = document.querySelector('input[name="delayType"]:checked')?.value || 'fixed';
    const fixedDelay = document.getElementById('fixed-delay-value')?.value || '5';
    const minDelay = document.getElementById('min-delay')?.value || '3';
    const maxDelay = document.getElementById('max-delay')?.value || '10';
    
    if (numbers.length === 0) {
        showToast('Please enter at least one phone number', 'error');
        return;
    }
    
    if (messageType !== 'text' && !mediaFile) {
        showToast('Please select a media file', 'error');
        return;
    }
    
    document.getElementById('bulk-progress').style.display = 'block';
    document.getElementById('bulk-results').style.display = 'none';
    
    // Create task in Task Manager
    const taskId = createTask('Bulk Message Campaign', 'bulk_message', {
        total: numbers.length,
        canStop: true,
        canPause: true
    });
    window.currentTaskId = taskId;
    
    // Initialize task manager if not exists
    if (!window.activeTasks) {
        window.activeTasks = new Map();
    }
    
    // Reset counters
    const successEl = document.getElementById('success-count');
    const failedEl = document.getElementById('failed-count');
    if (successEl) successEl.textContent = '0';
    if (failedEl) failedEl.textContent = '0';
    
    try {
        const formData = new FormData();
        formData.append('numbers', numbers.join('\n'));
        formData.append('message', message);
        formData.append('messageType', messageType);
        formData.append('delayType', delayType);
        formData.append('fixedDelay', fixedDelay);
        formData.append('minDelay', minDelay);
        formData.append('maxDelay', maxDelay);
        
        if (mediaFile) {
            formData.append('media', mediaFile);
        }
        
        const response = await fetch('/api/bulk-message', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayBulkResults(data.results);
            const successCount = data.results.filter(r => r.status === 'sent').length;
            
            // Update task manager
            if (window.currentTaskId) {
                updateTask(window.currentTaskId, {
                    progress: 100,
                    processed: data.results.length,
                    success: successCount,
                    failed: data.results.length - successCount
                });
                completeTask(window.currentTaskId, 'completed');
            }
            
            showToast(`Campaign completed! ${successCount}/${data.results.length} messages sent`, 'success');
        } else if (data.expired) {
            if (window.currentTaskId) {
                completeTask(window.currentTaskId, 'error');
            }
            showSubscriptionExpired();
            showToast('Subscription expired during operation', 'error');
        } else {
            if (window.currentTaskId) {
                completeTask(window.currentTaskId, 'error');
            }
            showToast(data.error || 'Bulk message failed', 'error');
        }
    } catch (error) {
        updateTaskPanel('Error', 0, { additionalInfo: 'Network or system error' });
        setTimeout(hideTaskPanel, 3000);
        showToast('Error sending bulk messages', 'error');
    }
}

async function loadContacts() {
    try {
        const response = await fetch('/api/contacts', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const contacts = await response.json();
        
        const container = document.getElementById('contacts-list');
        if (contacts.length === 0) {
            container.innerHTML = '<p>No contacts found. Connect WhatsApp first.</p>';
            return;
        }
        
        container.innerHTML = contacts.map(contact => {
            const lastMessage = contact.last_message_at ? new Date(contact.last_message_at).toLocaleDateString() : 'Never';
            const responseRate = contact.message_count > 0 ? Math.round((contact.response_count / contact.message_count) * 100) : 0;
            const statusColor = contact.status === 'active' ? '#10b981' : contact.status === 'blocked' ? '#ef4444' : '#6b7280';
            
            return `
                <div class="contact-item" style="padding: 1rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center;">
                    <div style="flex: 1;">
                        <h4>${contact.name || 'Unknown'}</h4>
                        <p>${contact.phone_number || contact.number}</p>
                        <div style="display: flex; gap: 1rem; margin-top: 0.5rem;">
                            <small style="color: ${statusColor};">● ${contact.status || 'active'}</small>
                            <small>📅 Last: ${lastMessage}</small>
                            <small>📊 Response: ${responseRate}%</small>
                            <small>💬 Messages: ${contact.message_count || 0}</small>
                        </div>
                    </div>
                    <div style="display: flex; gap: 0.5rem;">
                        <button class="btn btn-outline btn-small" onclick="addContactTag(${contact.id})">
                            🏷️ Tag
                        </button>
                        <button class="btn btn-outline btn-small" onclick="saveContactToGoogle('${contact.name || contact.phone_number}', '${contact.phone_number || contact.number}')">
                            📱 Save
                        </button>
                    </div>
                </div>
            `;
        }).join('');
        
    } catch (error) {
        document.getElementById('contacts-list').innerHTML = '<p>Error loading contacts</p>';
    }
}

async function loadGroups() {
    try {
        const response = await fetch('/api/groups', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const groups = await response.json();
        
        const container = document.getElementById('groups-list');
        if (groups.length === 0) {
            container.innerHTML = '<p>No groups found. Connect WhatsApp first.</p>';
            return;
        }
        
        container.innerHTML = groups.map(group => `
            <div class="group-item" style="padding: 1rem; border-bottom: 1px solid var(--border);">
                <h4>${group.name}</h4>
                <p>${group.participantCount} participants</p>
            </div>
        `).join('');
        
    } catch (error) {
        document.getElementById('groups-list').innerHTML = '<p>Error loading groups</p>';
    }
}

// Utility functions
function updateConnectionStatus(isConnected) {
    const statusElement = document.getElementById('connection-status');
    if (!statusElement) return;
    
    const dot = statusElement.querySelector('.status-dot');
    const text = statusElement.querySelector('span');
    
    if (isConnected) {
        dot.classList.add('online');
        text.textContent = 'Connected';
    } else {
        dot.classList.remove('online');
        text.textContent = 'Not Connected';
    }
}

function updateQRCode(qrData) {
    console.log('Updating QR code display');
    const qrCode = document.getElementById('qr-code');
    const qrPlaceholder = document.getElementById('qr-placeholder');
    const connectBtn = document.getElementById('connect-btn');
    
    if (qrCode && qrPlaceholder) {
        qrCode.src = qrData;
        qrCode.style.display = 'block';
        qrPlaceholder.style.display = 'none';
        
        if (connectBtn) {
            connectBtn.innerHTML = '<i class="fas fa-sync"></i> Refresh QR Code';
            connectBtn.disabled = false;
        }
    }
}

function hideQRCode() {
    const qrCode = document.getElementById('qr-code');
    const qrPlaceholder = document.getElementById('qr-placeholder');
    const connectBtn = document.getElementById('connect-btn');
    
    if (qrCode) qrCode.style.display = 'none';
    if (qrPlaceholder) {
        qrPlaceholder.innerHTML = `
            <i class="fas fa-check-circle" style="color: var(--success);"></i>
            <p>WhatsApp Connected Successfully!</p>
        `;
        qrPlaceholder.style.display = 'block';
    }
    if (connectBtn) {
        connectBtn.innerHTML = '<i class="fas fa-unlink"></i> Disconnect';
        connectBtn.onclick = disconnectWhatsApp;
    }
}

async function disconnectWhatsApp() {
    try {
        const response = await fetch('/api/whatsapp/disconnect', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            updateConnectionStatus(false);
            resetConnectButton();
            const qrPlaceholder = document.getElementById('qr-placeholder');
            if (qrPlaceholder) {
                qrPlaceholder.innerHTML = `
                    <i class="fas fa-qrcode"></i>
                    <p>Click "Connect WhatsApp" to generate QR code</p>
                `;
            }
            showToast('WhatsApp disconnected', 'success');
        }
    } catch (error) {
        showToast('Error disconnecting', 'error');
    }
}

function updateBulkProgress(data) {
    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');
    const successCount = document.getElementById('success-count');
    const failedCount = document.getElementById('failed-count');
    
    // Update counters first
    let currentSuccess = parseInt(successCount?.textContent || '0');
    let currentFailed = parseInt(failedCount?.textContent || '0');
    
    if (data.status === 'sent') {
        currentSuccess++;
        if (successCount) successCount.textContent = currentSuccess;
    } else if (data.status === 'failed') {
        currentFailed++;
        if (failedCount) failedCount.textContent = currentFailed;
    }
    
    // Update Task Manager
    if (window.currentTaskId) {
        const percentage = (data.current / data.total) * 100;
        updateTask(window.currentTaskId, {
            progress: percentage,
            processed: data.current,
            success: currentSuccess,
            failed: currentFailed,
            campaignId: data.campaignId
        });
    }
    
    if (progressFill && progressText) {
        const percentage = (data.current / data.total) * 100;
        progressFill.style.width = `${percentage}%`;
        progressText.innerHTML = `
            <div><strong>${parseInt(data.current)} / ${parseInt(data.total)}</strong> messages processed</div>
            <div>📱 Current: ${escapeHtml(data.number || '')}</div>
            <div>⏳ Remaining: ${parseInt(data.remaining || 0)}</div>
            <div>🕒 ETA: ${escapeHtml(data.eta || 'Calculating...')}</div>
        `;
        
        // Store campaign ID for stop functionality
        if (data.campaignId) {
            window.currentCampaignId = data.campaignId;
        }
    }
}

function displayBulkResults(results) {
    const resultsContainer = document.getElementById('bulk-results');
    const resultsList = document.getElementById('results-list');
    const totalSent = document.getElementById('total-sent');
    const finalSuccessRate = document.getElementById('final-success-rate');
    
    // Store results for download
    window.lastBulkResults = results;
    
    const successCount = results.filter(r => r.status === 'sent').length;
    const successRate = ((successCount / results.length) * 100).toFixed(1);
    
    totalSent.textContent = `${successCount}/${results.length}`;
    finalSuccessRate.textContent = `${successRate}%`;
    
    resultsList.innerHTML = results.map(result => `
        <div class="result-item" style="padding: 0.75rem; border-left: 3px solid ${result.status === 'sent' ? '#10b981' : '#ef4444'}; margin-bottom: 0.5rem; background: var(--surface); border-radius: 0.25rem; display: flex; justify-content: space-between; align-items: center;">
            <div>
                <strong>${result.number}</strong>
                <span class="status-badge ${result.status}">${result.status === 'sent' ? '✅ Delivered' : '❌ Failed'}</span>
            </div>
            ${result.error ? `<small style="color: var(--error); font-size: 0.8rem;">${result.error}</small>` : ''}
        </div>
    `).join('');
    
    resultsContainer.style.display = 'block';
    document.getElementById('bulk-progress').style.display = 'none';
}

function showLoading() {
    document.getElementById('loading-overlay').style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loading-overlay').style.display = 'none';
}

function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    document.getElementById('toast-container').appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

// Mobile Navigation Toggle
function toggleMobileNav() {
    const sidebar = document.querySelector('.sidebar');
    if (sidebar) {
        sidebar.classList.toggle('mobile-hidden');
    }
}

// Auto-hide mobile nav when clicking nav items
function navigateToSection(section) {
    // Update navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    document.querySelector(`[data-section="${section}"]`).classList.add('active');
    
    // Hide mobile nav after selection
    if (window.innerWidth <= 768) {
        const sidebar = document.querySelector('.sidebar');
        if (sidebar) {
            sidebar.classList.add('mobile-hidden');
        }
    }
    
    // Update page title
    const titles = {
        'overview': 'Overview',
        'connect': 'Connect WhatsApp',
        'single-message': 'Single Message',
        'bulk-message': 'Bulk Messages',
        'csv-sender': 'CSV Bulk Sender',
        'templates': 'Message Templates',
        'scheduler': 'Message Scheduler',
        'contacts': 'Contacts',
        'contact-broadcast': 'Contact Broadcast',
        'groups': 'Group Manager',
        'group-broadcast': 'Group Broadcast',
        'group-adder': 'Group Adder',
        'chatbot': 'Auto Chat Bot',
        'analytics': 'Analytics',
        'task-manager': 'Task Manager',
        'message-history': 'Message History',
        'link-generator': 'Link Generator', 
        'profile': 'Profile',
        'contact-us': 'Contact Us'
    };
    
    document.getElementById('page-title').textContent = titles[section] || 'Dashboard';
    currentSection = section;
    
    // Load section content
    loadSectionContent(section);
}

// Make functions global
window.showAuth = showAuth;
window.hideAuth = hideAuth;
window.toggleAuthMode = toggleAuthMode;
window.logout = logout;
window.navigateToSection = navigateToSection;
window.deleteRule = deleteRule;
window.switchMessageType = switchMessageType;
window.handleFileSelect = handleFileSelect;
window.toggleMobileNav = toggleMobileNav;

// CSV Sender Handlers
function setupCSVSenderHandlers() {
    document.getElementById('csv-file').addEventListener('change', handleCSVUpload);
    document.getElementById('download-template').addEventListener('click', downloadCSVTemplate);
    document.getElementById('send-csv-messages').addEventListener('click', sendCSVMessages);
}

function handleCSVUpload(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = function(e) {
        parseCSV(e.target.result);
    };
    reader.readAsText(file);
}

function parseCSV(csv) {
    const lines = csv.split('\n').filter(line => line.trim());
    const data = [];
    
    for (let i = 1; i < lines.length; i++) {
        const values = lines[i].split(',').map(v => v.trim());
        if (values.length >= 3) {
            data.push({ phone: values[0], name: values[1], message: values[2] });
        }
    }
    
    displayCSVPreview(data);
}

function displayCSVPreview(data) {
    const preview = document.getElementById('csv-preview');
    const table = document.getElementById('csv-table');
    const sendBtn = document.getElementById('send-csv-messages');
    
    let validCount = 0;
    
    table.innerHTML = `
        <thead><tr><th>Phone</th><th>Name</th><th>Message</th><th>Status</th></tr></thead>
        <tbody>
            ${data.map(row => {
                const isValid = /^[\d+\-\s()]+$/.test(row.phone) && row.phone.length >= 10;
                if (isValid) validCount++;
                return `
                    <tr class="${isValid ? 'valid' : 'invalid'}">
                        <td>${row.phone}</td>
                        <td>${row.name}</td>
                        <td>${row.message.substring(0, 50)}...</td>
                        <td>${isValid ? '✅ Valid' : '❌ Invalid'}</td>
                    </tr>
                `;
            }).join('')}
        </tbody>
    `;
    
    document.getElementById('csv-total').textContent = data.length;
    document.getElementById('csv-valid').textContent = validCount;
    document.getElementById('csv-invalid').textContent = data.length - validCount;
    
    preview.style.display = 'block';
    sendBtn.disabled = validCount === 0;
    
    window.csvData = data.filter(row => /^[\d+\-\s()]+$/.test(row.phone) && row.phone.length >= 10);
}

function downloadCSVTemplate() {
    const csv = 'phone,name,message\n1234567890,John Doe,Hello John! Special offer for you\n0987654321,Jane Smith,Hi Jane! Check our new products';
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'whatsapp_template.csv';
    a.click();
}

async function sendCSVMessages() {
    if (!window.csvData || window.csvData.length === 0) {
        showToast('No valid CSV data found', 'error');
        return;
    }
    
    document.getElementById('csv-progress').style.display = 'block';
    
    // Create task in Task Manager
    const taskId = createTask('CSV Message Campaign', 'csv_sender', {
        total: window.csvData.length,
        canStop: true,
        canPause: true
    });
    window.currentTaskId = taskId;
    
    let successCount = 0;
    let failedCount = 0;
    
    try {
        for (let i = 0; i < window.csvData.length; i++) {
            const row = window.csvData[i];
            const personalizedMessage = row.message.replace('{name}', row.name);
            
            const formData = new FormData();
            formData.append('number', row.phone);
            formData.append('message', personalizedMessage);
            formData.append('messageType', 'text');
            
            try {
                const response = await fetch('/api/send-message', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` },
                    body: formData
                });
                
                if (response.ok) {
                    successCount++;
                } else {
                    failedCount++;
                }
            } catch {
                failedCount++;
            }
            
            const progress = ((i + 1) / window.csvData.length) * 100;
            document.getElementById('csv-progress-fill').style.width = `${progress}%`;
            document.getElementById('csv-progress-text').textContent = `${i + 1} / ${window.csvData.length} messages sent`;
            
            // Update Task Manager
            updateTask(taskId, {
                progress: progress,
                processed: i + 1,
                success: successCount,
                failed: failedCount
            });
            
            // Add delay between messages
            const delay = 3000; // 3 seconds minimum
            await new Promise(resolve => setTimeout(resolve, delay));
        }
        
        completeTask(taskId, 'completed');
        showToast('CSV campaign completed!', 'success');
    } catch (error) {
        completeTask(taskId, 'error');
        showToast('Error sending CSV messages', 'error');
    }
}

// Templates
function setupTemplatesHandlers() {
    document.getElementById('template-form').addEventListener('submit', saveTemplate);
}

function saveTemplate(e) {
    e.preventDefault();
    const name = document.getElementById('template-name').value;
    const category = document.getElementById('template-category').value;
    const message = document.getElementById('template-message').value;
    
    const templates = JSON.parse(localStorage.getItem('templates') || '[]');
    templates.push({ id: Date.now(), name, category, message });
    localStorage.setItem('templates', JSON.stringify(templates));
    
    showToast('Template saved!', 'success');
    document.getElementById('template-form').reset();
    loadTemplates();
}

function loadTemplates() {
    const templates = JSON.parse(localStorage.getItem('templates') || '[]');
    const container = document.getElementById('templates-container');
    
    if (templates.length === 0) {
        container.innerHTML = '<p>No templates found.</p>';
        return;
    }
    
    container.innerHTML = templates.map(template => `
        <div class="template-item">
            <h4>${template.name}</h4>
            <p>${template.message}</p>
            <button class="btn btn-outline btn-small" onclick="useTemplate('${template.message}')">
                <i class="fas fa-copy"></i> Use
            </button>
            <button class="btn btn-outline btn-small" onclick="deleteTemplate(${template.id})">
                <i class="fas fa-trash"></i> Delete
            </button>
        </div>
    `).join('');
}

function useTemplate(message) {
    navigator.clipboard.writeText(message);
    showToast('Template copied!', 'success');
}

function deleteTemplate(id) {
    const templates = JSON.parse(localStorage.getItem('templates') || '[]');
    localStorage.setItem('templates', JSON.stringify(templates.filter(t => t.id !== id)));
    loadTemplates();
    showToast('Template deleted!', 'success');
}

// Scheduler
function setupSchedulerHandlers() {
    document.getElementById('scheduler-form').addEventListener('submit', scheduleMessage);
    document.getElementById('schedule-date').min = new Date().toISOString().split('T')[0];
}

function scheduleMessage(e) {
    e.preventDefault();
    const numbers = document.getElementById('schedule-numbers').value.split('\n').filter(n => n.trim());
    const message = document.getElementById('schedule-message').value;
    const date = document.getElementById('schedule-date').value;
    const time = document.getElementById('schedule-time').value;
    
    const scheduled = JSON.parse(localStorage.getItem('scheduled') || '[]');
    scheduled.push({ id: Date.now(), numbers, message, date, time, status: 'pending' });
    localStorage.setItem('scheduled', JSON.stringify(scheduled));
    
    showToast('Message scheduled!', 'success');
    document.getElementById('scheduler-form').reset();
    loadScheduledMessages();
}

function loadScheduledMessages() {
    const scheduled = JSON.parse(localStorage.getItem('scheduled') || '[]');
    const container = document.getElementById('scheduled-list');
    
    if (scheduled.length === 0) {
        container.innerHTML = '<p>No scheduled messages.</p>';
        return;
    }
    
    container.innerHTML = scheduled.map(item => `
        <div class="scheduled-item">
            <h4>${item.date} at ${item.time}</h4>
            <p>${item.message.substring(0, 100)}...</p>
            <small>Recipients: ${item.numbers.length}</small>
        </div>
    `).join('');
}



async function checkConnectionStatus() {
    if (!currentUser) return;
    
    try {
        const response = await fetch('/api/whatsapp/status', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        const data = await response.json();
        updateConnectionStatus(data.ready);
        
        if (data.qr && currentSection === 'connect') {
            updateQRCode(data.qr);
        }
    } catch (error) {
        console.error('Status check failed:', error);
    }
}

async function loadAnalytics() {
    try {
        const range = document.getElementById('analytics-range')?.value || 'all';
        const response = await fetch(`/api/analytics?range=${range}`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        console.log('Analytics data:', data);
        
        // Update analytics display with fallback values
        const elements = {
            'analytics-total-messages': data.totalMessages || 0,
            'analytics-bulk-campaigns': data.bulkCampaigns || 0,
            'analytics-group-broadcasts': data.groupBroadcasts || 0,
            'analytics-contact-broadcasts': data.contactBroadcasts || 0,
            'analytics-numbers-extracted': data.numbersExtracted || 0,
            'analytics-bot-replies': data.botReplies || 0
        };
        
        Object.entries(elements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value;
                console.log(`Updated ${id} with value:`, value);
            }
        });
        
        // Update overview stats too
        const overviewElements = {
            'total-messages': data.totalMessages || 0,
            'total-contacts': data.contactsAccessed || 0,
            'success-rate': data.totalMessages > 0 ? Math.round(((data.totalMessages - (data.failed || 0)) / data.totalMessages) * 100) + '%' : '0%',
            'campaigns-today': data.bulkCampaigns || 0
        };
        
        Object.entries(overviewElements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value;
                console.log(`Updated overview ${id} with value:`, value);
            }
        });
        
        console.log('Analytics loaded successfully');
        
    } catch (error) {
        console.error('Analytics error:', error);
        // Set default values on error
        const defaultElements = {
            'analytics-total-messages': 0,
            'analytics-bulk-campaigns': 0,
            'analytics-group-broadcasts': 0,
            'analytics-contact-broadcasts': 0,
            'analytics-numbers-extracted': 0,
            'analytics-bot-replies': 0,
            'total-messages': 0,
            'total-contacts': 0,
            'success-rate': '0%',
            'campaigns-today': 0
        };
        
        Object.entries(defaultElements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) element.textContent = value;
        });
    }
}

// Single Message
function getSingleMessageContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>📱 Send Single Message</h3>
            </div>
            <div class="card-body">
                <form id="single-message-form" enctype="multipart/form-data">
                    <div class="form-group">
                        <label>Message Type</label>
                        <div class="message-type-tabs">
                            <button type="button" class="tab-btn active" data-type="text">📝 Text</button>
                            <button type="button" class="tab-btn" data-type="image">🖼️ Image</button>
                            <button type="button" class="tab-btn" data-type="video">🎥 Video</button>
                            <button type="button" class="tab-btn" data-type="audio">🎵 Audio</button>
                            <button type="button" class="tab-btn" data-type="document">📄 Document</button>
                            <button type="button" class="tab-btn" data-type="button">🔘 Button</button>
                        </div>
                    </div>
                    
                    <div id="single-media-upload" style="display: none;">
                        <div class="form-group">
                            <label>Select Media File</label>
                            <input type="file" id="single-media-file" accept="*/*">
                            <div class="file-info" id="single-file-info" style="display: none;"></div>
                        </div>
                    </div>
                    
                    <div id="button-section" style="display: none;">
                        <div class="form-group">
                            <label>Button 1 Text</label>
                            <input type="text" id="button1-text" placeholder="Call Now">
                        </div>
                        <div class="form-group">
                            <label>Button 2 Text (Optional)</label>
                            <input type="text" id="button2-text" placeholder="Visit Website">
                        </div>
                        <div class="form-group">
                            <label>Button 3 Text (Optional)</label>
                            <input type="text" id="button3-text" placeholder="More Info">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label>Phone Number</label>
                        <input type="text" id="single-number" placeholder="1234567890 or +1234567890" required>
                        <small>Enter phone number with or without country code</small>
                    </div>
                    
                    <div class="form-group">
                        <label id="single-message-label">Message</label>
                        <textarea id="single-message" rows="4" placeholder="Enter your message..." required></textarea>
                        <small>For media messages, this will be used as caption</small>
                    </div>
                    
                    <button type="submit" class="btn btn-primary btn-large">
                        <i class="fas fa-paper-plane"></i> Send Message
                    </button>
                </form>
            </div>
        </div>
    `;
}

function setupSingleMessageHandlers() {
    document.getElementById('single-message-form').addEventListener('submit', sendSingleMessage);
    
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            switchSingleMessageType(btn.dataset.type);
        });
    });
    
    document.getElementById('single-media-file').addEventListener('change', handleSingleFileSelect);
}

function switchSingleMessageType(type) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector(`[data-type="${type}"]`).classList.add('active');
    
    const mediaUpload = document.getElementById('single-media-upload');
    const messageLabel = document.getElementById('single-message-label');
    const mediaFile = document.getElementById('single-media-file');
    const buttonSection = document.getElementById('button-section');
    
    if (type === 'text') {
        mediaUpload.style.display = 'none';
        if (buttonSection) buttonSection.style.display = 'none';
        messageLabel.textContent = 'Message';
        mediaFile.removeAttribute('accept');
    } else if (type === 'button') {
        mediaUpload.style.display = 'none';
        if (buttonSection) buttonSection.style.display = 'block';
        messageLabel.textContent = 'Message';
    } else {
        mediaUpload.style.display = 'block';
        if (buttonSection) buttonSection.style.display = 'none';
        messageLabel.textContent = 'Caption (Optional)';
        
        switch(type) {
            case 'image':
                mediaFile.setAttribute('accept', 'image/*');
                break;
            case 'video':
                mediaFile.setAttribute('accept', 'video/*');
                break;
            case 'audio':
                mediaFile.setAttribute('accept', 'audio/*');
                break;
            case 'document':
                mediaFile.setAttribute('accept', '.pdf,.doc,.docx,.txt,.xlsx,.ppt');
                break;
        }
    }
}

function handleSingleFileSelect(e) {
    const file = e.target.files[0];
    const fileInfo = document.getElementById('single-file-info');
    
    if (file) {
        const size = (file.size / 1024 / 1024).toFixed(2);
        fileInfo.innerHTML = `
            <div class="file-preview">
                <i class="fas fa-file"></i>
                <span>${file.name}</span>
                <small>(${size} MB)</small>
            </div>
        `;
        fileInfo.style.display = 'block';
    } else {
        fileInfo.style.display = 'none';
    }
}

window.useTemplate = useTemplate;
window.deleteTemplate = deleteTemplate;

// Test analytics function
async function testAnalytics() {
    console.log('Testing analytics...');
    try {
        const response = await fetch('/api/analytics?range=all', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        console.log('Response status:', response.status);
        const data = await response.json();
        console.log('Analytics test data:', data);
        
        if (data.totalMessages !== undefined) {
            showToast(`Analytics working! Total messages: ${data.totalMessages}`, 'success');
        } else {
            showToast('Analytics response missing data', 'error');
        }
    } catch (error) {
        console.error('Analytics test error:', error);
        showToast('Analytics test failed: ' + error.message, 'error');
    }
}

window.loadAnalytics = loadAnalytics;
window.testAnalytics = testAnalytics;
window.switchSingleMessageType = switchSingleMessageType;
window.handleSingleFileSelect = handleSingleFileSelect;
// Group Management Functions
async function loadGroups() {
    try {
        const response = await fetch('/api/groups', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const groups = await response.json();
        
        const container = document.getElementById('groups-list');
        if (groups.length === 0) {
            container.innerHTML = '<p>No groups found. Connect WhatsApp first.</p>';
            return;
        }
        
        container.innerHTML = groups.map(group => {
            const permissionColor = group.canAddMembers ? (group.isAdmin ? '#10b981' : '#3b82f6') : '#ef4444';
            const permissionIcon = group.canAddMembers ? (group.isAdmin ? '👑' : '✅') : '❌';
            
            return `
                <div class="group-item" style="padding: 1rem; border: 1px solid var(--border); margin: 0.5rem 0; border-radius: 0.5rem; background: var(--surface);">
                    <div class="group-info" style="flex: 1;">
                        <div style="display: flex; justify-content: between; align-items: start; margin-bottom: 0.5rem;">
                            <h4 style="margin: 0; flex: 1;">${escapeHtml(group.name)}</h4>
                            <div style="display: flex; gap: 0.5rem; align-items: center;">
                                <span class="permission-badge" style="background: ${permissionColor}; color: white; padding: 0.2rem 0.5rem; border-radius: 0.25rem; font-size: 0.7rem; font-weight: bold;">
                                    ${permissionIcon} ${group.addPermission}
                                </span>
                                ${group.isSuperAdmin ? '<span class="super-admin-badge" style="background: #8b5cf6; color: white; padding: 0.2rem 0.5rem; border-radius: 0.25rem; font-size: 0.7rem; margin-left: 0.25rem;">👑 Super Admin</span>' : 
                                  group.isAdmin ? '<span class="admin-badge" style="background: #10b981; color: white; padding: 0.2rem 0.5rem; border-radius: 0.25rem; font-size: 0.7rem; margin-left: 0.25rem;">🛡️ Admin</span>' : 
                                  '<span class="member-badge" style="background: #6b7280; color: white; padding: 0.2rem 0.5rem; border-radius: 0.25rem; font-size: 0.7rem; margin-left: 0.25rem;">👤 Member</span>'}
                            </div>
                        </div>
                        <div style="display: flex; gap: 1rem; margin-bottom: 0.5rem; font-size: 0.9rem; color: var(--text-secondary);">
                            <span>👥 ${group.participantCount} participants</span>
                            <span>🔒 ${group.restrictedGroup ? 'Restricted' : 'Open'}</span>
                            <span>📋 Role: ${group.memberRole}</span>
                        </div>
                        ${group.description ? `<p style="margin: 0; font-size: 0.8rem; color: var(--text-secondary);">${escapeHtml(group.description)}</p>` : ''}
                        ${group.error ? `<p style="margin: 0.5rem 0 0 0; font-size: 0.8rem; color: #ef4444;">⚠️ ${escapeHtml(group.error)}</p>` : ''}
                    </div>
                    <div class="group-actions" style="display: flex; gap: 0.5rem; margin-top: 1rem; flex-wrap: wrap;">
                        <button class="btn btn-outline btn-small" onclick="viewGroupParticipants('${group.id}', '${escapeHtml(group.name)}')">
                            👥 View Members
                        </button>
                        <button class="btn btn-outline btn-small" onclick="extractGroupNumbers('${group.id}', '${escapeHtml(group.name)}')">
                            📱 Extract Numbers
                        </button>
                        <button class="btn btn-primary btn-small" onclick="sendGroupMessage('${group.id}', '${escapeHtml(group.name)}')">
                            💬 Send Message
                        </button>
                        ${group.canAddMembers ? `
                            <button class="btn btn-success btn-small" onclick="showAddToGroupModal('${group.id}', '${escapeHtml(group.name)}', ${group.isAdmin})" style="background: #10b981; color: white;">
                                ➕ Add Members
                            </button>
                        ` : `
                            <button class="btn btn-outline btn-small" disabled title="No permission to add members">
                                🚫 Can't Add
                            </button>
                        `}
                    </div>
                </div>
            `;
        }).join('');
        
    } catch (error) {
        document.getElementById('groups-list').innerHTML = '<p>Error loading groups</p>';
    }
}

async function viewGroupParticipants(groupId, groupName) {
    try {
        const response = await fetch(`/api/groups/${groupId}/participants`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const participants = await response.json();
        
        const modal = document.createElement('div');
        modal.className = 'modal show';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>👥 ${groupName} Members</h3>
                    <button onclick="this.closest('.modal').remove()">×</button>
                </div>
                <div class="modal-body">
                    <div class="participants-list">
                        ${participants.map(p => `
                            <div class="participant-item">
                                <span>${p.name || p.number}</span>
                                <span class="participant-number">${p.number}</span>
                                ${p.isAdmin ? '<span class="admin-badge">Admin</span>' : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        
    } catch (error) {
        showToast('Error loading participants', 'error');
    }
}

async function extractGroupNumbers(groupId, groupName) {
    try {
        const response = await fetch(`/api/groups/${groupId}/extract-numbers`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const data = await response.json();
        
        const numbersDisplay = document.getElementById('numbers-display');
        numbersDisplay.innerHTML = `
            <h4>📱 Numbers from ${groupName}</h4>
            <p>Total: ${data.count} numbers</p>
            <div class="numbers-grid">
                ${data.numbers.map(num => `<span class="number-chip">${num}</span>`).join('')}
            </div>
            <div class="extract-actions">
                <button class="btn btn-primary" onclick="copyNumbers('${data.numbers.join('\\n')}')">
                    📋 Copy All
                </button>
                <button class="btn btn-outline" onclick="downloadGroupCSV('${groupId}', '${groupName}')">
                    📥 Download CSV
                </button>
            </div>
        `;
        
        document.getElementById('extracted-numbers').style.display = 'block';
        showToast(`Extracted ${data.count} numbers from ${groupName}`, 'success');
        
    } catch (error) {
        showToast('Error extracting numbers', 'error');
    }
}

async function extractAllNumbers() {
    try {
        const response = await fetch('/api/groups/extract-all-numbers', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const data = await response.json();
        
        const numbersDisplay = document.getElementById('numbers-display');
        numbersDisplay.innerHTML = `
            <h4>📱 All Group Numbers</h4>
            <div class="numbers-stats">
                <span class="stat">Total Unique: ${data.totalUniqueNumbers}</span>
                <span class="stat">Total Numbers: ${data.totalNumbers}</span>
                <span class="stat">Groups: ${data.groups.length}</span>
            </div>
            <div class="groups-breakdown">
                ${data.groups.map(group => `
                    <div class="group-breakdown">
                        <h5>${group.groupName} (${group.count})</h5>
                        <div class="numbers-preview">
                            ${group.numbers.slice(0, 5).map(num => `<span class="number-chip">${num}</span>`).join('')}
                            ${group.count > 5 ? `<span class="more-numbers">+${group.count - 5} more</span>` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
            <div class="extract-actions">
                <button class="btn btn-primary" onclick="copyNumbers('${data.uniqueNumbers.join('\\n')}')">
                    📋 Copy Unique Numbers
                </button>
                <button class="btn btn-outline" onclick="downloadAllNumbersCSV()">
                    📥 Download All CSV
                </button>
            </div>
        `;
        
        document.getElementById('extracted-numbers').style.display = 'block';
        showToast(`Extracted ${data.totalUniqueNumbers} unique numbers from ${data.groups.length} groups`, 'success');
        
    } catch (error) {
        showToast('Error extracting numbers', 'error');
    }
}

function copyNumbers(numbers) {
    navigator.clipboard.writeText(numbers);
    showToast('Numbers copied to clipboard!', 'success');
}

async function downloadGroupCSV(groupId, groupName) {
    try {
        const response = await fetch(`/api/groups/${groupId}/extract-numbers?format=csv`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${groupName}_numbers.csv`;
        a.click();
        
        showToast('CSV downloaded!', 'success');
    } catch (error) {
        showToast('Error downloading CSV', 'error');
    }
}

async function downloadAllNumbersCSV() {
    try {
        const response = await fetch('/api/groups/extract-all-numbers?format=csv', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'all_groups_numbers.csv';
        a.click();
        
        showToast('All numbers CSV downloaded!', 'success');
    } catch (error) {
        showToast('Error downloading CSV', 'error');
    }
}

// Group Broadcast Functions
function setupGroupBroadcastHandlers() {
    document.getElementById('group-broadcast-form').addEventListener('submit', sendGroupBroadcast);
    document.getElementById('select-all-groups').addEventListener('change', toggleAllGroups);
    
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            switchBroadcastMessageType(btn.dataset.type);
        });
    });
    
    document.getElementById('broadcast-media-file').addEventListener('change', handleBroadcastFileSelect);
    
    document.querySelectorAll('input[name="broadcastDelayType"]').forEach(radio => {
        radio.addEventListener('change', toggleBroadcastDelayInputs);
    });
}

async function loadGroupsForBroadcast() {
    try {
        const response = await fetch('/api/groups', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const groups = await response.json();
        
        const container = document.getElementById('groups-checkboxes');
        if (groups.length === 0) {
            container.innerHTML = '<p>No groups found. Connect WhatsApp first.</p>';
            return;
        }
        
        container.innerHTML = groups.map(group => `
            <div class="group-checkbox">
                <input type="checkbox" id="group-${group.id}" value="${group.id}">
                <label for="group-${group.id}">
                    <strong>${group.name}</strong>
                    <span>(${group.participantCount} members)</span>
                </label>
            </div>
        `).join('');
        
    } catch (error) {
        document.getElementById('groups-checkboxes').innerHTML = '<p>Error loading groups</p>';
    }
}

function toggleAllGroups() {
    const selectAll = document.getElementById('select-all-groups').checked;
    document.querySelectorAll('#groups-checkboxes input[type="checkbox"]').forEach(checkbox => {
        checkbox.checked = selectAll;
    });
}

function switchBroadcastMessageType(type) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector(`[data-type="${type}"]`).classList.add('active');
    
    const mediaUpload = document.getElementById('broadcast-media-upload');
    const messageLabel = document.getElementById('broadcast-message-label');
    const mediaFile = document.getElementById('broadcast-media-file');
    
    if (type === 'text') {
        mediaUpload.style.display = 'none';
        messageLabel.textContent = 'Message';
    } else {
        mediaUpload.style.display = 'block';
        messageLabel.textContent = 'Caption (Optional)';
        
        switch(type) {
            case 'image': mediaFile.setAttribute('accept', 'image/*'); break;
            case 'video': mediaFile.setAttribute('accept', 'video/*'); break;
            case 'audio': mediaFile.setAttribute('accept', 'audio/*'); break;
            case 'document': mediaFile.setAttribute('accept', '.pdf,.doc,.docx,.txt,.xlsx,.ppt'); break;
        }
    }
}

function handleBroadcastFileSelect(e) {
    const file = e.target.files[0];
    const fileInfo = document.getElementById('broadcast-file-info');
    
    if (file) {
        const size = (file.size / 1024 / 1024).toFixed(2);
        fileInfo.innerHTML = `
            <div class="file-preview">
                <i class="fas fa-file"></i>
                <span>${file.name}</span>
                <small>(${size} MB)</small>
            </div>
        `;
        fileInfo.style.display = 'block';
    } else {
        fileInfo.style.display = 'none';
    }
}

function toggleBroadcastDelayInputs() {
    const delayType = document.querySelector('input[name="broadcastDelayType"]:checked').value;
    const fixedInput = document.getElementById('broadcast-fixed-delay-input');
    const randomInputs = document.getElementById('broadcast-random-delay-inputs');
    const randomInputsMax = document.getElementById('broadcast-random-delay-inputs-max');
    
    if (delayType === 'fixed') {
        fixedInput.style.display = 'block';
        randomInputs.style.display = 'none';
        randomInputsMax.style.display = 'none';
    } else {
        fixedInput.style.display = 'none';
        randomInputs.style.display = 'block';
        randomInputsMax.style.display = 'block';
    }
}

async function sendGroupBroadcast(e) {
    e.preventDefault();
    
    const selectedGroups = Array.from(document.querySelectorAll('#groups-checkboxes input[type="checkbox"]:checked'))
        .map(cb => cb.value);
    
    if (selectedGroups.length === 0) {
        showToast('Please select at least one group', 'error');
        return;
    }
    
    const message = document.getElementById('broadcast-message').value;
    const messageType = document.querySelector('.tab-btn.active').dataset.type;
    const mediaFile = document.getElementById('broadcast-media-file').files[0];
    
    const delayType = document.querySelector('input[name="broadcastDelayType"]:checked').value;
    const fixedDelay = document.getElementById('broadcast-fixed-delay-value').value;
    const minDelay = document.getElementById('broadcast-min-delay').value;
    const maxDelay = document.getElementById('broadcast-max-delay').value;
    
    if (messageType !== 'text' && !mediaFile) {
        showToast('Please select a media file', 'error');
        return;
    }
    
    document.getElementById('broadcast-progress').style.display = 'block';
    
    // Create task in Task Manager
    const taskId = createTask('Group Broadcast Campaign', 'group_broadcast', {
        total: selectedGroups.length,
        canStop: true,
        canPause: true
    });
    window.currentTaskId = taskId;
    document.getElementById('broadcast-results').style.display = 'none';
    
    document.getElementById('broadcast-success-count').textContent = '0';
    document.getElementById('broadcast-failed-count').textContent = '0';
    
    try {
        const formData = new FormData();
        formData.append('message', message);
        formData.append('messageType', messageType);
        formData.append('selectedGroups', JSON.stringify(selectedGroups));
        formData.append('delayType', delayType);
        formData.append('fixedDelay', fixedDelay);
        formData.append('minDelay', minDelay);
        formData.append('maxDelay', maxDelay);
        formData.append('mentionAll', document.getElementById('mention-all-broadcast').checked);
        
        if (mediaFile) {
            formData.append('media', mediaFile);
        }
        
        const response = await fetch('/api/groups/broadcast', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayBroadcastResults(data.results);
            const successCount = data.results.filter(r => r.status === 'sent').length;
            
            // Update task manager
            if (window.currentTaskId) {
                updateTask(window.currentTaskId, {
                    progress: 100,
                    processed: data.results.length,
                    success: successCount,
                    failed: data.results.length - successCount
                });
                completeTask(window.currentTaskId, 'completed');
            }
            
            showToast(`Broadcast completed! ${successCount}/${data.results.length} groups reached`, 'success');
        } else {
            if (window.currentTaskId) {
                completeTask(window.currentTaskId, 'error');
            }
            showToast(data.error || 'Broadcast failed', 'error');
        }
    } catch (error) {
        if (window.currentTaskId) {
            completeTask(window.currentTaskId, 'error');
        }
        showToast('Error sending broadcast', 'error');
    }
}

function displayBroadcastResults(results) {
    const resultsContainer = document.getElementById('broadcast-results');
    const resultsList = document.getElementById('broadcast-results-list');
    
    resultsList.innerHTML = results.map(result => `
        <div class="result-item" style="padding: 0.75rem; border-left: 3px solid ${result.status === 'sent' ? '#10b981' : '#ef4444'}; margin-bottom: 0.5rem; background: var(--surface); border-radius: 0.25rem;">
            <div>
                <strong>${result.groupName}</strong>
                <span class="status-badge ${result.status}">${result.status === 'sent' ? '✅ Sent' : '❌ Failed'}</span>
            </div>
            ${result.error ? `<small style="color: var(--error);">${result.error}</small>` : ''}
        </div>
    `).join('');
    
    resultsContainer.style.display = 'block';
    document.getElementById('broadcast-progress').style.display = 'none';
}

// Socket event for broadcast progress
if (socket) {
    socket.on('broadcast-progress', (data) => {
        const progressFill = document.getElementById('broadcast-progress-fill');
        const progressText = document.getElementById('broadcast-progress-text');
        const successCount = document.getElementById('broadcast-success-count');
        const failedCount = document.getElementById('broadcast-failed-count');
        
        // Update Task Manager
        if (window.currentTaskId) {
            const percentage = (data.current / data.total) * 100;
            let currentSuccess = parseInt(successCount?.textContent || '0');
            let currentFailed = parseInt(failedCount?.textContent || '0');
            
            if (data.status === 'sent') currentSuccess++;
            else if (data.status === 'failed') currentFailed++;
            
            updateTask(window.currentTaskId, {
                progress: percentage,
                processed: data.current,
                success: currentSuccess,
                failed: currentFailed
            });
        }
        
        if (progressFill && progressText) {
            const percentage = (data.current / data.total) * 100;
            progressFill.style.width = `${percentage}%`;
            progressText.textContent = `${data.current} / ${data.total} groups`;
            
            if (data.status === 'sent') {
                successCount.textContent = parseInt(successCount.textContent) + 1;
            } else if (data.status === 'failed') {
                failedCount.textContent = parseInt(failedCount.textContent) + 1;
            }
        }
    });
}

// Global functions
window.viewGroupParticipants = viewGroupParticipants;
window.extractGroupNumbers = extractGroupNumbers;
window.extractAllNumbers = extractAllNumbers;
window.copyNumbers = copyNumbers;
window.downloadGroupCSV = downloadGroupCSV;
window.downloadAllNumbersCSV = downloadAllNumbersCSV;
window.sendGroupMessage = sendGroupMessage;
window.toggleAllGroups = toggleAllGroups;

function showCreateGroupModal() {
    const modal = document.createElement('div');
    modal.className = 'modal show';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>👥 Create New WhatsApp Group</h3>
                <button onclick="this.closest('.modal').remove()">×</button>
            </div>
            <div class="modal-body">
                <form id="create-group-form">
                    <div class="form-group">
                        <label>Group Name:</label>
                        <input type="text" id="group-name" placeholder="My New Group" required>
                    </div>
                    <div class="form-group">
                        <label>Phone Numbers (one per line):</label>
                        <textarea id="group-numbers" rows="6" placeholder="1234567890\n0987654321\n+1234567890" required></textarea>
                        <small>Enter phone numbers with or without country codes</small>
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn btn-outline" onclick="this.closest('.modal').remove()">Cancel</button>
                        <button type="submit" class="btn btn-primary">Create Group</button>
                    </div>
                </form>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    document.getElementById('create-group-form').onsubmit = createWhatsAppGroup;
}

async function createWhatsAppGroup(e) {
    e.preventDefault();
    
    const groupName = document.getElementById('group-name').value;
    const numbersText = document.getElementById('group-numbers').value;
    const numbers = numbersText.split('\n').filter(n => n.trim());
    
    if (numbers.length === 0) {
        showToast('Please enter at least one phone number', 'error');
        return;
    }
    
    try {
        showLoading();
        
        const response = await fetch('/api/groups/create', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ groupName, numbers })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast(`Group "${data.groupName}" created with ${data.participantCount} members!`, 'success');
            document.querySelector('.modal').remove();
            loadGroupsForBroadcast();
        } else {
            showToast(data.error || 'Failed to create group', 'error');
        }
    } catch (error) {
        showToast('Error creating group', 'error');
    }
    
    hideLoading();
}

window.showCreateGroupModal = showCreateGroupModal;
window.createWhatsAppGroup = createWhatsAppGroup;
function getContactBroadcastContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>📢 Contact Broadcast</h3>
                <p>Send messages to all your contacts at once</p>
            </div>
            <div class="card-body">
                <form id="contact-broadcast-form" enctype="multipart/form-data">
                    <div class="form-group">
                        <label>Message Type</label>
                        <div class="message-type-tabs">
                            <button type="button" class="tab-btn active" data-type="text">📝 Text</button>
                            <button type="button" class="tab-btn" data-type="image">🖼️ Image</button>
                            <button type="button" class="tab-btn" data-type="video">🎥 Video</button>
                            <button type="button" class="tab-btn" data-type="audio">🎵 Audio</button>
                            <button type="button" class="tab-btn" data-type="document">📄 Document</button>
                            <button type="button" class="tab-btn" data-type="button">🔘 Button</button>
                        </div>
                    </div>
                    
                    <div id="contact-media-upload" style="display: none;">
                        <div class="form-group">
                            <label>Select Media File</label>
                            <input type="file" id="contact-media-file" accept="*/*">
                            <div class="file-info" id="contact-file-info" style="display: none;"></div>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label id="contact-message-label">Message</label>
                        <textarea id="contact-message" rows="4" placeholder="Enter your broadcast message..." required></textarea>
                        <small>This message will be sent to all your contacts</small>
                    </div>
                    
                    <div class="timing-controls">
                        <h4>⏱️ Timing Controls</h4>
                        <div class="timing-options">
                            <div class="timing-option">
                                <input type="radio" id="contact-fixed-delay" name="contactDelayType" value="fixed" checked>
                                <label for="contact-fixed-delay">Fixed Delay</label>
                            </div>
                            <div class="timing-option">
                                <input type="radio" id="contact-random-delay" name="contactDelayType" value="random">
                                <label for="contact-random-delay">Random Delay</label>
                            </div>
                        </div>
                        
                        <div class="delay-inputs">
                            <div class="form-group" id="contact-fixed-delay-input">
                                <label>Delay (seconds)</label>
                                <input type="number" id="contact-fixed-delay-value" min="2" max="300" value="5">
                            </div>
                            <div class="form-group" id="contact-random-delay-inputs" style="display: none;">
                                <label>Min Delay (seconds)</label>
                                <input type="number" id="contact-min-delay" min="2" max="300" value="3">
                            </div>
                            <div class="form-group" id="contact-random-delay-inputs-max" style="display: none;">
                                <label>Max Delay (seconds)</label>
                                <input type="number" id="contact-max-delay" min="2" max="300" value="10">
                            </div>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary btn-large">
                        <i class="fas fa-bullhorn"></i> Send to All Contacts
                    </button>
                </form>
                
                <div id="contact-progress" style="display: none;">
                    <div class="progress-container">
                        <div class="progress-header">
                            <h4>📢 Broadcasting to Contacts...</h4>
                            <button id="stop-contact-broadcast" class="btn btn-outline btn-small">Stop</button>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" id="contact-progress-fill"></div>
                        </div>
                        <div class="progress-stats">
                            <div class="progress-text" id="contact-progress-text">0 / 0 contacts</div>
                            <div class="progress-details">
                                <span class="success-count">✅ <span id="contact-success-count">0</span></span>
                                <span class="failed-count">❌ <span id="contact-failed-count">0</span></span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div id="contact-results" style="display: none;">
                    <div class="results-header">
                        <h4>📊 Contact Broadcast Results</h4>
                    </div>
                    <div id="contact-results-list"></div>
                </div>
            </div>
        </div>
    `;
}

function setupContactBroadcastHandlers() {
    document.getElementById('contact-broadcast-form').addEventListener('submit', sendContactBroadcast);
    
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            switchContactMessageType(btn.dataset.type);
        });
    });
    
    document.getElementById('contact-media-file').addEventListener('change', handleContactFileSelect);
    
    document.querySelectorAll('input[name="contactDelayType"]').forEach(radio => {
        radio.addEventListener('change', toggleContactDelayInputs);
    });
}

function switchContactMessageType(type) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector(`[data-type="${type}"]`).classList.add('active');
    
    const mediaUpload = document.getElementById('contact-media-upload');
    const messageLabel = document.getElementById('contact-message-label');
    const mediaFile = document.getElementById('contact-media-file');
    
    if (type === 'text') {
        mediaUpload.style.display = 'none';
        messageLabel.textContent = 'Message';
    } else {
        mediaUpload.style.display = 'block';
        messageLabel.textContent = 'Caption (Optional)';
        
        switch(type) {
            case 'image': mediaFile.setAttribute('accept', 'image/*'); break;
            case 'video': mediaFile.setAttribute('accept', 'video/*'); break;
            case 'audio': mediaFile.setAttribute('accept', 'audio/*'); break;
            case 'document': mediaFile.setAttribute('accept', '.pdf,.doc,.docx,.txt,.xlsx,.ppt'); break;
        }
    }
}

function handleContactFileSelect(e) {
    const file = e.target.files[0];
    const fileInfo = document.getElementById('contact-file-info');
    
    if (file) {
        const size = (file.size / 1024 / 1024).toFixed(2);
        fileInfo.innerHTML = `
            <div class="file-preview">
                <i class="fas fa-file"></i>
                <span>${file.name}</span>
                <small>(${size} MB)</small>
            </div>
        `;
        fileInfo.style.display = 'block';
    } else {
        fileInfo.style.display = 'none';
    }
}

function toggleContactDelayInputs() {
    const delayType = document.querySelector('input[name="contactDelayType"]:checked').value;
    const fixedInput = document.getElementById('contact-fixed-delay-input');
    const randomInputs = document.getElementById('contact-random-delay-inputs');
    const randomInputsMax = document.getElementById('contact-random-delay-inputs-max');
    
    if (delayType === 'fixed') {
        fixedInput.style.display = 'block';
        randomInputs.style.display = 'none';
        randomInputsMax.style.display = 'none';
    } else {
        fixedInput.style.display = 'none';
        randomInputs.style.display = 'block';
        randomInputsMax.style.display = 'block';
    }
}

async function sendContactBroadcast(e) {
    e.preventDefault();
    
    const message = document.getElementById('contact-message').value;
    const messageType = document.querySelector('.tab-btn.active').dataset.type;
    const mediaFile = document.getElementById('contact-media-file').files[0];
    
    const delayType = document.querySelector('input[name="contactDelayType"]:checked').value;
    const fixedDelay = document.getElementById('contact-fixed-delay-value').value;
    const minDelay = document.getElementById('contact-min-delay').value;
    const maxDelay = document.getElementById('contact-max-delay').value;
    
    if (messageType !== 'text' && !mediaFile) {
        showToast('Please select a media file', 'error');
        return;
    }
    
    document.getElementById('contact-progress').style.display = 'block';
    
    // Create task in Task Manager
    const taskId = createTask('Contact Broadcast Campaign', 'contact_broadcast', {
        total: 0, // Will be updated when we get contact count
        canStop: true,
        canPause: true
    });
    window.currentTaskId = taskId;
    document.getElementById('contact-results').style.display = 'none';
    
    document.getElementById('contact-success-count').textContent = '0';
    document.getElementById('contact-failed-count').textContent = '0';
    
    try {
        const formData = new FormData();
        formData.append('message', message);
        formData.append('messageType', messageType);
        formData.append('delayType', delayType);
        formData.append('fixedDelay', fixedDelay);
        formData.append('minDelay', minDelay);
        formData.append('maxDelay', maxDelay);
        
        if (mediaFile) {
            formData.append('media', mediaFile);
        }
        
        const response = await fetch('/api/contacts/broadcast', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayContactResults(data.results);
            const successCount = data.results.filter(r => r.status === 'sent').length;
            
            // Update task manager
            if (window.currentTaskId) {
                updateTask(window.currentTaskId, {
                    progress: 100,
                    processed: data.results.length,
                    success: successCount,
                    failed: data.results.length - successCount,
                    total: data.results.length
                });
                completeTask(window.currentTaskId, 'completed');
            }
            
            showToast(`Broadcast completed! ${successCount}/${data.results.length} contacts reached`, 'success');
        } else {
            if (window.currentTaskId) {
                completeTask(window.currentTaskId, 'error');
            }
            showToast(data.error || 'Broadcast failed', 'error');
        }
    } catch (error) {
        if (window.currentTaskId) {
            completeTask(window.currentTaskId, 'error');
        }
        showToast('Error sending broadcast', 'error');
    }
}

function displayContactResults(results) {
    const resultsContainer = document.getElementById('contact-results');
    const resultsList = document.getElementById('contact-results-list');
    
    resultsList.innerHTML = results.map(result => `
        <div class="result-item" style="padding: 0.75rem; border-left: 3px solid ${result.status === 'sent' ? '#10b981' : '#ef4444'}; margin-bottom: 0.5rem; background: var(--surface); border-radius: 0.25rem;">
            <div>
                <strong>${result.contactName}</strong>
                <span class="status-badge ${result.status}">${result.status === 'sent' ? '✅ Sent' : '❌ Failed'}</span>
            </div>
            ${result.error ? `<small style="color: var(--error);">${result.error}</small>` : ''}
        </div>
    `).join('');
    
    resultsContainer.style.display = 'block';
    document.getElementById('contact-progress').style.display = 'none';
}

// Socket event for contact broadcast progress
if (socket) {
    socket.on('contact-broadcast-progress', (data) => {
        const progressFill = document.getElementById('contact-progress-fill');
        const progressText = document.getElementById('contact-progress-text');
        const successCount = document.getElementById('contact-success-count');
        const failedCount = document.getElementById('contact-failed-count');
        
        // Update Task Manager
        if (window.currentTaskId) {
            const percentage = (data.current / data.total) * 100;
            let currentSuccess = parseInt(successCount?.textContent || '0');
            let currentFailed = parseInt(failedCount?.textContent || '0');
            
            if (data.status === 'sent') currentSuccess++;
            else if (data.status === 'failed') currentFailed++;
            
            updateTask(window.currentTaskId, {
                progress: percentage,
                processed: data.current,
                success: currentSuccess,
                failed: currentFailed,
                total: data.total
            });
        }
        
        if (progressFill && progressText) {
            const percentage = (data.current / data.total) * 100;
            progressFill.style.width = `${percentage}%`;
            progressText.textContent = `${data.current} / ${data.total} contacts`;
            
            if (data.status === 'sent') {
                successCount.textContent = parseInt(successCount.textContent) + 1;
            } else if (data.status === 'failed') {
                failedCount.textContent = parseInt(failedCount.textContent) + 1;
            }
        }
    });
}
async function exportToGoogleContacts() {
    try {
        showLoading();
        
        const response = await fetch('/api/contacts/export-google', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'whatsapp_contacts_google.csv';
            a.click();
            
            showToast('Contacts exported! Import this CSV file to Google Contacts', 'success');
        } else {
            showToast('Error exporting contacts', 'error');
        }
    } catch (error) {
        showToast('Error exporting contacts', 'error');
    }
    
    hideLoading();
}

window.exportToGoogleContacts = exportToGoogleContacts;
function saveContactToGoogle(name, number) {
    // Open Google Contacts with pre-filled contact information
    const cleanNumber = number.startsWith('+') ? number : `+${number}`;
    const googleContactsUrl = `https://contacts.google.com/new?name=${encodeURIComponent(name)}&phone=${encodeURIComponent(cleanNumber)}`;
    window.open(googleContactsUrl, '_blank');
    
    showToast(`Opening Google Contacts to save ${name}`, 'success');
}

window.saveContactToGoogle = saveContactToGoogle;
async function checkBackgroundCampaigns() {
    try {
        const response = await fetch('/api/campaigns/status', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const campaigns = await response.json();
        const runningCampaigns = campaigns.filter(c => c.status === 'running');
        
        if (runningCampaigns.length > 0) {
            showCampaignResults(campaigns);
        }
    } catch (error) {
        console.error('Error checking campaigns:', error);
    }
}

function showCampaignResults(campaigns) {
    const modal = document.createElement('div');
    modal.className = 'modal show';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>📊 Campaign Results</h3>
                <button onclick="this.closest('.modal').remove()">×</button>
            </div>
            <div class="modal-body">
                ${campaigns.map(campaign => `
                    <div class="campaign-result" style="padding: 1rem; border: 1px solid var(--border); margin: 0.5rem 0; border-radius: 0.5rem;">
                        <h4>${campaign.type.replace('_', ' ').toUpperCase()}</h4>
                        <div class="campaign-stats">
                            <span class="stat">Total: ${campaign.total_count}</span>
                            <span class="stat">✅ Success: ${campaign.success_count || 0}</span>
                            <span class="stat">❌ Failed: ${campaign.failed_count || 0}</span>
                            <span class="stat">Status: ${campaign.status}</span>
                        </div>
                        <small>Started: ${new Date(campaign.created_at).toLocaleString()}</small>
                        ${campaign.completed_at ? `<br><small>Completed: ${new Date(campaign.completed_at).toLocaleString()}</small>` : ''}
                    </div>
                `).join('')}
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

window.checkBackgroundCampaigns = checkBackgroundCampaigns;
async function checkSubscriptionStatus() {
    try {
        const response = await fetch('/api/subscription/status', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const subscription = await response.json();
        
        if (subscription.subscription_type === 'expired' || 
            (subscription.subscription_expires && new Date() > new Date(subscription.subscription_expires))) {
            showSubscriptionExpired();
        } else if (subscription.subscription_type === 'trial' && subscription.subscription_expires) {
            const daysLeft = Math.ceil((new Date(subscription.subscription_expires) - new Date()) / (1000 * 60 * 60 * 24));
            if (daysLeft <= 1) {
                showTrialWarning(daysLeft);
            }
        }
    } catch (error) {
        console.error('Error checking subscription:', error);
    }
}

function showSubscriptionExpired() {
    // Hide dashboard and show subscription page
    document.getElementById('dashboard').style.display = 'none';
    
    const subscriptionPage = document.createElement('div');
    subscriptionPage.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: var(--background); display: flex; align-items: center; justify-content: center; z-index: 9999;';
    subscriptionPage.innerHTML = `
        <div class="card" style="max-width: 500px; text-align: center;">
            <div class="card-body">
                <i class="fas fa-exclamation-triangle" style="font-size: 4rem; color: #ef4444; margin-bottom: 1rem;"></i>
                <h2>Subscription Expired</h2>
                <p>Your subscription has expired. Please contact the admin to renew your subscription.</p>
                <div style="margin: 2rem 0;">
                    <h3>Contact Support:</h3>
                    <p><strong>WhatsApp:</strong> +92 317 0973410</p>
                </div>
                <button class="btn btn-outline" onclick="logout()">
                    <i class="fas fa-sign-out-alt"></i> Logout
                </button>
            </div>
        </div>
    `;
    document.body.appendChild(subscriptionPage);
}

function showTrialWarning(daysLeft) {
    const banner = document.createElement('div');
    banner.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; background: #f59e0b; color: white; padding: 1rem; text-align: center; z-index: 9999;';
    banner.innerHTML = `⏰ Trial expires in ${daysLeft} day(s). Contact admin for subscription.`;
    document.body.appendChild(banner);
}

window.checkSubscriptionStatus = checkSubscriptionStatus;
async function stopCampaign() {
    if (!window.currentCampaignId) {
        showToast('No active campaign to stop', 'error');
        return;
    }
    
    try {
        const response = await fetch(`/api/campaigns/stop/${window.currentCampaignId}`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Campaign stopped successfully!', 'success');
            window.currentCampaignId = null;
            hideTaskPanel();
            
            // Hide progress sections
            const progressSections = ['bulk-progress', 'broadcast-progress', 'contact-progress', 'csv-progress'];
            progressSections.forEach(id => {
                const el = document.getElementById(id);
                if (el) el.style.display = 'none';
            });
        } else {
            showToast('Failed to stop campaign', 'error');
        }
    } catch (error) {
        showToast('Error stopping campaign', 'error');
    }
}

async function checkActiveCampaigns() {
    try {
        const response = await fetch('/api/campaigns/active', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const campaigns = await response.json();
        
        if (campaigns.length > 0) {
            showActiveCampaigns(campaigns);
        }
    } catch (error) {
        console.error('Error checking active campaigns:', error);
    }
}

function showActiveCampaigns(campaigns) {
    const modal = document.createElement('div');
    modal.className = 'modal show';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>🚀 Active Campaigns</h3>
                <button onclick="this.closest('.modal').remove()">×</button>
            </div>
            <div class="modal-body">
                ${campaigns.map(campaign => `
                    <div class="campaign-status" style="padding: 1rem; border: 1px solid var(--border); margin: 0.5rem 0; border-radius: 0.5rem;">
                        <h4>${campaign.type.toUpperCase()} Campaign</h4>
                        <div class="campaign-progress">
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: ${(campaign.processed / campaign.total) * 100}%"></div>
                            </div>
                            <div class="campaign-stats">
                                <span>📊 ${campaign.processed}/${campaign.total}</span>
                                <span>✅ ${campaign.success}</span>
                                <span>❌ ${campaign.failed}</span>
                                <span>⏱️ ETA: ${campaign.eta}</span>
                            </div>
                        </div>
                        <button class="btn btn-outline btn-small" onclick="stopSpecificCampaign('${campaign.id}')">
                            Stop Campaign
                        </button>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

async function stopSpecificCampaign(campaignId) {
    try {
        const response = await fetch(`/api/campaigns/stop/${campaignId}`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Campaign stopped', 'success');
            document.querySelector('.modal').remove();
        }
    } catch (error) {
        showToast('Error stopping campaign', 'error');
    }
}

window.stopCampaign = stopCampaign;
window.checkActiveCampaigns = checkActiveCampaigns;
window.stopSpecificCampaign = stopSpecificCampaign;
function getContactUsContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>📞 Contact Support</h3>
            </div>
            <div class="card-body">
                <div style="text-align: center; padding: 2rem;">
                    <div style="margin-bottom: 2rem;">
                        <i class="fab fa-whatsapp" style="font-size: 4rem; color: #25d366;"></i>
                    </div>
                    <h2>Need Help?</h2>
                    <p>Contact our support team for assistance with subscriptions, technical issues, or any questions.</p>
                    
                    <div class="contact-info" style="margin: 2rem 0; padding: 2rem; background: var(--surface); border-radius: 1rem;">
                        <h3>Support WhatsApp</h3>
                        <p style="font-size: 1.5rem; font-weight: bold; color: var(--primary-color);">+92 317 0973410</p>
                        <button class="btn btn-primary btn-large" onclick="window.open('https://wa.me/923170973410', '_blank')">
                            <i class="fab fa-whatsapp"></i> Chat on WhatsApp
                        </button>
                    </div>
                    
                    <div class="subscription-info" style="margin-top: 2rem;">
                        <h4>📋 Your Subscription</h4>
                        <div id="subscription-details" style="padding: 1rem; background: var(--background); border-radius: 0.5rem; margin: 1rem 0;">
                            <p>Loading subscription details...</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

async function loadSubscriptionDetails() {
    try {
        const response = await fetch('/api/subscription/status', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        if (!response.ok) {
            throw new Error('Failed to fetch subscription');
        }
        
        const subscription = await response.json();
        const container = document.getElementById('subscription-details');
        
        if (container && subscription) {
            const expiresDate = subscription.subscription_expires ? 
                new Date(subscription.subscription_expires).toLocaleDateString() : null;
            
            const statusColor = subscription.subscription_type === 'premium' ? '#10b981' : 
                               subscription.subscription_type === 'trial' ? '#f59e0b' : '#ef4444';
            
            const daysLeft = subscription.subscription_expires ? 
                Math.ceil((new Date(subscription.subscription_expires) - new Date()) / (1000 * 60 * 60 * 24)) : null;
            
            let expirationText = 'No expiration';
            if (subscription.subscription_expires) {
                if (daysLeft > 0) {
                    expirationText = `Expires: ${expiresDate} (${daysLeft} days left)`;
                } else {
                    expirationText = `Expired on: ${expiresDate}`;
                }
            } else if (subscription.subscription_type === 'trial') {
                expirationText = '1-day trial (check server logs for exact expiration)';
            }
            
            container.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="color: ${statusColor}; font-weight: bold; text-transform: uppercase;">
                            ${subscription.subscription_type || 'Unknown'}
                        </span>
                        <br><small>${expirationText}</small>
                    </div>
                    <div>
                        ${subscription.subscription_type === 'trial' ? '🆓' : 
                          subscription.subscription_type === 'premium' ? '⭐' : '❌'}
                    </div>
                </div>
            `;
        }
    } catch (error) {
        console.error('Subscription load error:', error);
        const container = document.getElementById('subscription-details');
        if (container) {
            container.innerHTML = '<p style="color: var(--error);">Unable to load subscription details</p>';
        }
    }
}

// Load subscription details when contact page is opened
document.addEventListener('DOMContentLoaded', function() {
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'childList') {
                const subscriptionDetails = document.getElementById('subscription-details');
                if (subscriptionDetails && subscriptionDetails.textContent.includes('Loading')) {
                    loadSubscriptionDetails();
                }
            }
        });
    });
    
    observer.observe(document.body, { childList: true, subtree: true });
});
async function autoConnectWhatsApp() {
    try {
        // Check if already connected
        const response = await fetch('/api/whatsapp/status', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const data = await response.json();
        
        if (!data.ready) {
            // Auto-connect
            const connectResponse = await fetch('/api/whatsapp/connect', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (connectResponse.ok) {
                console.log('Auto-connecting WhatsApp...');
            }
        } else {
            updateConnectionStatus(true);
        }
    } catch (error) {
        console.error('Auto-connect failed:', error);
    }
}

window.autoConnectWhatsApp = autoConnectWhatsApp;
function getSchedulerContent() {
    return `
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
    `;
}

function showScheduleModal() {
    const modal = document.createElement('div');
    modal.className = 'modal show';
    modal.innerHTML = `
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
    `;
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
    
    // Validate phone number format
    const cleanRecipient = recipient.replace(/[^0-9+]/g, '');
    if (!/^[+]?[0-9]{10,15}$/.test(cleanRecipient)) {
        showToast('Please enter a valid phone number (10-15 digits)', 'error');
        return;
    }
    
    // Create datetime string
    const scheduledDateTime = `${date}T${time}:00`;
    const scheduledDate = new Date(scheduledDateTime);
    
    // Check if scheduled time is in the future (allow 1 minute buffer)
    const now = new Date();
    const oneMinuteFromNow = new Date(now.getTime() + 60000);
    if (scheduledDate <= oneMinuteFromNow) {
        showToast('Scheduled time must be at least 1 minute in the future', 'error');
        return;
    }
    
    // Show loading state
    const submitBtn = e.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    submitBtn.disabled = true;
    submitBtn.textContent = 'Scheduling...';
    
    try {
        const formData = new FormData();
        formData.append('recipient', cleanRecipient);
        formData.append('message', message);
        formData.append('scheduledAt', scheduledDateTime);
        
        if (mediaFile) {
            formData.append('media', mediaFile);
            formData.append('messageType', mediaFile.type.startsWith('image/') ? 'image' : 
                                         mediaFile.type.startsWith('video/') ? 'video' : 
                                         mediaFile.type.startsWith('audio/') ? 'audio' : 'document');
        }
        
        console.log(`📅 Scheduling message to ${cleanRecipient} for ${scheduledDate.toLocaleString()}`);
        
        const response = await fetch('/api/messages/schedule', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` },
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast(`✅ Message scheduled for ${scheduledDate.toLocaleString()}!`, 'success');
            document.querySelector('.modal').remove();
            
            // Reload scheduled messages to show the new one
            setTimeout(() => {
                loadScheduledMessages();
            }, 500);
            
            console.log(`✅ Message scheduled successfully with ID: ${data.queueId}`);
        } else {
            showToast(data.error || 'Failed to schedule message', 'error');
            console.error('Schedule error:', data.error);
        }
    } catch (error) {
        console.error('Error scheduling message:', error);
        showToast('Network error while scheduling message', 'error');
    } finally {
        // Reset button state
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
    }
}

async function loadScheduledMessages() {
    try {
        // Load statistics first
        const statsResponse = await fetch('/api/messages/scheduled/stats', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        if (statsResponse.ok) {
            const stats = await statsResponse.json();
            
            const pendingEl = document.getElementById('pending-scheduled');
            const sentEl = document.getElementById('sent-scheduled');
            const failedEl = document.getElementById('failed-scheduled');
            
            if (pendingEl) pendingEl.textContent = stats.pending || 0;
            if (sentEl) sentEl.textContent = stats.sent || 0;
            if (failedEl) failedEl.textContent = stats.failed || 0;
        }
        
        // Load all messages
        const response = await fetch('/api/messages/scheduled/all', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const messages = await response.json();
        const container = document.getElementById('scheduled-messages');
        
        if (messages.length === 0) {
            container.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--text-secondary);"><i class="fas fa-calendar-plus" style="font-size: 3rem; margin-bottom: 1rem;"></i><p>No scheduled messages found.</p><p>Click "Schedule Message" to create your first scheduled message.</p></div>';
            return;
        }
        
        // Group messages by status
        const pendingMessages = messages.filter(m => m.status === 'pending');
        const sentMessages = messages.filter(m => m.status === 'sent');
        const failedMessages = messages.filter(m => m.status === 'failed');
        
        container.innerHTML = `
            ${pendingMessages.length > 0 ? `
                <div class="message-group" style="margin-bottom: 2rem;">
                    <h4 style="color: #f59e0b; margin-bottom: 1rem;">⏳ Pending Messages (${pendingMessages.length})</h4>
                    ${pendingMessages.map(msg => createMessageCard(msg, true)).join('')}
                </div>
            ` : ''}
            
            ${failedMessages.length > 0 ? `
                <div class="message-group" style="margin-bottom: 2rem;">
                    <h4 style="color: #ef4444; margin-bottom: 1rem;">❌ Failed Messages (${failedMessages.length})</h4>
                    ${failedMessages.map(msg => createMessageCard(msg, true)).join('')}
                </div>
            ` : ''}
            
            ${sentMessages.length > 0 ? `
                <div class="message-group" style="margin-bottom: 2rem;">
                    <h4 style="color: #10b981; margin-bottom: 1rem;">✅ Sent Messages (${sentMessages.length})</h4>
                    ${sentMessages.slice(0, 10).map(msg => createMessageCard(msg, false)).join('')}
                    ${sentMessages.length > 10 ? `<p style="text-align: center; color: var(--text-secondary); font-style: italic;">Showing 10 of ${sentMessages.length} sent messages</p>` : ''}
                </div>
            ` : ''}
        `;
        
        console.log(`📅 Loaded ${messages.length} scheduled messages (${pendingMessages.length} pending, ${sentMessages.length} sent, ${failedMessages.length} failed)`);
        
    } catch (error) {
        console.error('Error loading scheduled messages:', error);
        const container = document.getElementById('scheduled-messages');
        if (container) {
            container.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--error);"><i class="fas fa-exclamation-triangle" style="font-size: 2rem; margin-bottom: 1rem;"></i><p>Error loading scheduled messages</p><p>Please try refreshing the page</p></div>';
        }
    }
}

function createMessageCard(msg, showActions) {
    const scheduledTime = new Date(msg.scheduled_at);
    const isOverdue = msg.status === 'pending' && scheduledTime < new Date();
    
    return `
        <div class="scheduled-message" style="padding: 1rem; border: 1px solid var(--border); margin: 0.5rem 0; border-radius: 0.5rem; ${isOverdue ? 'border-color: #ef4444;' : ''}">
            <div style="display: flex; justify-content: space-between; align-items: start;">
                <div style="flex: 1;">
                    <h4>📱 ${msg.recipient}</h4>
                    <p style="margin: 0.5rem 0;">${msg.message.substring(0, 100)}${msg.message.length > 100 ? '...' : ''}</p>
                    <div style="display: flex; gap: 1rem; font-size: 0.8rem; color: var(--text-secondary);">
                        <span>⏰ ${scheduledTime.toLocaleString()}</span>
                        <span>📈 Status: ${msg.status}</span>
                        ${msg.attempts > 0 ? `<span>🔄 Attempts: ${msg.attempts}</span>` : ''}
                        ${msg.media_path ? '<span>📎 Has media</span>' : ''}
                    </div>
                    ${isOverdue ? '<div style="color: #ef4444; font-size: 0.8rem; margin-top: 0.5rem;">⚠️ Overdue - Check WhatsApp connection</div>' : ''}
                </div>
                ${showActions ? `
                    <div style="display: flex; gap: 0.5rem;">
                        ${msg.status === 'pending' ? `
                            <button class="btn btn-outline btn-small" onclick="cancelScheduledMessage(${msg.id})">
                                ❌ Cancel
                            </button>
                        ` : ''}
                        ${msg.status === 'failed' ? `
                            <button class="btn btn-outline btn-small" onclick="retryScheduledMessage(${msg.id})">
                                🔄 Retry
                            </button>
                        ` : ''}
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

async function cancelScheduledMessage(messageId) {
    if (!confirm('Are you sure you want to cancel this scheduled message?')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/messages/scheduled/${messageId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
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
        const response = await fetch(`/api/messages/scheduled/${messageId}/retry`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
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

window.showScheduleModal = showScheduleModal;
window.scheduleMessage = scheduleMessage;
window.loadScheduledMessages = loadScheduledMessages;
window.cancelScheduledMessage = cancelScheduledMessage;
window.retryScheduledMessage = retryScheduledMessage;
window.createMessageCard = createMessageCard;

function getProfileContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>👤 Profile Settings</h3>
            </div>
            <div class="card-body">
                <div class="profile-section">
                    <h4>📋 Account Information</h4>
                    <div class="profile-info" style="background: var(--surface); padding: 1rem; border-radius: 0.5rem; margin-bottom: 2rem;">
                        <div class="info-item" style="margin-bottom: 0.5rem;">
                            <strong>Username:</strong> <span id="profile-username">Loading...</span>
                        </div>
                        <div class="info-item" style="margin-bottom: 0.5rem;">
                            <strong>Email:</strong> <span id="profile-email">Loading...</span>
                        </div>
                        <div class="info-item">
                            <strong>WhatsApp Number:</strong> <span id="profile-whatsapp">Not connected</span>
                        </div>
                    </div>
                </div>
                
                <div class="whatsapp-import-section">
                    <h4>📱 WhatsApp Settings</h4>
                    <div class="whatsapp-settings" style="background: var(--surface); padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 2rem;">
                        <div class="form-group">
                            <label>Import WhatsApp Number</label>
                            <input type="text" id="import-whatsapp-number" placeholder="923001234567">
                            <button type="button" id="import-whatsapp-btn" class="btn btn-outline" style="margin-top: 0.5rem;">
                                📥 Import WhatsApp
                            </button>
                        </div>
                    </div>
                </div>
                
                <div class="password-section">
                    <h4>🔐 Change Password</h4>
                    <div class="password-change-form" style="background: var(--surface); padding: 1.5rem; border-radius: 0.5rem;">
                        <form id="password-change-form">
                            <div class="form-group">
                                <label>Current Password</label>
                                <input type="password" id="current-password" placeholder="Enter current password" required>
                            </div>
                            
                            <div class="form-group">
                                <label>New Password</label>
                                <input type="password" id="new-password" placeholder="Enter new password" required>
                                <small>Password must contain at least 8 characters with uppercase, lowercase, and number</small>
                            </div>
                            
                            <div class="form-group">
                                <label>Confirm New Password</label>
                                <input type="password" id="confirm-password" placeholder="Confirm new password" required>
                            </div>
                            
                            <div class="form-group">
                                <label>Enter your WhatsApp number for OTP (format: 923001234567):</label>
                                <input type="text" id="whatsapp-otp-number" placeholder="923001234567" required>
                            </div>
                            
                            <div class="form-group">
                                <button type="button" id="send-password-otp" class="btn btn-outline">
                                    📱 Send OTP
                                </button>
                            </div>
                            
                            <div class="form-group">
                                <label>Enter OTP</label>
                                <input type="text" id="password-otp" placeholder="Enter 4-digit OTP" maxlength="4">
                                <small>Use demo OTP: 1234 for testing</small>
                            </div>
                            
                            <button type="submit" class="btn btn-primary" id="change-password-btn" disabled>
                                🔐 Change Password
                            </button>
                        </form>
                    </div>
                </div>
                
                <div class="subscription-section" style="margin-top: 2rem;">
                    <h4>⭐ Subscription Status</h4>
                    <div id="subscription-status" style="background: var(--surface); padding: 1rem; border-radius: 0.5rem;">
                        <p>Loading subscription details...</p>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function setupProfileHandlers() {
    document.getElementById('send-password-otp').addEventListener('click', sendPasswordOTP);
    document.getElementById('password-change-form').addEventListener('submit', changePassword);
    document.getElementById('import-whatsapp-btn').addEventListener('click', importWhatsAppNumber);
    
    document.getElementById('password-otp').addEventListener('input', function() {
        this.value = this.value.replace(/[^0-9]/g, '');
        document.getElementById('change-password-btn').disabled = this.value.length !== 4;
    });
    
    document.getElementById('whatsapp-otp-number').addEventListener('input', function() {
        this.value = this.value.replace(/[^0-9]/g, '');
    });
    
    document.getElementById('import-whatsapp-number').addEventListener('input', function() {
        this.value = this.value.replace(/[^0-9]/g, '');
    });
}

async function importWhatsAppNumber() {
    const whatsappNumber = document.getElementById('import-whatsapp-number').value.trim();
    const cleanNumber = whatsappNumber.replace(/[^0-9]/g, '');
    
    const importBtn = document.getElementById('import-whatsapp-btn');
    importBtn.disabled = true;
    importBtn.textContent = 'Importing...';
    
    try {
        await fetch('/api/import-whatsapp', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ whatsappNumber: cleanNumber })
        });
        
        document.getElementById('profile-whatsapp').textContent = cleanNumber;
        importBtn.textContent = 'Imported ✓';
        importBtn.style.backgroundColor = '#10b981';
        importBtn.style.color = 'white';
    } catch (error) {
        importBtn.disabled = false;
        importBtn.textContent = '📥 Import WhatsApp';
    }
}

async function loadUserProfile() {
    try {
        // Load user info from localStorage
        const user = JSON.parse(localStorage.getItem('user') || '{}');
        document.getElementById('profile-username').textContent = user.username || 'Unknown';
        document.getElementById('profile-email').textContent = user.email || 'Unknown';
        
        // Load subscription status
        const response = await fetch('/api/subscription/status', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        if (response.ok) {
            const subscription = await response.json();
            
            // Update WhatsApp number
            document.getElementById('profile-whatsapp').textContent = 
                subscription.whatsapp_number || 'Not connected';
            
            // Update subscription status
            const statusContainer = document.getElementById('subscription-status');
            const expiresDate = subscription.subscription_expires ? 
                new Date(subscription.subscription_expires).toLocaleDateString() : null;
            
            const statusColor = subscription.subscription_type === 'premium' ? '#10b981' : 
                               subscription.subscription_type === 'trial' ? '#f59e0b' : '#ef4444';
            
            const daysLeft = subscription.subscription_expires ? 
                Math.ceil((new Date(subscription.subscription_expires) - new Date()) / (1000 * 60 * 60 * 24)) : null;
            
            let expirationText = 'No expiration';
            if (subscription.subscription_expires) {
                if (daysLeft > 0) {
                    expirationText = `Expires: ${expiresDate} (${daysLeft} days left)`;
                } else {
                    expirationText = `Expired on: ${expiresDate}`;
                }
            }
            
            statusContainer.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="color: ${statusColor}; font-weight: bold; text-transform: uppercase;">
                            ${subscription.subscription_type || 'Unknown'}
                        </span>
                        <br><small>${expirationText}</small>
                    </div>
                    <div style="font-size: 2rem;">
                        ${subscription.subscription_type === 'trial' ? '🆓' : 
                          subscription.subscription_type === 'premium' ? '⭐' : '❌'}
                    </div>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error loading profile:', error);
    }
}

async function sendPasswordOTP() {
    const whatsappNumber = document.getElementById('whatsapp-otp-number').value.trim();
    const cleanNumber = whatsappNumber.replace(/[^0-9]/g, '');
    
    const sendBtn = document.getElementById('send-password-otp');
    sendBtn.disabled = true;
    sendBtn.textContent = 'Sending...';
    
    try {
        const response = await fetch('/api/send-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                whatsappNumber: cleanNumber,
                adminNumber: '923170973410',
                purpose: 'password change'
            })
        });
        
        const data = await response.json();
        document.getElementById('otp-verification').style.display = 'block';
        sendBtn.textContent = 'OTP Sent ✓';
        sendBtn.style.backgroundColor = '#10b981';
        sendBtn.style.color = 'white';
        document.getElementById('password-otp').focus();
    } catch (error) {
        sendBtn.disabled = false;
        sendBtn.textContent = '📱 Send OTP';
    }
}

async function changePassword(e) {
    e.preventDefault();
    
    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    const whatsappNumber = document.getElementById('whatsapp-otp-number').value.trim();
    const otp = document.getElementById('password-otp').value;
    
    const changeBtn = document.getElementById('change-password-btn');
    changeBtn.disabled = true;
    changeBtn.textContent = 'Changing Password...';
    
    try {
        const response = await fetch('/api/change-password', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                currentPassword,
                newPassword,
                whatsappNumber: whatsappNumber.replace(/[^0-9]/g, ''),
                otp
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('password-change-form').reset();
            const sendBtn = document.getElementById('send-password-otp');
            sendBtn.disabled = false;
            sendBtn.textContent = '📱 Send OTP';
            sendBtn.style.backgroundColor = '';
            sendBtn.style.color = '';
            changeBtn.disabled = true;
            changeBtn.textContent = '🔐 Change Password';
        }
    } catch (error) {
        changeBtn.disabled = false;
        changeBtn.textContent = '🔐 Change Password';
    }
}

window.loadUserProfile = loadUserProfile;
window.setupProfileHandlers = setupProfileHandlers;
window.sendPasswordOTP = sendPasswordOTP;
window.changePassword = changePassword;
function showImportModal() {
    const modal = document.createElement('div');
    modal.className = 'modal show';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>📁 Import Contacts from CSV</h3>
                <button onclick="this.closest('.modal').remove()">×</button>
            </div>
            <div class="modal-body">
                <form id="import-form">
                    <div class="form-group">
                        <label>CSV File:</label>
                        <input type="file" id="csv-file" accept=".csv" required>
                        <small>CSV should have columns: name, phone (or number)</small>
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn btn-outline" onclick="this.closest('.modal').remove()">Cancel</button>
                        <button type="submit" class="btn btn-primary">Import Contacts</button>
                    </div>
                </form>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    document.getElementById('import-form').onsubmit = importContacts;
}

async function importContacts(e) {
    e.preventDefault();
    
    const formData = new FormData();
    const csvFile = document.getElementById('csv-file').files[0];
    formData.append('csvFile', csvFile);
    
    try {
        showLoading();
        
        const response = await fetch('/api/contacts/import', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` },
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast(`Imported: ${data.imported}, Duplicates: ${data.duplicates}, Errors: ${data.errors}`, 'success');
            document.querySelector('.modal').remove();
            loadContacts();
        } else {
            showToast(data.error || 'Import failed', 'error');
        }
    } catch (error) {
        showToast('Error importing contacts', 'error');
    }
    
    hideLoading();
}

function showGroupModal() {
    const modal = document.createElement('div');
    modal.className = 'modal show';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>📂 Create Contact Group</h3>
                <button onclick="this.closest('.modal').remove()">×</button>
            </div>
            <div class="modal-body">
                <form id="group-form">
                    <div class="form-group">
                        <label>Group Name:</label>
                        <input type="text" id="group-name" placeholder="e.g., VIP Customers" required>
                    </div>
                    <div class="form-group">
                        <label>Description:</label>
                        <textarea id="group-description" rows="3" placeholder="Optional description"></textarea>
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn btn-outline" onclick="this.closest('.modal').remove()">Cancel</button>
                        <button type="submit" class="btn btn-primary">Create Group</button>
                    </div>
                </form>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    document.getElementById('group-form').onsubmit = createContactGroup;
}

async function createContactGroup(e) {
    e.preventDefault();
    
    const groupData = {
        name: document.getElementById('group-name').value,
        description: document.getElementById('group-description').value
    };
    
    try {
        const response = await fetch('/api/contacts/groups', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(groupData)
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Contact group created successfully!', 'success');
            document.querySelector('.modal').remove();
        } else {
            showToast(data.error || 'Failed to create group', 'error');
        }
    } catch (error) {
        showToast('Error creating group', 'error');
    }
}

window.showImportModal = showImportModal;
window.importContacts = importContacts;
window.showGroupModal = showGroupModal;
window.createContactGroup = createContactGroup;
function addContactTag(contactId) {
    const modal = document.createElement('div');
    modal.className = 'modal show';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>🏷️ Add Tags</h3>
                <button onclick="this.closest('.modal').remove()">×</button>
            </div>
            <div class="modal-body">
                <form id="tag-form">
                    <div class="form-group">
                        <label>Tags (comma separated):</label>
                        <input type="text" id="contact-tags" placeholder="VIP, Customer, Lead" required>
                        <small>Examples: VIP, Customer, Lead, Hot Prospect</small>
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn btn-outline" onclick="this.closest('.modal').remove()">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Tags</button>
                    </div>
                </form>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    
    document.getElementById('tag-form').onsubmit = async (e) => {
        e.preventDefault();
        
        const tags = document.getElementById('contact-tags').value.split(',').map(tag => tag.trim());
        
        try {
            const response = await fetch(`/api/contacts/${contactId}/tags`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ tags })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showToast('Tags added successfully!', 'success');
                document.querySelector('.modal').remove();
                loadContacts();
            } else {
                showToast(data.error || 'Failed to add tags', 'error');
            }
        } catch (error) {
            showToast('Error adding tags', 'error');
        }
    };
}

// Enhanced contact deduplication
async function deduplicateContacts() {
    try {
        showLoading();
        
        const response = await fetch('/api/contacts/deduplicate', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast(`Removed ${data.duplicatesRemoved} duplicate contacts`, 'success');
            loadContacts();
        } else {
            showToast(data.error || 'Deduplication failed', 'error');
        }
    } catch (error) {
        showToast('Error deduplicating contacts', 'error');
    }
    
    hideLoading();
}

window.addContactTag = addContactTag;
window.deduplicateContacts = deduplicateContacts;
function showTaskPanel(taskName, details = {}) {
    // Remove existing panel
    const existing = document.getElementById('task-panel');
    if (existing) existing.remove();
    
    const panel = document.createElement('div');
    panel.id = 'task-panel';
    panel.style.cssText = 'position: fixed; top: 20px; right: 20px; width: 400px; background: var(--surface); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1rem; z-index: 9999; box-shadow: 0 4px 12px rgba(0,0,0,0.15); max-height: 80vh; overflow-y: auto;';
    
    panel.innerHTML = `
        <div class="task-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <h4 style="margin: 0;">🔄 ${taskName}</h4>
            <button onclick="hideTaskPanel()" style="background: none; border: none; font-size: 1.2rem; cursor: pointer;">×</button>
        </div>
        
        <div id="task-status" style="margin-bottom: 1rem; padding: 0.5rem; background: var(--background); border-radius: 0.25rem;">
            <div class="status-text">Starting...</div>
            <div id="live-timer" style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem;">00:00</div>
        </div>
        
        <div id="task-progress" style="margin-bottom: 1rem;">
            <div class="progress-bar" style="background: var(--background); border-radius: 0.25rem; height: 10px; overflow: hidden;">
                <div id="task-progress-fill" style="background: var(--primary-color); height: 100%; width: 0%; transition: width 0.3s;"></div>
            </div>
            <div id="task-progress-text" style="font-size: 0.9rem; margin-top: 0.5rem; text-align: center;">0%</div>
        </div>
        
        <div id="task-stats" style="margin-bottom: 1rem;">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; font-size: 0.8rem;">
                <div>✅ Success: <span id="success-stat">0</span></div>
                <div>❌ Failed: <span id="failed-stat">0</span></div>
                <div>📊 Total: <span id="total-stat">0</span></div>
                <div>⏳ Remaining: <span id="remaining-stat">0</span></div>
            </div>
        </div>
        
        <div id="current-item" style="margin-bottom: 1rem; padding: 0.5rem; background: var(--background); border-radius: 0.25rem; font-size: 0.8rem;">
            <div>📱 Current: <span id="current-target">-</span></div>
            <div>⏱️ ETA: <span id="eta-time">Calculating...</span></div>
        </div>
        
        <div id="pending-list" style="margin-bottom: 1rem; max-height: 150px; overflow-y: auto;">
            <div style="font-size: 0.8rem; font-weight: bold; margin-bottom: 0.5rem;">Pending Items:</div>
            <div id="pending-items" style="font-size: 0.7rem; color: var(--text-secondary);">Loading...</div>
        </div>
        
        <div class="task-actions">
            <button id="task-stop-btn" class="btn btn-outline btn-small" onclick="stopCurrentTask()" style="display: none;">
                ⏹️ Stop Task
            </button>
            <button id="task-details-btn" class="btn btn-outline btn-small" onclick="toggleTaskDetails()">
                📄 Details
            </button>
        </div>
    `;
    
    document.body.appendChild(panel);
    window.currentTask = { name: taskName, startTime: new Date(), ...details };
    
    // Start live timer
    startLiveTimer();
}

function updateTaskPanel(status, progress = null, details = {}) {
    const panel = document.getElementById('task-panel');
    if (!panel) return;
    
    // Update status
    const statusEl = panel.querySelector('.status-text');
    if (statusEl) statusEl.textContent = status;
    
    // Update progress
    const progressFill = document.getElementById('task-progress-fill');
    const progressText = document.getElementById('task-progress-text');
    if (progress !== null) {
        if (progressFill) progressFill.style.width = `${progress}%`;
        if (progressText) progressText.textContent = `${Math.round(progress)}%`;
    }
    
    // Update stats with proper checks
    const successStat = document.getElementById('success-stat');
    const failedStat = document.getElementById('failed-stat');
    const totalStat = document.getElementById('total-stat');
    const remainingStat = document.getElementById('remaining-stat');
    
    if (successStat && details.success !== undefined) successStat.textContent = details.success;
    if (failedStat && details.failed !== undefined) failedStat.textContent = details.failed;
    if (totalStat && details.total !== undefined) totalStat.textContent = details.total;
    if (remainingStat && details.remaining !== undefined) remainingStat.textContent = details.remaining;
    
    // Update current item
    const currentTarget = document.getElementById('current-target');
    const etaTime = document.getElementById('eta-time');
    if (currentTarget && details.currentTarget) currentTarget.textContent = details.currentTarget;
    if (etaTime && details.eta) etaTime.textContent = details.eta;
    
    // Update pending list
    if (details.pendingItems) {
        const pendingEl = document.getElementById('pending-items');
        if (pendingEl) {
            pendingEl.innerHTML = details.pendingItems.slice(0, 10).map((item, index) => 
                `<div style="padding: 0.2rem 0; border-bottom: 1px solid var(--border);">${index + 1}. ${item}</div>`
            ).join('') + (details.pendingItems.length > 10 ? `<div style="padding: 0.2rem 0; font-style: italic;">...and ${details.pendingItems.length - 10} more</div>` : '');
        }
    }
    
    // Show/hide stop button
    const stopBtn = document.getElementById('task-stop-btn');
    if (details.showStop && stopBtn) {
        stopBtn.style.display = 'inline-block';
    }
}

function hideTaskPanel() {
    const panel = document.getElementById('task-panel');
    if (panel) panel.remove();
    window.currentTask = null;
}

function stopCurrentTask() {
    if (window.currentCampaignId) {
        stopCampaign();
    } else {
        // Force stop by reloading page if no campaign ID
        if (confirm('Force stop by refreshing page? This will stop all operations.')) {
            window.location.reload();
        }
    }
    updateTaskPanel('Stopping task...', null, { additionalInfo: 'Please wait while we stop the current operation.' });
}

// Legacy functions for compatibility
function showLoading() {
    showTaskPanel('Processing', { showStop: false });
}

function hideLoading() {
    hideTaskPanel();
}

window.showTaskPanel = showTaskPanel;
window.updateTaskPanel = updateTaskPanel;
window.hideTaskPanel = hideTaskPanel;
window.stopCurrentTask = stopCurrentTask;
async function restoreActiveCampaigns() {
    try {
        const response = await fetch('/api/campaigns/active', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const campaigns = await response.json();
        
        // Clear existing tasks and restore from server
        window.activeTasks.clear();
        
        campaigns.forEach(campaign => {
            const taskId = createTask(
                `${campaign.type.replace('_', ' ').toUpperCase()} Campaign`,
                campaign.type,
                {
                    campaignId: campaign.id,
                    total: campaign.total,
                    processed: campaign.processed,
                    success: campaign.success,
                    failed: campaign.failed,
                    progress: (campaign.processed / campaign.total) * 100,
                    canStop: true,
                    canPause: false
                }
            );
            
            // Set as current campaign for stop functionality
            window.currentCampaignId = campaign.id;
            window.currentTaskId = taskId;
        });
        
        if (campaigns.length > 0) {
            console.log(`Restored ${campaigns.length} active campaigns`);
        }
    } catch (error) {
        console.error('Error restoring campaigns:', error);
    }
}

window.restoreActiveCampaigns = restoreActiveCampaigns;
function startLiveTimer() {
    if (window.taskTimer) clearInterval(window.taskTimer);
    
    window.taskTimer = setInterval(() => {
        if (!window.currentTask || !document.getElementById('task-panel')) {
            clearInterval(window.taskTimer);
            return;
        }
        
        const elapsed = Math.floor((new Date() - window.currentTask.startTime) / 1000);
        const minutes = Math.floor(elapsed / 60);
        const seconds = elapsed % 60;
        
        const timerEl = document.getElementById('live-timer');
        if (timerEl) {
            timerEl.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        }
    }, 1000);
}

function toggleTaskDetails() {
    const pendingList = document.getElementById('pending-list');
    if (pendingList) {
        pendingList.style.display = pendingList.style.display === 'none' ? 'block' : 'none';
    }
}

window.startLiveTimer = startLiveTimer;
window.toggleTaskDetails = toggleTaskDetails;
function downloadBulkReport() {
    if (!window.lastBulkResults) {
        showToast('No results to download', 'error');
        return;
    }
    
    const results = window.lastBulkResults;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    
    // Create CSV content
    const csvContent = [
        'Number,Status,Error,Index,Timestamp',
        ...results.map(result => 
            `"${result.number}","${result.status}","${result.error || ''}","${result.index}","${new Date().toLocaleString()}"`
        )
    ].join('\\n');
    
    // Create and download file
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bulk-campaign-report-${timestamp}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('Report downloaded successfully!', 'success');
}

async function downloadBulkReport() {
    try {
        const response = await fetch('/api/campaigns/download-report', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        if (!response.ok) {
            showToast('No results to download', 'error');
            return;
        }
        
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `bulk-campaign-report-${new Date().toISOString().slice(0,10)}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        showToast('Report downloaded successfully!', 'success');
    } catch (error) {
        showToast('Error downloading report', 'error');
    }
}

window.downloadBulkReport = downloadBulkReport;

// Global Task Manager - Initialize immediately
if (!window.activeTasks) {
    window.activeTasks = new Map();
}
if (!window.taskCounter) {
    window.taskCounter = 0;
}

function createTask(name, type, details = {}) {
    if (!window.activeTasks) {
        window.activeTasks = new Map();
    }
    
    const taskId = `task_${++window.taskCounter}_${Date.now()}`;
    const task = {
        id: taskId,
        name,
        type,
        status: 'running',
        startTime: new Date(),
        progress: 0,
        total: details.total || 0,
        processed: 0,
        success: 0,
        failed: 0,
        canStop: details.canStop !== false,
        canPause: details.canPause || false,
        paused: false,
        ...details
    };
    
    window.activeTasks.set(taskId, task);
    console.log('Task created:', taskId, task);
    
    // Show task panel immediately
    showTaskPanel(name, {
        taskId: taskId,
        total: task.total,
        showStop: task.canStop
    });
    
    updateTaskManagerUI();
    return taskId;
}

function updateTask(taskId, updates) {
    if (!window.activeTasks) return;
    
    const task = window.activeTasks.get(taskId);
    if (task) {
        Object.assign(task, updates);
        
        // Update task panel if visible
        updateTaskPanel(
            `${task.name} - ${task.status}`,
            task.progress,
            {
                success: task.success,
                failed: task.failed,
                total: task.total,
                remaining: task.total - task.processed,
                currentTarget: updates.number || task.currentTarget,
                eta: updates.eta || 'Calculating...',
                showStop: task.canStop && ['running', 'paused'].includes(task.status)
            }
        );
        
        updateTaskManagerUI();
    }
}

function completeTask(taskId, status = 'completed') {
    const task = window.activeTasks.get(taskId);
    if (task) {
        task.status = status;
        task.endTime = new Date();
        updateTaskManagerUI();
        
        // Auto-remove completed tasks after 30 seconds
        setTimeout(() => {
            window.activeTasks.delete(taskId);
            updateTaskManagerUI();
        }, 30000);
    }
}

async function stopTask(taskId) {
    
    try {
        const response = await fetch(`/api/tasks/${taskId}/stop`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            showToast('Task stopped successfully', 'success');
            loadTasks();
        } else {
            showToast(data.error || 'Failed to stop task', 'error');
        }
    } catch (error) {
        console.error('Stop task error:', error);
        showToast('Error stopping task', 'error');
    }
}

async function pauseTask(taskId) {
    try {
        const response = await fetch(`/api/tasks/${taskId}/pause`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            showToast('Task paused successfully', 'success');
            loadTasks();
        } else {
            showToast(data.error || 'Failed to pause task', 'error');
        }
    } catch (error) {
        console.error('Pause task error:', error);
        showToast('Error pausing task', 'error');
    }
}

async function resumeTask(taskId) {
    try {
        const response = await fetch(`/api/tasks/${taskId}/resume`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            showToast('Task resumed successfully', 'success');
            loadTasks();
        } else {
            showToast(data.error || 'Failed to resume task', 'error');
        }
    } catch (error) {
        console.error('Resume task error:', error);
        showToast('Error resuming task', 'error');
    }
}

async function restartTask(taskId) {
    
    try {
        const response = await fetch(`/api/tasks/${taskId}/restart`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            showToast('Task restarted successfully', 'success');
            loadTasks();
        } else {
            showToast(data.error || 'Failed to restart task', 'error');
        }
    } catch (error) {
        console.error('Restart task error:', error);
        showToast('Error restarting task', 'error');
    }
}

async function deleteTask(taskId) {
    
    try {
        const response = await fetch(`/api/tasks/${taskId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            showToast('Task deleted successfully', 'success');
            loadTasks();
        } else {
            showToast(data.error || 'Failed to delete task', 'error');
        }
    } catch (error) {
        console.error('Delete task error:', error);
        showToast('Error deleting task', 'error');
    }
}

// Enhanced task details function with proper modal
async function showTaskDetails(taskId) {
    try {
        const response = await fetch(`/api/tasks/${taskId}/details`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const data = await response.json();
        
        if (response.ok && data.task) {
            const task = data.task;
            const details = data.details || [];
            
            const modal = document.createElement('div');
            modal.className = 'modal show';
            modal.innerHTML = `
                <div class="modal-content" style="max-width: 800px;">
                    <div class="modal-header">
                        <h3>📊 Campaign Details</h3>
                        <button onclick="this.closest('.modal').remove()">×</button>
                    </div>
                    <div class="modal-body">
                        <div class="task-summary" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem; margin-bottom: 1.5rem; padding: 0.75rem; background: var(--surface); border-radius: 0.5rem;">
                            <div class="stat-item">
                                <h4 style="margin: 0; color: var(--primary-color);">${task.total_count || 0}</h4>
                                <p style="margin: 0; font-size: 0.8rem;">Total Numbers</p>
                            </div>
                            <div class="stat-item">
                                <h4 style="margin: 0; color: #10b981;">${task.success_count || 0}</h4>
                                <p style="margin: 0; font-size: 0.8rem;">Successfully Sent</p>
                            </div>
                            <div class="stat-item">
                                <h4 style="margin: 0; color: #ef4444;">${task.failed_count || 0}</h4>
                                <p style="margin: 0; font-size: 0.8rem;">Failed to Send</p>
                            </div>
                        </div>
                        
                        <div class="campaign-info" style="margin-bottom: 1.5rem;">
                            <h4>Campaign Information</h4>
                            <div style="background: var(--background); padding: 0.75rem; border-radius: 0.5rem;">
                                <p><strong>Campaign ID:</strong> ${task.id}</p>
                                <p><strong>Type:</strong> ${task.type.replace('_', ' ').toUpperCase()}</p>
                                <p><strong>Status:</strong> <span style="color: ${getTaskStatusColor(task.status)};">${task.status.toUpperCase()}</span></p>
                                <p><strong>Started:</strong> ${new Date(task.created_at).toLocaleString()}</p>
                                ${task.completed_at ? `<p><strong>Completed:</strong> ${new Date(task.completed_at).toLocaleString()}</p>` : ''}
                                <p><strong>Progress:</strong> ${task.processed_count || 0}/${task.total_count || 0} (${task.total_count > 0 ? Math.round(((task.processed_count || 0) / task.total_count) * 100) : 0}%)</p>
                            </div>
                        </div>
                        
                        ${details.length > 0 ? `
                            <div class="message-details">
                                <h4>Message Details (Last 50)</h4>
                                <div style="max-height: 250px; overflow-y: auto; border: 1px solid var(--border); border-radius: 0.5rem;">
                                    ${details.map(detail => `
                                        <div style="padding: 0.5rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center;">
                                            <div>
                                                <strong>${detail.recipient || detail.target_number || 'Unknown'}</strong>
                                                ${detail.message_content ? `<br><small style="color: var(--text-secondary);">${detail.message_content.substring(0, 50)}...</small>` : ''}
                                            </div>
                                            <span class="status-badge" style="background: ${detail.status === 'sent' ? '#10b981' : '#ef4444'}; color: white; padding: 0.2rem 0.4rem; border-radius: 0.25rem; font-size: 0.7rem;">
                                                ${detail.status === 'sent' ? '✅ Sent' : '❌ Failed'}
                                            </span>
                                        </div>
                                    `).join('')}
                                </div>
                            </div>
                        ` : '<p>No detailed message logs available.</p>'}
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
        } else {
            showToast('Task details not available', 'error');
        }
    } catch (error) {
        showToast('Error loading task details', 'error');
    }
}

function getTaskStatusColor(status) {
    const colors = {
        'running': '#10b981',
        'paused': '#f59e0b',
        'completed': '#10b981',
        'failed': '#ef4444',
        'stopped': '#6b7280'
    };
    return colors[status] || '#6b7280';
}

// Make functions globally available
window.stopTask = stopTask;
window.pauseTask = pauseTask;
window.resumeTask = resumeTask;
window.restartTask = restartTask;
window.deleteTask = deleteTask;
window.showTaskDetails = showTaskDetails;

function getTaskManagerContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>⚙️ Task Manager</h3>
                <div class="task-filters">
                    <select id="task-filter" onchange="loadTasks()">
                        <option value="all">All Tasks</option>
                        <option value="running">Running</option>
                        <option value="completed">Completed</option>
                        <option value="failed">Failed</option>
                        <option value="stopped">Stopped</option>
                    </select>
                    <button class="btn btn-primary" onclick="loadTasks()">
                        <i class="fas fa-sync"></i> Refresh
                    </button>
                </div>
            </div>
            <div class="card-body">
                <div id="tasks-container">
                    <p>Loading tasks...</p>
                </div>
            </div>
        </div>
    `;
}

function updateTaskManagerUI() {
    const container = document.getElementById('active-tasks-container');
    if (!container) return;
    
    if (!window.activeTasks) window.activeTasks = new Map();
    const tasks = Array.from(window.activeTasks.values());
    
    if (tasks.length === 0) {
        container.innerHTML = `
            <div id="no-tasks" style="text-align: center; padding: 2rem; color: var(--text-secondary);">
                <i class="fas fa-tasks" style="font-size: 3rem; margin-bottom: 1rem;"></i>
                <p>No active tasks</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = tasks.map(task => {
        const duration = task.endTime ? 
            Math.round((task.endTime - task.startTime) / 1000) : 
            Math.round((new Date() - task.startTime) / 1000);
        
        const statusColor = {
            'running': '#10b981',
            'paused': '#f59e0b', 
            'stopping': '#ef4444',
            'stopped': '#6b7280',
            'completed': '#10b981',
            'error': '#ef4444'
        }[task.status] || '#6b7280';
        
        return `
            <div class="task-item" style="border: 1px solid var(--border); border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem; background: var(--surface);">
                <div class="task-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <div>
                        <h4 style="margin: 0; color: ${statusColor};">${task.name}</h4>
                        <small style="color: var(--text-secondary);">${task.type} • ${duration}s</small>
                    </div>
                    <div class="task-actions" style="display: flex; gap: 0.5rem;">
                        ${task.canPause && task.status === 'running' ? 
                            `<button class="btn btn-outline btn-small" onclick="pauseTask('${task.id}')">⏸️</button>` : ''}
                        ${task.canPause && task.status === 'paused' ? 
                            `<button class="btn btn-outline btn-small" onclick="pauseTask('${task.id}')">▶️</button>` : ''}
                        ${task.canStop && ['running', 'paused'].includes(task.status) ? 
                            `<button class="btn btn-outline btn-small" onclick="stopTask('${task.id}')">⏹️</button>` : ''}
                    </div>
                </div>
                
                <div class="task-progress" style="margin-bottom: 0.5rem;">
                    <div class="progress-bar" style="background: var(--background); border-radius: 0.25rem; height: 8px; overflow: hidden;">
                        <div style="background: ${statusColor}; height: 100%; width: ${task.progress}%; transition: width 0.3s;"></div>
                    </div>
                </div>
                
                <div class="task-stats" style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.5rem; font-size: 0.8rem;">
                    <div>📊 ${task.processed}/${task.total}</div>
                    <div>✅ ${task.success}</div>
                    <div>❌ ${task.failed}</div>
                    <div style="color: ${statusColor};">● ${task.status.toUpperCase()}</div>
                </div>
            </div>
        `;
    }).join('');
}

async function loadTasks() {
    try {
        const filter = document.getElementById('task-filter')?.value || 'all';
        const response = await fetch(`/api/tasks?status=${filter === 'all' ? '' : filter}`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const tasks = await response.json();
        const container = document.getElementById('tasks-container');
        
        if (tasks.length === 0) {
            container.innerHTML = '<p>No tasks found</p>';
            return;
        }
        
        container.innerHTML = tasks.map(task => {
            const duration = task.completedTime ? 
                Math.round((new Date(task.completedTime) - new Date(task.startTime)) / 1000) : 
                Math.round((new Date() - new Date(task.startTime)) / 1000);
            const progress = task.total > 0 ? Math.round((task.processed / task.total) * 100) : 0;
            
            return `
                <div class="task-item" style="border: 1px solid var(--border); padding: 0.75rem; margin: 0.25rem 0; border-radius: 0.5rem; background: var(--surface);">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div style="flex: 1;">
                            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
                                <h4 style="margin: 0; font-size: 1rem;">${task.name}</h4>
                                <span class="status-badge" style="background: ${getStatusColor(task.status)}; color: white; padding: 0.1rem 0.4rem; border-radius: 0.25rem; font-size: 0.65rem;">${task.status.toUpperCase()}</span>
                            </div>
                            
                            <div class="task-progress" style="margin: 0.25rem 0;">
                                <div style="background: var(--background); border-radius: 0.25rem; height: 6px; overflow: hidden;">
                                    <div style="background: ${getStatusColor(task.status)}; height: 100%; width: ${progress}%; transition: width 0.3s;"></div>
                                </div>
                                <div style="display: flex; justify-content: space-between; font-size: 0.75rem; margin-top: 0.1rem;">
                                    <span>${task.processed}/${task.total} (${progress}%)</span>
                                    <span>${duration}s</span>
                                </div>
                            </div>
                            
                            <div class="task-stats" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.25rem; font-size: 0.75rem; margin: 0.25rem 0;">
                                <div>✅ ${task.success}</div>
                                <div>❌ ${task.failed}</div>
                                <div>📊 ${task.type}</div>
                            </div>
                            
                            <div style="font-size: 0.65rem; color: var(--text-secondary);">
                                <div>Started: ${new Date(task.startTime).toLocaleString()}</div>
                                ${task.completedTime ? `<div>Completed: ${new Date(task.completedTime).toLocaleString()}</div>` : ''}
                            </div>
                        </div>
                        
                        <div class="task-actions" style="display: flex; flex-direction: column; gap: 0.2rem;">
                            ${task.status === 'running' ? `<button class="btn btn-outline btn-small" onclick="pauseTask('${task.id}')" title="Pause">⏸️</button>` : ''}
                            ${task.status === 'paused' ? `<button class="btn btn-outline btn-small" onclick="resumeTask('${task.id}')" title="Resume">▶️</button>` : ''}
                            ${['running', 'paused'].includes(task.status) ? `<button class="btn btn-outline btn-small" onclick="stopTask('${task.id}')" title="Stop">⏹️</button>` : ''}
                            ${task.canRestart ? `<button class="btn btn-primary btn-small" onclick="restartTask('${task.id}')" title="Restart">🔄</button>` : ''}
                            <button class="btn btn-outline btn-small" onclick="showTaskDetails('${task.id}')" title="Details">📄</button>
                            <button class="btn btn-outline btn-small" onclick="deleteTask('${task.id}')" title="Delete">🗑️</button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
        
        function getStatusColor(status) {
            const colors = {
                'running': '#10b981',
                'paused': '#f59e0b',
                'completed': '#10b981',
                'failed': '#ef4444',
                'stopped': '#6b7280'
            };
            return colors[status] || '#6b7280';
        }
        
    } catch (error) {
        document.getElementById('tasks-container').innerHTML = '<p>Error loading tasks</p>';
    }
}

async function stopAllTasks() {
    if (!confirm('Stop all running tasks?')) return;
    
    const runningTasks = Array.from(window.activeTasks.values())
        .filter(task => ['running', 'paused'].includes(task.status));
    
    if (runningTasks.length === 0) {
        showToast('No running tasks to stop', 'info');
        return;
    }
    
    showToast(`Stopping ${runningTasks.length} tasks...`, 'info');
    
    for (const task of runningTasks) {
        await stopTask(task.id);
    }
}

function clearCompletedTasks() {
    Array.from(window.activeTasks.keys()).forEach(taskId => {
        const task = window.activeTasks.get(taskId);
        if (task && ['completed', 'stopped', 'error'].includes(task.status)) {
            window.activeTasks.delete(taskId);
        }
    });
    updateTaskManagerUI();
    showToast('Completed tasks cleared', 'success');
}

async function stopAllTasks() {
    if (!confirm('Stop all running tasks?')) return;
    
    const runningTasks = Array.from(window.activeTasks.values())
        .filter(task => ['running', 'paused'].includes(task.status));
    
    if (runningTasks.length === 0) {
        showToast('No running tasks to stop', 'info');
        return;
    }
    
    try {
        showToast(`Stopping ${runningTasks.length} tasks...`, 'info');
        
        const response = await fetch('/api/campaigns/stop-all', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const data = await response.json();
        
        if (data.success) {
            window.activeTasks.clear();
            updateTaskManagerUI();
            window.currentCampaignId = null;
            window.currentTaskId = null;
            showToast(`Successfully stopped ${data.count} tasks`, 'success');
        } else {
            throw new Error(data.error || 'Failed to stop tasks');
        }
    } catch (error) {
        showToast('Error stopping tasks: ' + error.message, 'error');
        for (const task of runningTasks) {
            await stopTask(task.id);
        }
    }
}

// Global task management functions
window.createTask = createTask;
window.updateTask = updateTask;
window.completeTask = completeTask;
window.stopTask = stopTask;
window.pauseTask = pauseTask;
window.resumeTask = resumeTask;
window.restartTask = restartTask;
window.deleteTask = deleteTask;
window.showTaskDetails = showTaskDetails;
window.loadTasks = loadTasks;
async function showTaskDetails(taskId) {
    try {
        const response = await fetch(`/api/tasks/${taskId}/details`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const data = await response.json();
        
        const modal = document.createElement('div');
        modal.className = 'modal show';
        modal.innerHTML = `
            <div class="modal-content" style="max-width: 800px;">
                <div class="modal-header">
                    <h3>📄 Task Details: ${data.task.task_name || data.task.type}</h3>
                    <button onclick="this.closest('.modal').remove()">×</button>
                </div>
                <div class="modal-body">
                    <div class="task-info" style="margin-bottom: 1rem; padding: 1rem; background: var(--surface); border-radius: 0.5rem;">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                            <div><strong>Type:</strong> ${data.task.type}</div>
                            <div><strong>Status:</strong> ${data.task.status}</div>
                            <div><strong>Total:</strong> ${data.task.total_count || 0}</div>
                            <div><strong>Processed:</strong> ${data.task.processed_count || 0}</div>
                            <div><strong>Success:</strong> ${data.task.success_count || 0}</div>
                            <div><strong>Failed:</strong> ${data.task.failed_count || 0}</div>
                        </div>
                        <div style="margin-top: 1rem;">
                            <div><strong>Started:</strong> ${new Date(data.task.created_at).toLocaleString()}</div>
                            ${data.task.completed_at ? `<div><strong>Completed:</strong> ${new Date(data.task.completed_at).toLocaleString()}</div>` : ''}
                        </div>
                        ${data.task.message_content ? `<div style="margin-top: 1rem;"><strong>Message:</strong><br><div style="background: var(--background); padding: 0.5rem; border-radius: 0.25rem; font-family: monospace;">${data.task.message_content}</div></div>` : ''}
                    </div>
                    
                    <div class="task-details">
                        <h4>Processing Details (Last 100 items)</h4>
                        <div style="max-height: 400px; overflow-y: auto; border: 1px solid var(--border); border-radius: 0.5rem;">
                            ${data.details.length > 0 ? data.details.map(detail => `
                                <div style="padding: 0.5rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between;">
                                    <div>
                                        <strong>${detail.recipient}</strong>
                                        ${detail.message ? `<br><small>${detail.message.substring(0, 50)}...</small>` : ''}
                                        ${detail.error ? `<br><small style="color: var(--error);">${detail.error}</small>` : ''}
                                    </div>
                                    <div style="text-align: right;">
                                        <span class="status-badge" style="background: ${detail.status === 'sent' ? '#10b981' : '#ef4444'}; color: white; padding: 0.2rem 0.5rem; border-radius: 0.25rem; font-size: 0.7rem;">${detail.status}</span>
                                        <br><small>${detail.timestamp ? new Date(detail.timestamp).toLocaleString() : ''}</small>
                                    </div>
                                </div>
                            `).join('') : '<p style="padding: 1rem; text-align: center;">No processing details available</p>'}
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        
    } catch (error) {
        showToast('Error loading task details', 'error');
    }
}

window.loadTasks = loadTasks;
window.stopTask = stopTask;
window.pauseTask = pauseTask;
window.resumeTask = resumeTask;
window.restartTask = restartTask;
window.deleteTask = deleteTask;
window.showTaskDetails = showTaskDetails;

// // Message History
// function getMessageHistoryContent() {
//     return `
//         <div class="card">
//             <div class="card-header">
//                 <h3>📜 Message History</h3>
//                 <select id="history-filter">
//                     <option value="all">All Messages</option>
//                     <option value="single">Single Messages</option>
//                     <option value="bulk">Bulk Messages</option>
//                 </select>
//             </div>
//             <div class="card-body">
//                 <div id="message-history-list">
//                     <p>Loading message history...</p>
//                 </div>
//             </div>
//         </div>
//     `;
// }

// async function loadMessageHistory() {
//     const container = document.getElementById('message-history-list');
//     container.innerHTML = `
//         <div class="history-item">
//             <div>📱 Single Message to +1234567890</div>
//             <div>Hello! This is a test message</div>
//             <small>Today 2:30 PM - ✅ Sent</small>
//         </div>
//         <div class="history-item">
//             <div>📢 Bulk Campaign (50 contacts)</div>
//             <div>Special offer for our customers!</div>
//             <small>Yesterday 10:15 AM - ✅ Completed</small>
//         </div>
//     `;
// }

// Link Generator
function getLinkGeneratorContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>🔗 WhatsApp Link Generator</h3>
            </div>
            <div class="card-body">
                <div class="form-group">
                    <label>Phone Number:</label>
                    <input type="text" id="link-phone" placeholder="+1234567890">
                </div>
                <div class="form-group">
                    <label>Message (Optional):</label>
                    <textarea id="link-message" rows="3" placeholder="Hello!"></textarea>
                </div>
                <button class="btn btn-primary" onclick="generateWhatsAppLink()">Generate Link</button>
                
                <div id="generated-link" style="display: none; margin-top: 1rem;">
                    <label>Generated Link:</label>
                    <div style="display: flex; gap: 0.5rem;">
                        <input type="text" id="wa-link" readonly style="flex: 1;">
                        <button class="btn btn-outline" onclick="copyLink()">Copy</button>
                        <button class="btn btn-primary" onclick="testLink()">Test</button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function generateWhatsAppLink() {
    const phone = document.getElementById('link-phone').value.replace(/[^0-9+]/g, '');
    const message = document.getElementById('link-message').value;
    
    if (!phone) {
        showToast('Please enter a phone number', 'error');
        return;
    }
    
    const encodedMessage = encodeURIComponent(message);
    const link = `https://wa.me/${phone.replace('+', '')}${message ? `?text=${encodedMessage}` : ''}`;
    
    document.getElementById('wa-link').value = link;
    document.getElementById('generated-link').style.display = 'block';
}

function copyLink() {
    const linkInput = document.getElementById('wa-link');
    linkInput.select();
    document.execCommand('copy');
    showToast('Link copied!', 'success');
}

function testLink() {
    const link = document.getElementById('wa-link').value;
    window.open(link, '_blank');
}

// Profile
function getProfileContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>👤 Profile Settings</h3>
            </div>
            <div class="card-body">
                <div class="form-group">
                    <label>Name:</label>
                    <input type="text" id="profile-name" value="${currentUser?.username || ''}">
                </div>
                <div class="form-group">
                    <label>Email:</label>
                    <input type="email" id="profile-email" value="${currentUser?.email || ''}" readonly>
                </div>
                <button class="btn btn-primary" onclick="updateProfile()">Update Profile</button>
                
                <hr style="margin: 2rem 0;">
                
                <h4>Change Password</h4>
                <div class="form-group">
                    <label>Current Password:</label>
                    <input type="password" id="current-password">
                </div>
                <div class="form-group">
                    <label>New Password:</label>
                    <input type="password" id="new-password">
                </div>
                <button class="btn btn-outline" onclick="changePassword()">Change Password</button>
            </div>
        </div>
    `;
}

function loadUserProfile() {
    // Profile loads with current user data
}

function updateProfile() {
    const name = document.getElementById('profile-name').value;
    if (name) {
        currentUser.username = name;
        localStorage.setItem('user', JSON.stringify(currentUser));
        document.getElementById('user-name').textContent = name;
        showToast('Profile updated!', 'success');
    }
}

async function changePassword() {
    const whatsappNumber = prompt('Enter your WhatsApp number for OTP verification:');
    if (!whatsappNumber) return;
    
    const otp = prompt('OTP will be sent to your WhatsApp. Enter OTP:');
    if (otp) {
        const newPassword = document.getElementById('new-password').value;
        if (otp === '1234') { // Demo OTP
            showToast('Password changed successfully!', 'success');
            document.getElementById('current-password').value = '';
            document.getElementById('new-password').value = '';
        } else {
            showToast('Invalid OTP', 'error');
        }
    }
}

window.generateWhatsAppLink = generateWhatsAppLink;
window.copyLink = copyLink;
window.testLink = testLink;
window.updateProfile = updateProfile;

// Group Adder Functions
function getGroupAdderContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>👥 Group Adder</h3>
                <p>Add phone numbers to multiple WhatsApp groups</p>
            </div>
            <div class="card-body">
                <form id="group-adder-form">
                    <div class="form-group">
                        <label>Phone Numbers (one per line)</label>
                        <textarea id="adder-numbers" rows="6" placeholder="1234567890\n0987654321\n+1234567890\n..." required></textarea>
                        <small>Enter phone numbers with or without country codes</small>
                    </div>
                    
                    <div class="form-group">
                        <label>Select Groups to Add Numbers To</label>
                        <div class="group-selection">
                            <div class="select-all-groups">
                                <input type="checkbox" id="select-all-adder-groups">
                                <label for="select-all-adder-groups">Select All Groups</label>
                            </div>
                            <div id="adder-groups-checkboxes">
                                <p>Loading groups...</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="timing-controls">
                        <h4>⏱️ Timing Controls</h4>
                        <div class="timing-options">
                            <div class="timing-option">
                                <input type="radio" id="adder-fixed-delay" name="adderDelayType" value="fixed" checked>
                                <label for="adder-fixed-delay">Fixed Delay</label>
                            </div>
                            <div class="timing-option">
                                <input type="radio" id="adder-random-delay" name="adderDelayType" value="random">
                                <label for="adder-random-delay">Random Delay</label>
                            </div>
                        </div>
                        
                        <div class="delay-inputs">
                            <div class="form-group" id="adder-fixed-delay-input">
                                <label>Delay (seconds)</label>
                                <input type="number" id="adder-fixed-delay-value" min="3" max="300" value="5">
                            </div>
                            <div class="form-group" id="adder-random-delay-inputs" style="display: none;">
                                <label>Min Delay (seconds)</label>
                                <input type="number" id="adder-min-delay" min="3" max="300" value="5">
                            </div>
                            <div class="form-group" id="adder-random-delay-inputs-max" style="display: none;">
                                <label>Max Delay (seconds)</label>
                                <input type="number" id="adder-max-delay" min="3" max="300" value="15">
                            </div>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary btn-large">
                        <i class="fas fa-user-plus"></i> Add Numbers to Groups
                    </button>
                </form>
                
                <div id="adder-progress" style="display: none;">
                    <div class="progress-container">
                        <div class="progress-header">
                            <h4>👥 Adding Numbers to Groups...</h4>
                            <button id="stop-adder" class="btn btn-outline btn-small">Stop</button>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" id="adder-progress-fill"></div>
                        </div>
                        <div class="progress-stats">
                            <div class="progress-text" id="adder-progress-text">0 / 0 operations</div>
                            <div class="progress-details">
                                <span class="success-count">✅ <span id="adder-success-count">0</span></span>
                                <span class="failed-count">❌ <span id="adder-failed-count">0</span></span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div id="adder-results" style="display: none;">
                    <div class="results-header">
                        <h4>📊 Group Adder Results</h4>
                    </div>
                    <div id="adder-results-list"></div>
                </div>
            </div>
        </div>
    `;
}

function setupGroupAdderHandlers() {
    document.getElementById('group-adder-form').addEventListener('submit', addNumbersToGroups);
    document.getElementById('select-all-adder-groups').addEventListener('change', toggleAllAdderGroups);
    
    document.querySelectorAll('input[name="adderDelayType"]').forEach(radio => {
        radio.addEventListener('change', toggleAdderDelayInputs);
    });
}

async function loadGroupsForAdder() {
    try {
        const response = await fetch('/api/groups', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const groups = await response.json();
        
        const container = document.getElementById('adder-groups-checkboxes');
        if (groups.length === 0) {
            container.innerHTML = '<p>No groups found. Connect WhatsApp first.</p>';
            return;
        }
        
        // Only show groups where user is admin
        const adminGroups = groups.filter(group => group.isAdmin);
        
        if (adminGroups.length === 0) {
            container.innerHTML = '<p>No groups found where you are admin. You need admin rights to add members.</p>';
            return;
        }
        
        container.innerHTML = adminGroups.map(group => `
            <div class="group-checkbox">
                <input type="checkbox" id="adder-group-${group.id}" value="${group.id}">
                <label for="adder-group-${group.id}">
                    <strong>${group.name}</strong>
                    <span>(${group.participantCount} members) - Admin</span>
                </label>
            </div>
        `).join('');
        
    } catch (error) {
        document.getElementById('adder-groups-checkboxes').innerHTML = '<p>Error loading groups</p>';
    }
}

function toggleAllAdderGroups() {
    const selectAll = document.getElementById('select-all-adder-groups').checked;
    document.querySelectorAll('#adder-groups-checkboxes input[type="checkbox"]').forEach(checkbox => {
        checkbox.checked = selectAll;
    });
}

function toggleAdderDelayInputs() {
    const delayType = document.querySelector('input[name="adderDelayType"]:checked').value;
    const fixedInput = document.getElementById('adder-fixed-delay-input');
    const randomInputs = document.getElementById('adder-random-delay-inputs');
    const randomInputsMax = document.getElementById('adder-random-delay-inputs-max');
    
    if (delayType === 'fixed') {
        fixedInput.style.display = 'block';
        randomInputs.style.display = 'none';
        randomInputsMax.style.display = 'none';
    } else {
        fixedInput.style.display = 'none';
        randomInputs.style.display = 'block';
        randomInputsMax.style.display = 'block';
    }
}

async function addNumbersToGroups(e) {
    e.preventDefault();
    
    const numbersText = document.getElementById('adder-numbers').value;
    const numbers = numbersText.split('\n').filter(n => n.trim());
    
    const selectedGroups = Array.from(document.querySelectorAll('#adder-groups-checkboxes input[type="checkbox"]:checked'))
        .map(cb => cb.value);
    
    if (numbers.length === 0) {
        showToast('Please enter at least one phone number', 'error');
        return;
    }
    
    if (selectedGroups.length === 0) {
        showToast('Please select at least one group', 'error');
        return;
    }
    
    const delayType = document.querySelector('input[name="adderDelayType"]:checked').value;
    const fixedDelay = document.getElementById('adder-fixed-delay-value').value;
    const minDelay = document.getElementById('adder-min-delay').value;
    const maxDelay = document.getElementById('adder-max-delay').value;
    
    document.getElementById('adder-progress').style.display = 'block';
    document.getElementById('adder-results').style.display = 'none';
    
    // Create task in Task Manager
    const totalOperations = numbers.length * selectedGroups.length;
    const taskId = createTask('Group Adder Campaign', 'group_adder', {
        total: totalOperations,
        canStop: true,
        canPause: false
    });
    window.currentTaskId = taskId;
    
    document.getElementById('adder-success-count').textContent = '0';
    document.getElementById('adder-failed-count').textContent = '0';
    
    try {
        const response = await fetch('/api/groups/add-numbers', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                numbers: numbers,
                selectedGroups: selectedGroups,
                delayType: delayType,
                fixedDelay: fixedDelay,
                minDelay: minDelay,
                maxDelay: maxDelay
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayAdderResults(data.results);
            const successCount = data.results.filter(r => r.status === 'added').length;
            
            // Update task manager
            if (window.currentTaskId) {
                updateTask(window.currentTaskId, {
                    progress: 100,
                    processed: data.results.length,
                    success: successCount,
                    failed: data.results.length - successCount
                });
                completeTask(window.currentTaskId, 'completed');
            }
            
            showToast(`Group adding completed! ${successCount}/${data.results.length} operations successful`, 'success');
        } else {
            if (window.currentTaskId) {
                completeTask(window.currentTaskId, 'error');
            }
            showToast(data.error || 'Group adding failed', 'error');
        }
    } catch (error) {
        if (window.currentTaskId) {
            completeTask(window.currentTaskId, 'error');
        }
        showToast('Error adding numbers to groups', 'error');
    }
}

function displayAdderResults(results) {
    const resultsContainer = document.getElementById('adder-results');
    const resultsList = document.getElementById('adder-results-list');
    
    resultsList.innerHTML = results.map(result => `
        <div class="result-item" style="padding: 0.75rem; border-left: 3px solid ${result.status === 'added' ? '#10b981' : '#ef4444'}; margin-bottom: 0.5rem; background: var(--surface); border-radius: 0.25rem;">
            <div>
                <strong>${result.number}</strong> → <strong>${result.groupName}</strong>
                <span class="status-badge ${result.status}">${result.status === 'added' ? '✅ Added' : '❌ Failed'}</span>
            </div>
            ${result.error ? `<small style="color: var(--error);">${result.error}</small>` : ''}
        </div>
    `).join('');
    
    resultsContainer.style.display = 'block';
    document.getElementById('adder-progress').style.display = 'none';
}

// Global functions for Group Adder
window.getGroupAdderContent = getGroupAdderContent;
window.setupGroupAdderHandlers = setupGroupAdderHandlers;
window.loadGroupsForAdder = loadGroupsForAdder;
window.toggleAllAdderGroups = toggleAllAdderGroups;
window.addNumbersToGroups = addNumbersToGroups;
async function changePassword() {
    const whatsappNumber = prompt('Enter your WhatsApp number for OTP (format: 923001234567):');
    if (!whatsappNumber) return;
    
    // Validate WhatsApp number format
    const cleanNumber = whatsappNumber.replace(/[^0-9]/g, '');
    if (cleanNumber.length < 10 || cleanNumber.length > 15) {
        showToast('Please enter WhatsApp number in format: 923001234567 (with country code, no + or spaces)', 'error');
        return;
    }
    
    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    
    if (!currentPassword || !newPassword) {
        showToast('Please fill in both password fields', 'error');
        return;
    }
    
    try {
        // Request OTP from admin
        const otpResponse = await fetch('/api/send-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                whatsappNumber: whatsappNumber,
                adminNumber: '923400885132',
                purpose: 'password_change'
            })
        });
        
        const otpData = await otpResponse.json();
        if (!otpData.success) {
            showToast('Failed to send OTP. Please try again.', 'error');
            return;
        }
        
        showToast('OTP sent to your WhatsApp from admin (923400885132)', 'info');
        
        setTimeout(async () => {
            const otp = prompt('Enter OTP received on WhatsApp:');
            if (!otp) return;
            
            try {
                // Verify OTP and change password
                const response = await fetch('/api/change-password', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('token')}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        currentPassword: currentPassword,
                        newPassword: newPassword,
                        whatsappNumber: whatsappNumber,
                        otp: otp
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showToast('Password changed successfully!', 'success');
                    document.getElementById('current-password').value = '';
                    document.getElementById('new-password').value = '';
                } else {
                    showToast(data.error || 'Failed to change password', 'error');
                }
            } catch (error) {
                showToast('Error changing password', 'error');
            }
        }, 2000);
        
    } catch (error) {
        showToast('Error sending OTP. Please try again.', 'error');
    }
}

window.sendOTP = sendOTP;
window.changePassword = changePassword;
window.loadMessageHistory = loadMessageHistory;
window.loadUserProfile = loadUserProfile;
// Group Adder Functions
function getGroupAdderContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>👥 Group Adder</h3>
                <p>Add phone numbers to WhatsApp groups ultra</p>
            </div>
            <div class="card-body">
                <form id="group-adder-form">
                    <div class="form-group">
                        <label>Phone Numbers to Add (one per line)</label>
                        <textarea id="adder-numbers" rows="6" placeholder="1234567890
0987654321
+1234567890" required></textarea>
                        <small>Enter phone numbers with or without country codes</small>
                    </div>
                    
                    <div class="form-group">
                        <label>Select Groups</label>
                        <div class="group-selection">
                            <div class="select-all-groups">
                                <input type="checkbox" id="select-all-adder-groups">
                                <label for="select-all-adder-groups">Select All Groups</label>
                            </div>
                            <div id="adder-groups-checkboxes">
                                <p>Loading groups...</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="timing-controls">
                        <h4>⏱️ Timing Controls</h4>
                        <div class="timing-options">
                            <div class="timing-option">
                                <input type="radio" id="adder-fixed-delay" name="adderDelayType" value="fixed" checked>
                                <label for="adder-fixed-delay">Fixed Delay</label>
                            </div>
                            <div class="timing-option">
                                <input type="radio" id="adder-random-delay" name="adderDelayType" value="random">
                                <label for="adder-random-delay">Random Delay</label>
                            </div>
                        </div>
                        
                        <div class="delay-inputs">
                            <div class="form-group" id="adder-fixed-delay-input">
                                <label>Delay (seconds)</label>
                                <input type="number" id="adder-fixed-delay-value" min="2" max="300" value="5">
                            </div>
                            <div class="form-group" id="adder-random-delay-inputs" style="display: none;">
                                <label>Min Delay (seconds)</label>
                                <input type="number" id="adder-min-delay" min="2" max="300" value="3">
                            </div>
                            <div class="form-group" id="adder-random-delay-inputs-max" style="display: none;">
                                <label>Max Delay (seconds)</label>
                                <input type="number" id="adder-max-delay" min="2" max="300" value="10">
                            </div>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary btn-large">
                        <i class="fas fa-user-plus"></i> Add Numbers to Groups
                    </button>
                </form>
                
                <div id="adder-progress" style="display: none;">
                    <div class="progress-container">
                        <div class="progress-header">
                            <h4>👥 Adding Numbers...</h4>
                            <button id="stop-adder" class="btn btn-outline btn-small">Stop</button>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" id="adder-progress-fill"></div>
                        </div>
                        <div class="progress-stats">
                            <div class="progress-text" id="adder-progress-text">0 / 0 operations</div>
                            <div class="progress-details">
                                <span class="success-count">✅ <span id="adder-success-count">0</span></span>
                                <span class="failed-count">❌ <span id="adder-failed-count">0</span></span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div id="adder-results" style="display: none;">
                    <div class="results-header">
                        <h4>📊 Group Adder Results</h4>
                    </div>
                    <div id="adder-results-list"></div>
                </div>
            </div>
        </div>
    `;
}

function setupGroupAdderHandlers() {
    document.getElementById('group-adder-form').addEventListener('submit', addNumbersToGroups);
    document.getElementById('select-all-adder-groups').addEventListener('change', toggleAllAdderGroups);
    
    document.querySelectorAll('input[name="adderDelayType"]').forEach(radio => {
        radio.addEventListener('change', toggleAdderDelayInputs);
    });
}

async function loadGroupsForAdder() {
    try {
        const response = await fetch('/api/groups', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const groups = await response.json();
        
        const container = document.getElementById('adder-groups-checkboxes');
        if (groups.length === 0) {
            container.innerHTML = '<p>No groups found. Connect WhatsApp first.</p>';
            return;
        }
        
        container.innerHTML = groups.map(group => `
            <div class="group-checkbox">
                <input type="checkbox" id="adder-group-${group.id}" value="${group.id}">
                <label for="adder-group-${group.id}">
                    <strong>${group.name}</strong>
                    <span>(${group.participantCount} members)</span>
                </label>
            </div>
        `).join('');
        
    } catch (error) {
        document.getElementById('adder-groups-checkboxes').innerHTML = '<p>Error loading groups</p>';
    }
}

function toggleAllAdderGroups() {
    const selectAll = document.getElementById('select-all-adder-groups').checked;
    document.querySelectorAll('#adder-groups-checkboxes input[type="checkbox"]').forEach(checkbox => {
        checkbox.checked = selectAll;
    });
}

function toggleAdderDelayInputs() {
    const delayType = document.querySelector('input[name="adderDelayType"]:checked').value;
    const fixedInput = document.getElementById('adder-fixed-delay-input');
    const randomInputs = document.getElementById('adder-random-delay-inputs');
    const randomInputsMax = document.getElementById('adder-random-delay-inputs-max');
    
    if (delayType === 'fixed') {
        fixedInput.style.display = 'block';
        randomInputs.style.display = 'none';
        randomInputsMax.style.display = 'none';
    } else {
        fixedInput.style.display = 'none';
        randomInputs.style.display = 'block';
        randomInputsMax.style.display = 'block';
    }
}

async function addNumbersToGroups(e) {
    e.preventDefault();
    
    const numbersText = document.getElementById('adder-numbers').value;
    const numbers = numbersText.split('\n').filter(n => n.trim());
    
    const selectedGroups = Array.from(document.querySelectorAll('#adder-groups-checkboxes input[type="checkbox"]:checked'))
        .map(cb => cb.value);
    
    if (numbers.length === 0) {
        showToast('Please enter at least one phone number', 'error');
        return;
    }
    
    if (selectedGroups.length === 0) {
        showToast('Please select at least one group', 'error');
        return;
    }
    
    const delayType = document.querySelector('input[name="adderDelayType"]:checked').value;
    const fixedDelay = document.getElementById('adder-fixed-delay-value').value;
    const minDelay = document.getElementById('adder-min-delay').value;
    const maxDelay = document.getElementById('adder-max-delay').value;
    
    document.getElementById('adder-progress').style.display = 'block';
    document.getElementById('adder-results').style.display = 'none';
    
    const taskId = createTask('Group Adder Campaign', 'group_adder', {
        total: numbers.length * selectedGroups.length,
        canStop: true,
        canPause: true
    });
    window.currentTaskId = taskId;
    
    document.getElementById('adder-success-count').textContent = '0';
    document.getElementById('adder-failed-count').textContent = '0';
    
    try {
        const response = await fetch('/api/groups/add-numbers', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                numbers: numbers,
                selectedGroups: selectedGroups,
                delayType: delayType,
                fixedDelay: fixedDelay,
                minDelay: minDelay,
                maxDelay: maxDelay
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayAdderResults(data.results);
            const successCount = data.results.filter(r => r.status === 'added').length;
            
            if (window.currentTaskId) {
                updateTask(window.currentTaskId, {
                    progress: 100,
                    processed: data.results.length,
                    success: successCount,
                    failed: data.results.length - successCount
                });
                completeTask(window.currentTaskId, 'completed');
            }
            
            showToast(`Operation completed! ${successCount}/${data.results.length} numbers added`, 'success');
        } else {
            if (window.currentTaskId) {
                completeTask(window.currentTaskId, 'error');
            }
            showToast(data.error || 'Group adder failed', 'error');
        }
    } catch (error) {
        if (window.currentTaskId) {
            completeTask(window.currentTaskId, 'error');
        }
        showToast('Error adding numbers to groups', 'error');
    }
}

function displayAdderResults(results) {
    const resultsContainer = document.getElementById('adder-results');
    const resultsList = document.getElementById('adder-results-list');
    
    resultsList.innerHTML = results.map(result => `
        <div class="result-item" style="padding: 0.75rem; border-left: 3px solid ${result.status === 'added' ? '#10b981' : '#ef4444'}; margin-bottom: 0.5rem; background: var(--surface); border-radius: 0.25rem;">
            <div>
                <strong>${result.number}</strong> → <strong>${result.groupName}</strong>
                <span class="status-badge ${result.status}">${result.status === 'added' ? '✅ Added' : '❌ Failed'}</span>
            </div>
            ${result.error ? `<small style="color: var(--error);">${result.error}</small>` : ''}
        </div>
    `).join('');
    
    resultsContainer.style.display = 'block';
    document.getElementById('adder-progress').style.display = 'none';
}

window.toggleAllAdderGroups = toggleAllAdderGroups;

// Group Adder Functions
function getGroupAdderContent() {
    return `
        <div class="card">
            <div class="card-header">
                <h3>👥 Group Adder</h3>
                <p>Add phone numbers to WhatsApp groups ultra</p>
            </div>
            <div class="card-body">
                <form id="group-adder-form">
                    <div class="form-group">
                        <label>Phone Numbers (one per line)</label>
                        <textarea id="adder-numbers" rows="6" placeholder="1234567890\n0987654321\n+1234567890" required></textarea>
                        <small>Enter phone numbers with or without country codes</small>
                    </div>
                    
                    <div class="form-group">
                        <label>Select Groups</label>
                        <div class="group-selection">
                            <div class="select-all-groups">
                                <input type="checkbox" id="select-all-adder-groups">
                                <label for="select-all-adder-groups">Select All Groups</label>
                            </div>
                            <div id="adder-groups-checkboxes">
                                <p>Loading groups...</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="timing-controls">
                        <h4>⏱️ Timing Controls</h4>
                        <div class="timing-options">
                            <div class="timing-option">
                                <input type="radio" id="adder-fixed-delay" name="adderDelayType" value="fixed" checked>
                                <label for="adder-fixed-delay">Fixed Delay</label>
                            </div>
                            <div class="timing-option">
                                <input type="radio" id="adder-random-delay" name="adderDelayType" value="random">
                                <label for="adder-random-delay">Random Delay</label>
                            </div>
                        </div>
                        
                        <div class="delay-inputs">
                            <div class="form-group" id="adder-fixed-delay-input">
                                <label>Delay (seconds)</label>
                                <input type="number" id="adder-fixed-delay-value" min="3" max="300" value="5">
                            </div>
                            <div class="form-group" id="adder-random-delay-inputs" style="display: none;">
                                <label>Min Delay (seconds)</label>
                                <input type="number" id="adder-min-delay" min="3" max="300" value="3">
                            </div>
                            <div class="form-group" id="adder-random-delay-inputs-max" style="display: none;">
                                <label>Max Delay (seconds)</label>
                                <input type="number" id="adder-max-delay" min="3" max="300" value="10">
                            </div>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary btn-large">
                        <i class="fas fa-user-plus"></i> Add Numbers to Groups
                    </button>
                </form>
                
                <div id="adder-progress" style="display: none;">
                    <div class="progress-container">
                        <div class="progress-header">
                            <h4>👥 Adding Numbers...</h4>
                            <button id="stop-adder" class="btn btn-outline btn-small">Stop</button>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" id="adder-progress-fill"></div>
                        </div>
                        <div class="progress-stats">
                            <div class="progress-text" id="adder-progress-text">0 / 0 operations</div>
                            <div class="progress-details">
                                <span class="success-count">✅ <span id="adder-success-count">0</span></span>
                                <span class="failed-count">❌ <span id="adder-failed-count">0</span></span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div id="adder-results" style="display: none;">
                    <div class="results-header">
                        <h4>📊 Group Adder Results</h4>
                    </div>
                    <div id="adder-results-list"></div>
                </div>
            </div>
        </div>
    `;
}

function setupGroupAdderHandlers() {
    document.getElementById('group-adder-form').addEventListener('submit', addNumbersToGroups);
    document.getElementById('select-all-adder-groups').addEventListener('change', toggleAllAdderGroups);
    
    document.querySelectorAll('input[name="adderDelayType"]').forEach(radio => {
        radio.addEventListener('change', toggleAdderDelayInputs);
    });
}

async function loadGroupsForAdder() {
    try {
        const response = await fetch('/api/groups', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        const groups = await response.json();
        
        const container = document.getElementById('adder-groups-checkboxes');
        if (groups.length === 0) {
            container.innerHTML = '<p>No groups found. Connect WhatsApp first.</p>';
            return;
        }
        
        container.innerHTML = groups.map(group => `
            <div class="group-checkbox">
                <input type="checkbox" id="adder-group-${group.id}" value="${group.id}">
                <label for="adder-group-${group.id}">
                    <strong>${group.name}</strong>
                    <span>(${group.participantCount} members)</span>
                </label>
            </div>
        `).join('');
        
    } catch (error) {
        document.getElementById('adder-groups-checkboxes').innerHTML = '<p>Error loading groups</p>';
    }
}

function toggleAllAdderGroups() {
    const selectAll = document.getElementById('select-all-adder-groups').checked;
    document.querySelectorAll('#adder-groups-checkboxes input[type="checkbox"]').forEach(checkbox => {
        checkbox.checked = selectAll;
    });
}

function toggleAdderDelayInputs() {
    const delayType = document.querySelector('input[name="adderDelayType"]:checked').value;
    const fixedInput = document.getElementById('adder-fixed-delay-input');
    const randomInputs = document.getElementById('adder-random-delay-inputs');
    const randomInputsMax = document.getElementById('adder-random-delay-inputs-max');
    
    if (delayType === 'fixed') {
        fixedInput.style.display = 'block';
        randomInputs.style.display = 'none';
        randomInputsMax.style.display = 'none';
    } else {
        fixedInput.style.display = 'none';
        randomInputs.style.display = 'block';
        randomInputsMax.style.display = 'block';
    }
}

async function addNumbersToGroups(e) {
    e.preventDefault();
    
    const numbersText = document.getElementById('adder-numbers').value;
    const numbers = numbersText.split('\n').filter(n => n.trim());
    
    const selectedGroups = Array.from(document.querySelectorAll('#adder-groups-checkboxes input[type="checkbox"]:checked'))
        .map(cb => cb.value);
    
    if (numbers.length === 0) {
        showToast('Please enter at least one phone number', 'error');
        return;
    }
    
    if (selectedGroups.length === 0) {
        showToast('Please select at least one group', 'error');
        return;
    }
    
    const delayType = document.querySelector('input[name="adderDelayType"]:checked').value;
    const fixedDelay = document.getElementById('adder-fixed-delay-value').value;
    const minDelay = document.getElementById('adder-min-delay').value;
    const maxDelay = document.getElementById('adder-max-delay').value;
    
    document.getElementById('adder-progress').style.display = 'block';
    document.getElementById('adder-results').style.display = 'none';
    
    // Create task in Task Manager
    const totalOperations = numbers.length * selectedGroups.length;
    const taskId = createTask('Group Adder Campaign', 'group_adder', {
        total: totalOperations,
        canStop: true,
        canPause: false
    });
    window.currentTaskId = taskId;
    
    document.getElementById('adder-success-count').textContent = '0';
    document.getElementById('adder-failed-count').textContent = '0';
    
    try {
        const response = await fetch('/api/groups/add-numbers', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                numbers: numbers,
                selectedGroups: selectedGroups,
                delayType: delayType,
                fixedDelay: fixedDelay,
                minDelay: minDelay,
                maxDelay: maxDelay
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayAdderResults(data.results);
            const successCount = data.results.filter(r => r.status === 'added').length;
            
            // Update task manager
            if (window.currentTaskId) {
                updateTask(window.currentTaskId, {
                    progress: 100,
                    processed: data.results.length,
                    success: successCount,
                    failed: data.results.length - successCount
                });
                completeTask(window.currentTaskId, 'completed');
            }
            
            showToast(`Group Adder completed! ${successCount}/${data.results.length} operations successful`, 'success');
        } else {
            if (window.currentTaskId) {
                completeTask(window.currentTaskId, 'error');
            }
            showToast(data.error || 'Group Adder failed', 'error');
        }
    } catch (error) {
        if (window.currentTaskId) {
            completeTask(window.currentTaskId, 'error');
        }
        showToast('Error adding numbers to groups', 'error');
    }
}

function displayAdderResults(results) {
    const resultsContainer = document.getElementById('adder-results');
    const resultsList = document.getElementById('adder-results-list');
    
    resultsList.innerHTML = results.map(result => `
        <div class="result-item" style="padding: 0.75rem; border-left: 3px solid ${result.status === 'added' ? '#10b981' : '#ef4444'}; margin-bottom: 0.5rem; background: var(--surface); border-radius: 0.25rem;">
            <div>
                <strong>${result.number}</strong> → <strong>${result.groupName}</strong>
                <span class="status-badge ${result.status}">${result.status === 'added' ? '✅ Added' : '❌ Failed'}</span>
            </div>
            ${result.error ? `<small style="color: var(--error);">${result.error}</small>` : ''}
        </div>
    `).join('');
    
    resultsContainer.style.display = 'block';
    document.getElementById('adder-progress').style.display = 'none';
}

// Global functions for Group Adder
window.setupGroupAdderHandlers = setupGroupAdderHandlers;
window.loadGroupsForAdder = loadGroupsForAdder;
window.toggleAllAdderGroups = toggleAllAdderGroups;
window.addNumbersToGroups = addNumbersToGroups;

function showTaskDetails(taskId) {
    alert('Task ID: ' + taskId);
}

function pauseTask(taskId) {
    if (confirm('Pause task?')) {
        fetch(`/api/tasks/${taskId}/pause`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        }).then(() => loadTasks());
    }
}

function resumeTask(taskId) {
    fetch(`/api/tasks/${taskId}/resume`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
    }).then(() => loadTasks());
}

function stopTask(taskId) {
    if (confirm('Stop task?')) {
        fetch(`/api/tasks/${taskId}/stop`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        }).then(() => loadTasks());
    }
}

function restartTask(taskId) {
    if (confirm('Restart task?')) {
        fetch(`/api/tasks/${taskId}/restart`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        }).then(() => loadTasks());
    }
}

function deleteTask(taskId) {
    if (confirm('Delete task?')) {
        fetch(`/api/tasks/${taskId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        }).then(() => loadTasks());
    }
}