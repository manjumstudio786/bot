# WhatsApp Automation Pro 🚀

A professional WhatsApp bulk messaging platform with advanced features for marketing, customer engagement, and business automation.

![WhatsApp Pro](https://img.shields.io/badge/WhatsApp-Pro-25D366?style=for-the-badge&logo=whatsapp)
![Node.js](https://img.shields.io/badge/Node.js-18+-339933?style=for-the-badge&logo=node.js)
![MySQL](https://img.shields.io/badge/MySQL-8.0+-4479A1?style=for-the-badge&logo=mysql)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

## 📋 Table of Contents

- [Features](#-features)
- [Screenshots](#-screenshots)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [API Documentation](#-api-documentation)
- [Security](#-security)
- [Contributing](#-contributing)
- [License](#-license)
- [Support](#-support)

## ✨ Features

### 🔐 **Authentication & Security**
- JWT-based secure authentication
- User registration with OTP verification
- Password encryption with bcrypt
- Session management and user isolation
- Subscription-based access control

### 📱 **WhatsApp Integration**
- QR code-based WhatsApp Web connection
- Multi-device support
- Session persistence and auto-reconnection
- Real-time connection status monitoring
- Anti-ban protection with smart delays

### 💬 **Messaging Features**
- **Single Messages**: Send text, images, videos, audio, and documents
- **Bulk Messaging**: Send to multiple contacts with customizable delays
- **CSV Bulk Sender**: Import contacts from CSV with personalized messages
- **Group Broadcasting**: Send messages to multiple WhatsApp groups
- **Contact Broadcasting**: Send messages to all contacts at once
- **Message Scheduling**: Schedule messages for future delivery

### 👥 **Contact & Group Management**
- Extract phone numbers from WhatsApp groups
- Contact import/export (CSV, Google Contacts format)
- Contact tagging and organization
- Group creation and management
- Duplicate contact removal
- Contact activity tracking

### 🤖 **Automation Features**
- **Auto Chat Bot**: Respond to messages with exact match or keyword rules
- **Auto Reply System**: Automated responses with customizable rules
- **Message Templates**: Create and manage reusable message templates
- **Smart Timing**: Fixed delays, random intervals, and intelligent scheduling

### 📊 **Analytics & Reporting**
- Real-time campaign progress tracking
- Delivery reports and success rates
- Message history and logs
- User activity analytics
- Campaign performance metrics
- Downloadable CSV reports

### ⚙️ **Advanced Features**
- **Task Manager**: Monitor and control all running campaigns
- **Message Queue**: Reliable message delivery system
- **Link Generator**: Create WhatsApp chat links
- **Profile Management**: User settings and password change
- **Subscription Management**: Trial and premium account handling

## 📸 Screenshots

### Landing Page
![Landing Page](docs/screenshots/landing.png)

### Dashboard Overview
![Dashboard](docs/screenshots/dashboard.png)

### Bulk Messaging
![Bulk Messaging](docs/screenshots/bulk-messaging.png)

### Group Management
![Group Management](docs/screenshots/groups.png)

## 🚀 Installation

### Prerequisites
- Node.js 18+ 
- MySQL 8.0+
- Git

### Quick Start

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/whatsapp-automation-pro.git
cd whatsapp-automation-pro
```

2. **Install dependencies**
```bash
npm install
```

3. **Set up environment variables**
```bash
cp .env.example .env
```

Edit `.env` file with your configuration:
```env
# Database Configuration
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_secure_password
DB_NAME=whatsapp_bot_pro
DB_PORT=3306

# JWT Secret (CHANGE THIS IN PRODUCTION)
JWT_SECRET=your_super_secure_jwt_secret_key_here_minimum_32_characters

# Server Configuration
PORT=3000
NODE_ENV=production
```

4. **Set up MySQL database**
```sql
CREATE DATABASE whatsapp_bot_pro;
```

5. **Start the application**
```bash
npm start
```

6. **Access the application**
Open your browser and navigate to `http://localhost:3000`

## ⚙️ Configuration

### Database Setup
The application automatically creates all required tables on first run. No manual database setup required.

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `DB_HOST` | MySQL host | Yes | localhost |
| `DB_USER` | MySQL username | Yes | root |
| `DB_PASSWORD` | MySQL password | Yes | - |
| `DB_NAME` | Database name | Yes | whatsapp_bot_pro |
| `DB_PORT` | MySQL port | No | 3306 |
| `JWT_SECRET` | JWT signing secret | Yes | - |
| `PORT` | Server port | No | 3000 |
| `NODE_ENV` | Environment | No | development |

### Security Configuration
- Change default JWT secret in production
- Use strong database passwords
- Enable HTTPS in production
- Configure firewall rules
- Set up reverse proxy (nginx/Apache)

## 📖 Usage

### Getting Started

1. **Register an Account**
   - Visit the landing page
   - Click "Get Started" 
   - Fill in your details and verify with OTP

2. **Connect WhatsApp**
   - Go to "Connect WhatsApp" section
   - Scan the QR code with your WhatsApp
   - Wait for connection confirmation

3. **Send Your First Message**
   - Navigate to "Single Message"
   - Enter recipient number and message
   - Click "Send Message"

### Bulk Messaging

1. **Prepare Contact List**
   - Go to "Bulk Messages"
   - Enter phone numbers (one per line)
   - Or use CSV import feature

2. **Configure Message**
   - Choose message type (text, image, video, etc.)
   - Enter your message content
   - Upload media if needed

3. **Set Timing**
   - Choose fixed or random delays
   - Set appropriate intervals (minimum 2 seconds)
   - Start the campaign

### CSV Bulk Sender

1. **Prepare CSV File**
   ```csv
   phone,name,message
   1234567890,John,Hello John! Special offer for you
   0987654321,Sarah,Hi Sarah! Check our new products
   ```

2. **Upload and Send**
   - Upload your CSV file
   - Preview the data
   - Configure timing settings
   - Start the campaign

### Group Management

1. **Extract Numbers**
   - Go to "Group Manager"
   - Click "Extract Numbers" on any group
   - Copy or download the extracted numbers

2. **Group Broadcasting**
   - Navigate to "Group Broadcast"
   - Select target groups
   - Compose your message
   - Send to all selected groups

### Auto Chat Bot

1. **Enable Bot**
   - Go to "Auto Chat Bot"
   - Toggle "Enable Bot"

2. **Add Rules**
   - **Exact Match**: Bot responds when message exactly matches
   - **Keyword Match**: Bot responds when keywords are found

3. **Monitor Activity**
   - View bot responses in real-time
   - Check activity logs

## 🔌 API Documentation

### Authentication

#### Register User
```http
POST /api/register
Content-Type: application/json

{
  "username": "John Doe",
  "email": "john@example.com",
  "password": "securepassword"
}
```

#### Login
```http
POST /api/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "securepassword"
}
```

### WhatsApp Operations

#### Connect WhatsApp
```http
POST /api/whatsapp/connect
Authorization: Bearer <token>
```

#### Send Single Message
```http
POST /api/send-message
Authorization: Bearer <token>
Content-Type: multipart/form-data

{
  "number": "1234567890",
  "message": "Hello World!",
  "messageType": "text"
}
```

#### Send Bulk Messages
```http
POST /api/bulk-message
Authorization: Bearer <token>
Content-Type: multipart/form-data

{
  "numbers": "1234567890\n0987654321",
  "message": "Bulk message content",
  "messageType": "text",
  "delayType": "fixed",
  "fixedDelay": "5"
}
```

### Group Operations

#### Get Groups
```http
GET /api/groups
Authorization: Bearer <token>
```

#### Extract Group Numbers
```http
GET /api/groups/{groupId}/extract-numbers
Authorization: Bearer <token>
```

#### Group Broadcast
```http
POST /api/groups/broadcast
Authorization: Bearer <token>
Content-Type: multipart/form-data

{
  "message": "Broadcast message",
  "selectedGroups": ["group1", "group2"],
  "messageType": "text"
}
```

### Analytics

#### Get Analytics
```http
GET /api/analytics?range=week
Authorization: Bearer <token>
```

## 🔒 Security

### Security Features Implemented

✅ **Authentication & Authorization**
- JWT tokens with secure validation
- Password hashing with bcrypt (10 rounds)
- User session isolation
- Subscription-based access control

✅ **Data Protection**
- User data isolation (each user only sees their own data)
- Parameterized SQL queries (SQL injection protection)
- Input sanitization and validation
- File upload restrictions

✅ **Network Security**
- CORS configuration for production
- Rate limiting (100 requests per 15 minutes)
- File upload size limits (50MB max)
- HTTPS-ready configuration

✅ **Privacy Protection**
- WhatsApp sessions isolated per user
- Campaign data segregated by user ID
- Contact data user-specific
- Message logs tied to users

### Production Security Checklist

- [ ] Set strong JWT_SECRET (32+ characters)
- [ ] Use strong database passwords
- [ ] Enable HTTPS/SSL certificates
- [ ] Configure firewall rules
- [ ] Set up reverse proxy
- [ ] Regular security updates
- [ ] Monitor logs and activities

## 🏗️ Architecture

### Technology Stack
- **Backend**: Node.js, Express.js
- **Database**: MySQL with connection pooling
- **WhatsApp**: whatsapp-web.js library
- **Authentication**: JWT tokens
- **Real-time**: Socket.io
- **Frontend**: Vanilla JavaScript, CSS3
- **File Upload**: Multer with security validation

### Project Structure
```
whatsapp-automation-pro/
├── public-pro/           # Frontend files
│   ├── index.html       # Main HTML file
│   ├── app.js          # Frontend JavaScript
│   ├── styles.css      # Main styles
│   └── advanced-styles.css # Additional styles
├── uploads/             # File uploads directory
├── .wwebjs_auth/       # WhatsApp session data
├── .wwebjs_cache/      # WhatsApp cache
├── server.js           # Main server file
├── database.js         # Database configuration
├── package.json        # Dependencies
├── .env.example        # Environment template
└── README.md          # This file
```

### Database Schema

#### Users Table
```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    whatsapp_number VARCHAR(50),
    subscription_type ENUM('trial', 'premium', 'expired') DEFAULT 'trial',
    subscription_expires TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Campaigns Table
```sql
CREATE TABLE campaigns (
    id VARCHAR(255) PRIMARY KEY,
    user_id INT NOT NULL,
    type ENUM('bulk', 'group_broadcast', 'contact_broadcast') NOT NULL,
    total_count INT NOT NULL,
    processed_count INT DEFAULT 0,
    success_count INT DEFAULT 0,
    failed_count INT DEFAULT 0,
    status ENUM('running', 'completed', 'failed') DEFAULT 'running',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Commit your changes**
   ```bash
   git commit -m 'Add amazing feature'
   ```
4. **Push to the branch**
   ```bash
   git push origin feature/amazing-feature
   ```
5. **Open a Pull Request**

### Development Guidelines

- Follow existing code style
- Add comments for complex logic
- Test your changes thoroughly
- Update documentation if needed
- Ensure security best practices

### Code Style
- Use 4 spaces for indentation
- Use camelCase for variables and functions
- Use PascalCase for classes
- Add JSDoc comments for functions
- Keep functions small and focused

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 WhatsApp Automation Pro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 📞 Support

### Get Help

- **WhatsApp Support**: +92 317 0973410
- **Email**: support@whatsapppro.com
- **Documentation**: [Wiki](https://github.com/yourusername/whatsapp-automation-pro/wiki)
- **Issues**: [GitHub Issues](https://github.com/yourusername/whatsapp-automation-pro/issues)

### Subscription & Pricing

- **Trial**: 1-day free trial for new WhatsApp numbers
- **Premium**: Contact support for pricing and features
- **Enterprise**: Custom solutions available

### Troubleshooting

#### Common Issues

**WhatsApp won't connect**
- Ensure WhatsApp Web is not open elsewhere
- Clear browser cache and try again
- Check internet connection
- Restart the application

**Messages not sending**
- Check WhatsApp connection status
- Verify phone number format
- Ensure sufficient delays between messages
- Check subscription status

**Database connection errors**
- Verify MySQL is running
- Check database credentials in .env
- Ensure database exists
- Check network connectivity

#### Performance Tips

- Use appropriate delays (minimum 2 seconds)
- Limit concurrent campaigns
- Regular database maintenance
- Monitor server resources
- Use SSD storage for better performance

## 🚀 Deployment

### Production Deployment

1. **Server Requirements**
   - Ubuntu 20.04+ or CentOS 8+
   - 2GB+ RAM
   - 20GB+ storage
   - Node.js 18+
   - MySQL 8.0+

2. **Deploy with PM2**
   ```bash
   npm install -g pm2
   pm2 start server.js --name "whatsapp-pro"
   pm2 startup
   pm2 save
   ```

3. **Nginx Configuration**
   ```nginx
   server {
       listen 80;
       server_name yourdomain.com;
       
       location / {
           proxy_pass http://localhost:3000;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection 'upgrade';
           proxy_set_header Host $host;
           proxy_cache_bypass $http_upgrade;
       }
   }
   ```

4. **SSL Certificate**
   ```bash
   sudo certbot --nginx -d yourdomain.com
   ```

### Docker Deployment

```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
EXPOSE 3000

CMD ["npm", "start"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    depends_on:
      - mysql
      
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: whatsapp_bot_pro
    volumes:
      - mysql_data:/var/lib/mysql

volumes:
  mysql_data:
```

## 📊 Monitoring & Maintenance

### Health Checks
- Monitor application uptime
- Check database connections
- Monitor WhatsApp session status
- Track memory and CPU usage

### Backup Strategy
- Daily database backups
- Weekly full system backups
- Session data backup
- Configuration backup

### Log Management
- Application logs rotation
- Error tracking and alerting
- Performance monitoring
- Security audit logs

---

## 🎯 Roadmap

### Upcoming Features
- [ ] Multi-language support
- [ ] Advanced analytics dashboard
- [ ] API rate limiting per user
- [ ] Webhook integrations
- [ ] Advanced message templates
- [ ] CRM integration
- [ ] Mobile app (React Native)
- [ ] Advanced reporting
- [ ] Team collaboration features
- [ ] Advanced automation workflows

### Version History

#### v2.0.0 (Current)
- Complete UI/UX redesign
- Enhanced security features
- Task manager implementation
- Advanced campaign controls
- Improved error handling

#### v1.0.0
- Initial release
- Basic messaging features
- Group management
- Simple analytics

---

**Made with ❤️ for WhatsApp Marketing Professionals**

*This project is not affiliated with WhatsApp Inc. WhatsApp is a trademark of WhatsApp Inc.*