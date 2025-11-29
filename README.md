# IntraShare - Local Network Security Setup

## 🎯 Project Goal

**IntraShare** is designed for **secure local network file sharing**:
- ✅ Accessible only within the same network (LAN)
- ✅ Not accessible from the internet
- ✅ Admin-controlled user access
- ✅ Secure file sharing between team members
- ✅ Perfect for offices, labs, or home networks

---

## 🔐 Security Features

### 1. **Network Isolation**
- Only accessible from local network (192.168.x.x or 10.x.x.x)
- Not exposed to the internet
- No port forwarding required

### 2. **User Authentication**
- All users must login
- Admin approval required for new accounts
- Session-based authentication
- Secure password storage (Django hashed)

### 3. **Access Control**
- Users can only update/delete their own files
- Admins have full control
- File-level permissions

### 4. **Admin Oversight**
- Admin can activate/deactivate users
- Admin can manage all files
- Centralized user management

---

## 🚀 Setup for Local Network Access

### Step 1: Configure Django Settings

Edit `intrashare/settings.py`:

```python
# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False  # Set to False for production

# Allow only local network access
ALLOWED_HOSTS = [
    'localhost',
    '127.0.0.1',
    '192.168.1.100',  # Your server's local IP
    '192.168.1.*',     # Allow all devices in your network
    '10.0.0.*',        # Alternative private network range
]

# Session Security
SESSION_COOKIE_SECURE = False  # Set to True if using HTTPS
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_AGE = 86400  # 24 hours

# CSRF Protection
CSRF_COOKIE_SECURE = False  # Set to True if using HTTPS
CSRF_COOKIE_HTTPONLY = True

# Security Headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
```

### Step 2: Find Your Server's Local IP

**On Linux/Mac:**
```bash
# Find your local IP
ip addr show | grep "inet 192.168"
# or
ifconfig | grep "inet 192.168"

# Example output: 192.168.1.100
```

**On Windows:**
```cmd
ipconfig

# Look for: IPv4 Address. . . : 192.168.1.100
```

### Step 3: Run Server on Local Network

```bash
# Run on all network interfaces (accessible from LAN)
python manage.py runserver 0.0.0.0:8000

# Or run on specific IP
python manage.py runserver 192.168.1.100:8000
```

### Step 4: Access from Other Devices

**From any device on the same network:**
```
http://192.168.1.100:8000
```

Replace `192.168.1.100` with your server's actual IP.

---

## 🔒 Security Best Practices

### 1. **Firewall Configuration**

**On Ubuntu/Debian:**
```bash
# Install firewall
sudo apt install ufw

# Allow only local network
sudo ufw allow from 192.168.1.0/24 to any port 8000

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status
```

**On Windows:**
```
1. Open Windows Defender Firewall
2. Advanced Settings
3. Inbound Rules → New Rule
4. Port → TCP 8000
5. Allow connection only from local subnet
```

### 2. **Strong Password Policy**

In your Django admin, enforce:
- Minimum 8 characters
- Mix of letters, numbers, symbols
- Change default admin password immediately

### 3. **Regular Backups**

```bash
# Backup database
cp db.sqlite3 backups/db_$(date +%Y%m%d).sqlite3

# Backup media files
cp -r media backups/media_$(date +%Y%m%d)
```

### 4. **Admin User Management**

- Review user accounts regularly
- Deactivate unused accounts
- Monitor file uploads
- Check for suspicious activity

---

## 📋 Network Security Checklist

- [ ] DEBUG = False in production
- [ ] ALLOWED_HOSTS configured for local network only
- [ ] Firewall rules set to allow only local network
- [ ] No port forwarding on router
- [ ] Strong admin password set
- [ ] All users require admin approval
- [ ] Regular backups scheduled
- [ ] HTTPS configured (optional but recommended)
- [ ] Session timeouts configured
- [ ] File size limits set

---

## 🌐 Network Topology

```
┌─────────────────────────────────────┐
│           Local Network             │
│         (192.168.1.0/24)            │
├─────────────────────────────────────┤
│                                     │
│  ┌──────────┐                       │
│  │  Router  │  ← No port forwarding │
│  └────┬─────┘                       │
│       │                             │
│  ┌────┴─────────────────┐           │
│  │                      │           │
│  │  ┌────────────┐  ┌──────────┐   │
│  │  │   Server   │  │  Laptop  │   │
│  │  │ (Django)   │  │  User 1  │   │
│  │  │.100:8000   │  │          │   │
│  │  └────────────┘  └──────────┘   │
│  │                                  │
│  │  ┌──────────┐   ┌──────────┐    │
│  │  │ Desktop  │   │  Phone   │    │
│  │  │ User 2   │   │  User 3  │    │
│  │  └──────────┘   └──────────┘    │
│  │                                  │
│  └──────────────────────────────────┘
│                                     │
│  ✅ All can access IntraShare       │
│  ❌ Internet cannot access          │
└─────────────────────────────────────┘
```

---

## 🔧 Production Deployment

### Option 1: Run as System Service (Linux)

Create `/etc/systemd/system/intrashare.service`:

```ini
[Unit]
Description=IntraShare Django Application
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/path/to/intrashare
Environment="PATH=/path/to/venv/bin"
ExecStart=/path/to/venv/bin/python manage.py runserver 0.0.0.0:8000
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable intrashare
sudo systemctl start intrashare
sudo systemctl status intrashare
```

### Option 2: Use Gunicorn (Production Server)

```bash
# Install Gunicorn
pip install gunicorn

# Run with Gunicorn
gunicorn --bind 0.0.0.0:8000 intrashare.wsgi:application
```

### Option 3: Docker Container

Create `Dockerfile`:
```dockerfile
FROM python:3.9
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
```

Build and run:
```bash
docker build -t intrashare .
docker run -p 8000:8000 intrashare
```

---

## 📱 Access from Different Devices

### Desktop Computer:
```
http://192.168.1.100:8000
```

### Mobile Phone (on same WiFi):
```
http://192.168.1.100:8000
```

### Laptop:
```
http://192.168.1.100:8000
```

### Tablet:
```
http://192.168.1.100:8000
```

**Note:** All devices must be connected to the same WiFi/network.

---

## 🚨 Troubleshooting

### Issue 1: Cannot access from other devices

**Solution:**
```bash
# Make sure server is running on 0.0.0.0
python manage.py runserver 0.0.0.0:8000

# Check firewall
sudo ufw status
sudo ufw allow 8000

# Check ALLOWED_HOSTS in settings.py
```

### Issue 2: CSRF verification failed

**Solution:**
Add your server IP to CSRF_TRUSTED_ORIGINS in settings.py:
```python
CSRF_TRUSTED_ORIGINS = [
    'http://192.168.1.100:8000',
    'http://localhost:8000',
]
```

---

## 📊 Security Comparison

| Feature | IntraShare | Public Cloud |
|---------|------------|--------------|
| **Network Access** | Local only | Internet |
| **Data Location** | Your server | Third-party |
| **Access Control** | Full control | Limited |
| **Privacy** | 100% private | Shared infrastructure |
| **Cost** | Free (hardware only) | Monthly fees |
| **Speed** | LAN speed (fast) | Internet speed |
| **Admin Control** | Complete | Limited |

---

## ✅ Why Local Network is Secure

### 1. **Physical Isolation**
- Data never leaves your network
- No exposure to internet threats
- Complete control over access

### 2. **Network Layer Protection**
- Router acts as first firewall
- No port forwarding = no entry point
- Local IP addresses not routable from internet

### 3. **Application Layer Security**
- Django authentication
- Admin approval required
- Session management
- CSRF protection

### 4. **Administrative Control**
- You control all user accounts
- You manage all files
- You set all policies
- You own all data

---

## 📖 User Instructions

### For Team Members:

**How to Access IntraShare:**

1. **Connect to Office/Home WiFi**
   - Make sure you're on the same network as the server

2. **Open Web Browser**
   - Chrome, Firefox, Safari, or Edge

3. **Visit IntraShare**
   ```
   http://192.168.1.100:8000
   ```
   (Your admin will provide the exact URL)

4. **First Time Setup**
   - Click "Register"
   - Create account
   - Wait for admin approval
   - Login after approval

5. **Using IntraShare**
   - Upload files
   - Set expiry time
   - Download team files
   - Update your files
   - Manage expiry times

---

## 🎓 For Administrators

### Daily Tasks:
- [ ] Check for new user registrations
- [ ] Approve/reject new users
- [ ] Monitor storage usage
- [ ] Review uploaded files

### Weekly Tasks:
- [ ] Backup database and files
- [ ] Review user activity
- [ ] Clean up expired files
- [ ] Check server logs

### Monthly Tasks:
- [ ] Update Django and dependencies
- [ ] Review security settings
- [ ] Check firewall rules
- [ ] Test disaster recovery

---

## 📞 Support & Maintenance

### Server Status Check:
```bash
# Check if Django is running
ps aux | grep python

# Check network connections
netstat -tlnp | grep 8000

# Check disk space
df -h

# Check logs
tail -f /var/log/syslog
```

### Quick Restart:
```bash
# Stop server (Ctrl+C or)
pkill -f "manage.py runserver"

# Start server
python manage.py runserver 0.0.0.0:8000
```

---

## 🎉 Benefits of Local Network Deployment

1. ✅ **Complete Privacy** - Data never leaves your premises
2. ✅ **Fast Speed** - LAN speeds (100Mbps - 1Gbps)
3. ✅ **No Internet Required** - Works during internet outages
4. ✅ **No Recurring Costs** - One-time setup only
5. ✅ **Full Control** - You own everything
6. ✅ **Compliance** - Meets data residency requirements
7. ✅ **Secure** - Protected by network isolation
8. ✅ **Scalable** - Add more users as needed

---

## 📝 Summary

IntraShare is designed for **secure, local network file sharing**:

- 🔒 **Secure**: Multiple layers of security
- 🏠 **Local**: Never exposed to internet
- 👥 **Controlled**: Admin approval required
- ⚡ **Fast**: LAN-speed transfers
- 💰 **Free**: No cloud subscription fees
- 🔐 **Private**: Your data stays with you

**Perfect for:** Offices, labs, schools, homes, small businesses, research teams

---

**Your data, your network, your control! 🚀**