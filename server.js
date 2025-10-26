const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const twilio = require('twilio');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Rate limiting for SOS alerts
const sosRateLimit = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 3, // max 3 SOS alerts per minute
  message: { error: 'Too many SOS alerts. Please wait before sending another.' }
});

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/sos-system', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  emergencyContacts: [{
    name: String,
    phone: String,
    email: String,
    relationship: String
  }],
  medicalInfo: {
    bloodType: String,
    allergies: [String],
    medications: [String],
    conditions: [String]
  },
  location: {
    latitude: Number,
    longitude: Number,
    address: String,
    lastUpdated: { type: Date, default: Date.now }
  },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

// SOS Alert Schema
const sosAlertSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { 
    type: String, 
    enum: ['medical', 'fire', 'police', 'natural_disaster', 'accident', 'other'],
    required: true 
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'high'
  },
  location: {
    latitude: { type: Number, required: true },
    longitude: { type: Number, required: true },
    address: String
  },
  message: String,
  status: {
    type: String,
    enum: ['active', 'responded', 'resolved', 'false_alarm'],
    default: 'active'
  },
  responders: [{
    type: { type: String, enum: ['ambulance', 'fire', 'police', 'contact'] },
    name: String,
    phone: String,
    notifiedAt: Date,
    respondedAt: Date
  }],
  createdAt: { type: Date, default: Date.now },
  resolvedAt: Date
});

// Emergency Service Schema
const emergencyServiceSchema = new mongoose.Schema({
  name: { type: String, required: true },
  type: { 
    type: String, 
    enum: ['ambulance', 'fire', 'police'], 
    required: true 
  },
  phone: { type: String, required: true },
  email: String,
  location: {
    latitude: { type: Number, required: true },
    longitude: { type: Number, required: true },
    address: { type: String, required: true }
  },
  serviceRadius: { type: Number, default: 10 }, // km
  isAvailable: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const SOSAlert = mongoose.model('SOSAlert', sosAlertSchema);
const EmergencyService = mongoose.model('EmergencyService', emergencyServiceSchema);

// Initialize communication services
const twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

const emailTransporter = nodemailer.createTransporter({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Helper function to calculate distance between two coordinates
const calculateDistance = (lat1, lon1, lat2, lon2) => {
  const R = 6371; // Earth's radius in km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
};

// Helper function to send SMS
const sendSMS = async (to, message) => {
  try {
    if (process.env.TWILIO_SID && process.env.TWILIO_AUTH_TOKEN) {
      await twilioClient.messages.create({
        body: message,
        from: process.env.TWILIO_PHONE,
        to: to
      });
    }
    console.log(`SMS sent to ${to}: ${message}`);
  } catch (error) {
    console.error('SMS Error:', error);
  }
};

// Helper function to send email
const sendEmail = async (to, subject, text) => {
  try {
    await emailTransporter.sendMail({
      from: process.env.EMAIL_USER,
      to: to,
      subject: subject,
      text: text
    });
    console.log(`Email sent to ${to}: ${subject}`);
  } catch (error) {
    console.error('Email Error:', error);
  }
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'SOS Backend is running!', timestamp: new Date() });
});

// User Registration
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    
    // Validation
    if (!name || !email || !phone || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      name,
      email,
      phone,
      password: hashedPassword
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '30d' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '30d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        emergencyContacts: user.emergencyContacts,
        medicalInfo: user.medicalInfo
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    res.json({ user });
  } catch (error) {
    res.status(500).json({ error: 'Error fetching profile' });
  }
});

// Update user profile
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const updates = req.body;
    const user = await User.findByIdAndUpdate(
      req.user.userId,
      updates,
      { new: true, runValidators: true }
    ).select('-password');
    
    res.json({ message: 'Profile updated', user });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Error updating profile' });
  }
});

// Update user location
app.put('/api/user/location', authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude, address } = req.body;
    
    if (!latitude || !longitude) {
      return res.status(400).json({ error: 'Latitude and longitude required' });
    }

    await User.findByIdAndUpdate(req.user.userId, {
      location: {
        latitude,
        longitude,
        address,
        lastUpdated: new Date()
      }
    });

    res.json({ message: 'Location updated successfully' });
  } catch (error) {
    console.error('Location update error:', error);
    res.status(500).json({ error: 'Error updating location' });
  }
});

// Add emergency contact
app.post('/api/user/emergency-contacts', authenticateToken, async (req, res) => {
  try {
    const { name, phone, email, relationship } = req.body;
    
    if (!name || !phone) {
      return res.status(400).json({ error: 'Name and phone are required' });
    }

    const user = await User.findById(req.user.userId);
    user.emergencyContacts.push({ name, phone, email, relationship });
    await user.save();

    res.json({ message: 'Emergency contact added', contacts: user.emergencyContacts });
  } catch (error) {
    console.error('Add contact error:', error);
    res.status(500).json({ error: 'Error adding emergency contact' });
  }
});

// Remove emergency contact
app.delete('/api/user/emergency-contacts/:id', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    user.emergencyContacts.id(req.params.id).remove();
    await user.save();

    res.json({ message: 'Emergency contact removed', contacts: user.emergencyContacts });
  } catch (error) {
    res.status(500).json({ error: 'Error removing emergency contact' });
  }
});

// Send SOS Alert - THE MAIN FEATURE
app.post('/api/sos/alert', [authenticateToken, sosRateLimit], async (req, res) => {
  try {
    const { type, latitude, longitude, address, message, priority } = req.body;
    
    if (!type || !latitude || !longitude) {
      return res.status(400).json({ error: 'Alert type and location are required' });
    }

    // Get user details
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Create SOS alert
    const sosAlert = new SOSAlert({
      userId: req.user.userId,
      type,
      priority: priority || 'high',
      location: { latitude, longitude, address },
      message
    });

    await sosAlert.save();

    // Find nearby emergency services
    const emergencyServices = await EmergencyService.find({ 
      type: getServiceType(type),
      isAvailable: true 
    });

    const nearbyServices = emergencyServices.filter(service => {
      const distance = calculateDistance(
        latitude, longitude,
        service.location.latitude, service.location.longitude
      );
      return distance <= service.serviceRadius;
    });

    // Prepare alert message
    const alertMessage = `🚨 EMERGENCY ALERT 🚨\n${user.name} needs ${type} assistance!\nLocation: ${address || `${latitude}, ${longitude}`}\nMessage: ${message || 'No additional message'}\nTime: ${new Date().toLocaleString()}\nGoogle Maps: https://maps.google.com/?q=${latitude},${longitude}`;

    // Notify emergency contacts
    const notificationPromises = [];
    
    for (const contact of user.emergencyContacts) {
      if (contact.phone) {
        notificationPromises.push(sendSMS(contact.phone, alertMessage));
      }
      if (contact.email) {
        notificationPromises.push(sendEmail(
          contact.email,
          '🚨 EMERGENCY ALERT - Immediate Response Needed',
          alertMessage
        ));
      }
    }

    // Notify nearby emergency services
    for (const service of nearbyServices) {
      const serviceMessage = `EMERGENCY DISPATCH\nType: ${type.toUpperCase()}\nPriority: ${priority?.toUpperCase() || 'HIGH'}\nLocation: ${address || `${latitude}, ${longitude}`}\nRequester: ${user.name} (${user.phone})\nMedical Info: Blood Type: ${user.medicalInfo?.bloodType || 'Unknown'}\nAllergies: ${user.medicalInfo?.allergies?.join(', ') || 'None listed'}\nGoogle Maps: https://maps.google.com/?q=${latitude},${longitude}`;
      
      notificationPromises.push(sendSMS(service.phone, serviceMessage));
      
      if (service.email) {
        notificationPromises.push(sendEmail(
          service.email,
          `EMERGENCY DISPATCH - ${type.toUpperCase()}`,
          serviceMessage
        ));
      }

      // Record responder notification
      sosAlert.responders.push({
        type: service.type,
        name: service.name,
        phone: service.phone,
        notifiedAt: new Date()
      });
    }

    // Execute all notifications
    await Promise.allSettled(notificationPromises);
    await sosAlert.save();

    res.json({
      success: true,
      message: 'SOS alert sent successfully',
      data: {
        alertId: sosAlert._id,
        notifiedServices: nearbyServices.length,
        notifiedContacts: user.emergencyContacts.length,
        location: { latitude, longitude, address },
        timestamp: sosAlert.createdAt
      }
    });
  } catch (error) {
    console.error('SOS Alert Error:', error);
    res.status(500).json({ error: 'Error sending SOS alert' });
  }
});

// Helper function to map alert types to service types
const getServiceType = (alertType) => {
  const mapping = {
    'medical': 'ambulance',
    'fire': 'fire',
    'accident': 'ambulance',
    'natural_disaster': 'fire',
    'police': 'police',
    'other': 'police'
  };
  return mapping[alertType] || 'police';
};

// Get user's SOS alerts
app.get('/api/sos/alerts', authenticateToken, async (req, res) => {
  try {
    const alerts = await SOSAlert.find({ userId: req.user.userId })
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json({ alerts });
  } catch (error) {
    console.error('Get alerts error:', error);
    res.status(500).json({ error: 'Error fetching alerts' });
  }
});

// Update alert status
app.put('/api/sos/alerts/:id/status', authenticateToken, async (req, res) => {
  try {
    const { status } = req.body;
    const alert = await SOSAlert.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.userId },
      { 
        status, 
        resolvedAt: status === 'resolved' ? new Date() : undefined 
      },
      { new: true }
    );
    
    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    res.json({ message: 'Alert status updated', alert });
  } catch (error) {
    res.status(500).json({ error: 'Error updating alert status' });
  }
});

// Emergency Services Management (for admin/testing)
app.post('/api/admin/emergency-services', async (req, res) => {
  try {
    const service = new EmergencyService(req.body);
    await service.save();
    res.status(201).json({ message: 'Emergency service added', service });
  } catch (error) {
    console.error('Add service error:', error);
    res.status(500).json({ error: 'Error adding emergency service' });
  }
});

app.get('/api/admin/emergency-services', async (req, res) => {
  try {
    const services = await EmergencyService.find();
    res.json({ services });
  } catch (error) {
    res.status(500).json({ error: 'Error fetching emergency services' });
  }
});

// Test route for notifications
app.post('/api/test/notification', authenticateToken, async (req, res) => {
  try {
    const { phone, email, message } = req.body;
    
    const promises = [];
    if (phone) promises.push(sendSMS(phone, message || 'Test SMS from SOS System'));
    if (email) promises.push(sendEmail(email, 'Test Email', message || 'Test email from SOS System'));
    
    await Promise.allSettled(promises);
    res.json({ message: 'Test notifications sent' });
  } catch (error) {
    res.status(500).json({ error: 'Error sending test notifications' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚨 SOS Backend Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  mongoose.connection.close();
  process.exit(0);
});