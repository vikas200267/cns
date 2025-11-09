const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const admin = require('firebase-admin');
const path = require('path');

// Initialize Firebase Admin SDK
const serviceAccount = require('../firebase-admin-key.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    projectId: serviceAccount.project_id
  });
}

const db = admin.firestore();
const usersCollection = db.collection('users');

const JWT_SECRET = process.env.JWT_SECRET || 'cns-lab-secret-key-change-in-production';
const JWT_EXPIRES_IN = '7d'; // Token expires in 7 days

// Firestore helper functions
async function getUserByEmail(email) {
  const snapshot = await usersCollection.where('email', '==', email).limit(1).get();
  if (snapshot.empty) {
    return null;
  }
  const doc = snapshot.docs[0];
  return { id: doc.id, ...doc.data() };
}

async function getUserById(userId) {
  const doc = await usersCollection.doc(userId).get();
  if (!doc.exists) {
    return null;
  }
  return { id: doc.id, ...doc.data() };
}

async function createUser(userData) {
  const docRef = await usersCollection.add(userData);
  return { id: docRef.id, ...userData };
}

async function updateUser(userId, updates) {
  await usersCollection.doc(userId).update(updates);
  return getUserById(userId);
}

// Generate API key for user
function generateApiKey(userId, role) {
  const prefix = role === 'admin' ? 'adm' : 'op';
  const random = Math.random().toString(36).substring(2, 15) + 
                 Math.random().toString(36).substring(2, 15);
  return `${prefix}_${random}`;
}

/**
 * POST /api/auth/register
 * Register a new user (requires root registration key)
 */
router.post('/register', [
  body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
  body('email').isEmail().normalizeEmail().withMessage('Invalid email address'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('role').optional().isIn(['operator', 'admin']).withMessage('Invalid role'),
  body('registrationKey').notEmpty().withMessage('Registration key is required'),
], async (req, res) => {
  try {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { name, email, password, role = 'operator', registrationKey } = req.body;

    // Verify registration key
    const ROOT_REGISTRATION_KEY = process.env.ROOT_REGISTRATION_KEY || 'root_secure_registration_key_2025';
    if (registrationKey !== ROOT_REGISTRATION_KEY) {
      return res.status(403).json({ 
        error: 'Invalid registration key. Only authorized personnel can register.' 
      });
    }

    // Load existing users
    const users = await loadUsers();

    // Check if email already exists
    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
      return res.status(409).json({ 
        error: 'Email already registered' 
      });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);

    // Create new user
    const newUser = {
      id: `user_${Date.now()}_${Math.random().toString(36).substring(7)}`,
      name,
      email,
      passwordHash,
      role,
      apiKey: generateApiKey(users.length, role),
      createdAt: new Date().toISOString(),
      lastLogin: null,
    };

    // Add to users array
    users.push(newUser);

    // Save to file
    await saveUsers(users);

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: newUser.id, 
        email: newUser.email, 
        role: newUser.role 
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // Return user data (without password hash)
    const { passwordHash: _, ...userWithoutPassword } = newUser;

    res.status(201).json({
      message: 'Registration successful',
      token,
      user: userWithoutPassword,
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      error: 'Registration failed', 
      details: error.message 
    });
  }
});

/**
 * POST /api/auth/login
 * Authenticate user and return JWT token
 */
router.post('/login', [
  body('email').isEmail().normalizeEmail().withMessage('Invalid email address'),
  body('password').notEmpty().withMessage('Password is required'),
], async (req, res) => {
  try {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { email, password } = req.body;

    // Load users
    const users = await loadUsers();

    // Find user by email
    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ 
        error: 'Invalid email or password' 
      });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatch) {
      return res.status(401).json({ 
        error: 'Invalid email or password' 
      });
    }

    // Update last login
    user.lastLogin = new Date().toISOString();
    await saveUsers(users);

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email, 
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // Return user data (without password hash)
    const { passwordHash: _, ...userWithoutPassword } = user;

    res.json({
      message: 'Login successful',
      token,
      user: userWithoutPassword,
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      error: 'Login failed', 
      details: error.message 
    });
  }
});

/**
 * GET /api/auth/me
 * Get current user info from JWT token
 */
router.get('/me', async (req, res) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        error: 'No token provided' 
      });
    }

    const token = authHeader.substring(7);

    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);

    // Load users
    const users = await loadUsers();

    // Find user
    const user = users.find(u => u.id === decoded.userId);
    if (!user) {
      return res.status(404).json({ 
        error: 'User not found' 
      });
    }

    // Return user data (without password hash)
    const { passwordHash: _, ...userWithoutPassword } = user;

    res.json({
      user: userWithoutPassword,
    });

  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        error: 'Invalid token' 
      });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Token expired' 
      });
    }
    console.error('Get user error:', error);
    res.status(500).json({ 
      error: 'Failed to get user info', 
      details: error.message 
    });
  }
});

/**
 * POST /api/auth/logout
 * Logout user (client should delete token)
 */
router.post('/logout', (req, res) => {
  // In a stateless JWT setup, logout is handled client-side by deleting the token
  // This endpoint is here for completeness and can be extended for token blacklisting
  res.json({
    message: 'Logout successful. Please delete your token client-side.',
  });
});

/**
 * PUT /api/auth/change-password
 * Change user password
 */
router.put('/change-password', [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters'),
], async (req, res) => {
  try {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    // Extract token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        error: 'No token provided' 
      });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, JWT_SECRET);

    const { currentPassword, newPassword } = req.body;

    // Load users
    const users = await loadUsers();

    // Find user
    const userIndex = users.findIndex(u => u.id === decoded.userId);
    if (userIndex === -1) {
      return res.status(404).json({ 
        error: 'User not found' 
      });
    }

    const user = users[userIndex];

    // Verify current password
    const passwordMatch = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!passwordMatch) {
      return res.status(401).json({ 
        error: 'Current password is incorrect' 
      });
    }

    // Hash new password
    const newPasswordHash = await bcrypt.hash(newPassword, 12);

    // Update password
    users[userIndex].passwordHash = newPasswordHash;
    await saveUsers(users);

    res.json({
      message: 'Password changed successfully',
    });

  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Invalid or expired token' 
      });
    }
    console.error('Change password error:', error);
    res.status(500).json({ 
      error: 'Failed to change password', 
      details: error.message 
    });
  }
});

module.exports = router;
