const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const admin = require('firebase-admin');

// Flexible Firebase Admin SDK initialization
// Priority:
// 1. FIREBASE_ADMIN_KEY_PATH -> path to JSON file
// 2. Environment variables (FIREBASE_PRIVATE_KEY, FIREBASE_CLIENT_EMAIL, FIREBASE_PROJECT_ID)
// 3. ./firebase-admin-key.json (legacy/local file)

let serviceAccount;
try {
  if (process.env.FIREBASE_ADMIN_KEY_PATH) {
    // Allow absolute or relative path
    serviceAccount = require(process.env.FIREBASE_ADMIN_KEY_PATH);
    console.log('Using Firebase admin key from FIREBASE_ADMIN_KEY_PATH');
  } else if (process.env.FIREBASE_PRIVATE_KEY && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PROJECT_ID) {
    // Build service account object from environment vars (private key may contain '\n' sequences)
    serviceAccount = {
      type: 'service_account',
      project_id: process.env.FIREBASE_PROJECT_ID,
      private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID || '',
      private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
      client_email: process.env.FIREBASE_CLIENT_EMAIL,
      client_id: process.env.FIREBASE_CLIENT_ID || '',
      auth_uri: 'https://accounts.google.com/o/oauth2/auth',
      token_uri: 'https://oauth2.googleapis.com/token',
      auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
      client_x509_cert_url: process.env.FIREBASE_CLIENT_X509 || ''
    };
    console.log('Using Firebase admin credentials from environment variables');
  } else {
    // Fallback to local file (same behavior as before)
    serviceAccount = require('../firebase-admin-key.json');
    console.log('Using local backend/firebase-admin-key.json');
  }
} catch (err) {
  console.error('Failed to load Firebase Admin credentials:', err && err.message ? err.message : err);
  throw err;
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    projectId: serviceAccount.project_id
  });
}

const db = admin.firestore();
const usersCollection = db.collection('users');

const JWT_SECRET = process.env.JWT_SECRET || 'cns-lab-secret-key-change-in-production';
const JWT_EXPIRES_IN = '7d';
const ROOT_REGISTRATION_KEY = process.env.ROOT_REGISTRATION_KEY || 'root_secure_registration_key_2025';

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

    // Verify root registration key
    if (registrationKey !== ROOT_REGISTRATION_KEY) {
      return res.status(403).json({ 
        error: 'Invalid registration key. Only authorized personnel can register.' 
      });
    }

    // Check if email already exists in Firestore
    const existingUser = await getUserByEmail(email);
    if (existingUser) {
      return res.status(409).json({ 
        error: 'Email already registered' 
      });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);

    // Create new user data
    const userData = {
      name,
      email,
      passwordHash,
      role,
      apiKey: generateApiKey(Date.now(), role),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      lastLogin: null,
      isActive: true,
    };

    // Save to Firestore
    const newUser = await createUser(userData);

    console.log('✅ User registered in Firebase:', email);

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
    console.error('❌ Registration error:', error);
    res.status(500).json({ 
      error: 'Registration failed', 
      details: error.message 
    });
  }
});

/**
 * POST /api/auth/login
 * Authenticate user from Firebase and return JWT token
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

    // Find user in Firestore
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(401).json({ 
        error: 'Invalid email or password' 
      });
    }

    // Check if user is active
    if (user.isActive === false) {
      return res.status(403).json({ 
        error: 'Account has been deactivated. Please contact administrator.' 
      });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatch) {
      return res.status(401).json({ 
        error: 'Invalid email or password' 
      });
    }

    // Update last login timestamp
    await updateUser(user.id, {
      lastLogin: admin.firestore.FieldValue.serverTimestamp()
    });

    console.log('✅ User logged in from Firebase:', email);

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
    console.error('❌ Login error:', error);
    res.status(500).json({ 
      error: 'Login failed', 
      details: error.message 
    });
  }
});

/**
 * GET /api/auth/me
 * Get current user info from JWT token and Firebase
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

    // Find user in Firestore
    const user = await getUserById(decoded.userId);
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
  res.json({
    message: 'Logout successful. Please delete your token client-side.',
  });
});

/**
 * PUT /api/auth/change-password
 * Change user password in Firebase
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

    // Find user in Firestore
    const user = await getUserById(decoded.userId);
    if (!user) {
      return res.status(404).json({ 
        error: 'User not found' 
      });
    }

    // Verify current password
    const passwordMatch = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!passwordMatch) {
      return res.status(401).json({ 
        error: 'Current password is incorrect' 
      });
    }

    // Hash new password
    const newPasswordHash = await bcrypt.hash(newPassword, 12);

    // Update password in Firestore
    await updateUser(user.id, {
      passwordHash: newPasswordHash
    });

    console.log('✅ Password changed for user:', user.email);

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
