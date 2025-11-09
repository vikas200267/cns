# Firebase Setup Guide for CNS Lab

## Step 1: Create Firebase Project

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click "Add project" or select existing project
3. Enter project name (e.g., "cns-lab-control")
4. Disable Google Analytics (optional)
5. Click "Create project"

## Step 2: Enable Firestore Database

1. In Firebase Console, click **"Firestore Database"** in left menu
2. Click **"Create database"**
3. Select **"Start in production mode"** (we'll add rules later)
4. Choose a location (e.g., us-central)
5. Click "Enable"

### Firestore Security Rules
After creating database, go to **"Rules"** tab and set:

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Users collection - only admins can read all, users can read their own
    match /users/{userId} {
      allow read: if request.auth != null && 
                     (request.auth.uid == userId || 
                      get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin');
      allow write: if false; // Only backend can write
    }
    
    // Audit logs - only admins can read
    match /auditLogs/{logId} {
      allow read: if request.auth != null && 
                     get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
      allow write: if false; // Only backend can write
    }
  }
}
```

## Step 3: Enable Authentication

1. Click **"Authentication"** in left menu
2. Click **"Get started"**
3. Go to **"Sign-in method"** tab
4. Enable **"Email/Password"**
5. Click "Save"

## Step 4: Get Firebase Admin SDK Credentials (for Backend)

1. Click the **⚙️ gear icon** (Settings) → **"Project settings"**
2. Go to **"Service accounts"** tab
3. Click **"Generate new private key"**
4. Click **"Generate key"** (downloads a JSON file)
5. **SAVE THIS FILE** - it contains your admin credentials

**File location needed:** `/workspaces/cns/backend/firebase-admin-key.json`

The JSON file will look like:
```json
{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key_id": "...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-xxxxx@your-project-id.iam.gserviceaccount.com",
  "client_id": "...",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "..."
}
```

## Step 5: Get Firebase Web Config (for Frontend)

1. Still in **"Project settings"**
2. Scroll down to **"Your apps"** section
3. Click the **</>** (Web) icon to add a web app
4. Enter app nickname (e.g., "CNS Lab Frontend")
5. Click **"Register app"**
6. Copy the **firebaseConfig** object

**You'll need these values:**
```javascript
const firebaseConfig = {
  apiKey: "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  authDomain: "your-project-id.firebaseapp.com",
  projectId: "your-project-id",
  storageBucket: "your-project-id.appspot.com",
  messagingSenderId: "123456789012",
  appId: "1:123456789012:web:abcdef123456"
};
```

## Step 6: Where to Find Each Credential

| Credential | Location in Firebase Console |
|------------|------------------------------|
| **Admin SDK JSON** | Settings → Service accounts → Generate new private key |
| **API Key** | Settings → General → Web API Key |
| **Auth Domain** | Settings → General → Your apps section |
| **Project ID** | Settings → General (top of page) |
| **Storage Bucket** | Settings → General → Your apps section |
| **Messaging Sender ID** | Settings → Cloud Messaging → Sender ID |
| **App ID** | Settings → General → Your apps section |

## Step 7: Set Environment Variables

After you provide the credentials, I'll need:

### Backend (.env file)
```env
# Firebase Admin SDK
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
FIREBASE_CLIENT_EMAIL=firebase-adminsdk-xxxxx@your-project-id.iam.gserviceaccount.com

# Or provide the JSON file path
FIREBASE_ADMIN_KEY_PATH=./firebase-admin-key.json

# Registration Key (already exists)
ROOT_REGISTRATION_KEY=root_secure_registration_key_2025
```

### Frontend (.env file)
```env
REACT_APP_FIREBASE_API_KEY=AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
REACT_APP_FIREBASE_AUTH_DOMAIN=your-project-id.firebaseapp.com
REACT_APP_FIREBASE_PROJECT_ID=your-project-id
REACT_APP_FIREBASE_STORAGE_BUCKET=your-project-id.appspot.com
REACT_APP_FIREBASE_MESSAGING_SENDER_ID=123456789012
REACT_APP_FIREBASE_APP_ID=1:123456789012:web:abcdef123456
```

## What to Provide Me

Please provide either:

**Option 1: Upload the JSON file**
- Upload the downloaded `firebase-admin-key.json` to `/workspaces/cns/backend/`

**Option 2: Share the credentials**
Provide these values from your Firebase Console:
1. Project ID
2. Web API Key
3. Auth Domain
4. Storage Bucket
5. Messaging Sender ID
6. App ID
7. Admin SDK JSON content (or just project_id, private_key, client_email)

## Security Notes

⚠️ **IMPORTANT:**
- Never commit `firebase-admin-key.json` to Git
- Add to `.gitignore`: `firebase-admin-key.json`
- Keep your private keys secure
- Use environment variables in production
- Enable Firestore security rules

## After Providing Credentials

Once you provide the credentials, I will:
1. ✅ Create Firebase service initialization
2. ✅ Update authentication routes to use Firestore
3. ✅ Store user data in Firestore on registration
4. ✅ Validate login against Firestore database
5. ✅ Add real-time user synchronization
6. ✅ Implement audit logging in Firestore

---

**Ready to proceed?** 
Just provide the Firebase credentials and I'll integrate everything!
