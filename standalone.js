/**
 * Standalone server combining frontend and backend
 * Serves both static files and API from a single server with no CORS issues
 */
const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 5000;

// Built-in API keys
const API_KEYS = {
  'op_1234567890abcdef': { role: 'operator', id: 'operator-key-1' },
  'adm_fedcba0987654321': { role: 'admin', id: 'admin-key-1' }
};

// Allowed targets
const ALLOWED_TARGETS = ['192.168.56.101', '192.168.56.102', '192.168.56.103'];

// Predefined tasks (simplified)
const TASKS = {
  'nmap-scan': {
    name: 'Nmap Scan',
    description: 'Port scan with service detection',
    enabled: true,
    requiredRole: 'operator',
    sensitive: false
  },
  'nikto-scan': {
    name: 'Nikto Scan',
    description: 'Web vulnerability scanner',
    enabled: true,
    requiredRole: 'operator',
    sensitive: false
  },
  'start-capture': {
    name: 'Start Capture',
    description: 'Start packet capture (60 seconds)',
    enabled: true,
    requiredRole: 'operator',
    sensitive: false
  },
  'ddos-attack': {
    name: 'DDoS Attack',
    description: 'Simulate DDoS attack (lab only)',
    enabled: true,
    requiredRole: 'admin',
    sensitive: true,
    warning: 'This will simulate a DDoS attack. Use only in isolated lab environment.'
  },
  'ddos-mitigate': {
    name: 'DDoS Mitigation',
    description: 'Apply DDoS mitigation',
    enabled: true,
    requiredRole: 'admin',
    sensitive: true,
    warning: 'This will add iptables rules for DDoS mitigation.'
  },
  'add-firewall': {
    name: 'Add Firewall Rules',
    description: 'Configure basic firewall rules',
    enabled: true,
    requiredRole: 'admin',
    sensitive: true,
    warning: 'This will modify system firewall rules.'
  }
};

// Middleware
app.use(express.json());

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'frontend', 'build')));

// Authentication middleware
function authenticate(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey || !API_KEYS[apiKey]) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  req.auth = API_KEYS[apiKey];
  next();
}

// Authorization middleware
function requireRole(role) {
  return (req, res, next) => {
    if (req.auth.role !== role && req.auth.role !== 'admin') {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// API Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Get tasks list
app.get('/api/tasks', authenticate, (req, res) => {
  const tasksList = Object.keys(TASKS).map(id => ({
    id,
    name: TASKS[id].name,
    description: TASKS[id].description,
    requiredRole: TASKS[id].requiredRole,
    sensitive: TASKS[id].sensitive || false
  }));
  
  res.json(tasksList);
});

// Execute task
app.post('/api/tasks', authenticate, async (req, res) => {
  const { taskId, target, confirmed } = req.body;

  // Validate task
  if (!TASKS[taskId] || !TASKS[taskId].enabled) {
    return res.status(400).json({ error: 'Invalid or disabled task' });
  }

  // Validate target
  if (!ALLOWED_TARGETS.includes(target)) {
    return res.status(403).json({ error: 'Target not in allowed list' });
  }

  const task = TASKS[taskId];

  // Check role requirements
  if (task.requiredRole === 'admin' && req.auth.role !== 'admin') {
    return res.status(403).json({ error: 'Admin role required for this task' });
  }

  // Require confirmation for sensitive tasks
  if (task.sensitive && !confirmed) {
    return res.status(400).json({
      error: 'Confirmation required for sensitive task',
      taskId,
      warning: task.warning
    });
  }

  // Simulate task execution
  const taskInstanceId = `task_${uuidv4().split('-')[0]}`;
  const startTime = Date.now();
  const duration = Math.random() * 2 + 0.5; // Random duration 0.5-2.5s
  
  // Simulate some processing time
  await new Promise(resolve => setTimeout(resolve, duration * 1000));

  // Generate simulated output based on task type
  let output = '';
  let artifactPath = null;

  switch (taskId) {
    case 'nmap-scan':
      output = `Starting Nmap 7.94 ( https://nmap.org ) at ${new Date().toLocaleString()}
Nmap scan report for ${target}
Host is up (0.00042s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
3306/tcp open  mysql
5432/tcp open  postgresql

Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds`;
      artifactPath = `/artifacts/${taskInstanceId}-nmap-scan.txt`;
      break;
      
    case 'nikto-scan':
      output = `- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          ${target}
+ Target Hostname:    ${target}
+ Target Port:        80
+ Start Time:         ${new Date().toLocaleString()}
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: Retrieved x-powered-by header: PHP/7.4.3
+ /login.php: Admin login page/section found.
+ /phpmyadmin/: phpMyAdmin directory found
+ /wp-login.php: WordPress login found
+ 7890 requests: 0 error(s) and 4 item(s) reported on remote host`;
      artifactPath = `/artifacts/${taskInstanceId}-nikto-scan.txt`;
      break;

    case 'start-capture':
      output = `Starting packet capture on eth0
Target: ${target}
Duration: 60 seconds
Capture ID: cap_${Math.floor(Math.random() * 1000)}
Status: Running`;
      break;

    case 'ddos-attack':
      output = `[WARNING] Running DDoS simulation against ${target}
Using protocol: TCP SYN Flood
Target Port: 80
Duration: 10 seconds
Packets Sent: ~100 connection attempts
Status: Completed
Traffic generated: Multiple rapid SYN packets
Note: This is a SIMULATED attack for lab/training purposes only`;
      artifactPath = `/artifacts/${taskInstanceId}-ddos-report.txt`;
      break;

    case 'ddos-mitigate':
      output = `Applying DDoS mitigation for ${target}
Timestamp: ${new Date().toLocaleString()}

=== DDoS Mitigation Rules (Simulated) ===

1. Rate limiting for HTTP traffic:
   iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
   iptables -A INPUT -p tcp --dport 80 -j DROP

2. Connection tracking rules:
   iptables -A INPUT -p tcp -m state --state NEW -m limit --limit 50/second --limit-burst 50 -j ACCEPT

3. SYN flood protection:
   iptables -A INPUT -p tcp --syn -m limit --limit 1/second -j ACCEPT

4. Drop invalid packets:
   iptables -A INPUT -m state --state INVALID -j DROP

Status: Rules configured successfully (simulation mode)
Note: In production, these rules would be applied with root privileges`;
      artifactPath = `/artifacts/${taskInstanceId}-ddos-mitigation.txt`;
      break;

    case 'add-firewall':
      output = `Configuring firewall rules for ${target}
Timestamp: ${new Date().toLocaleString()}

=== Basic Firewall Configuration (Simulated) ===

1. Allow established/related connections
2. Allow SSH access (port 22)
3. Allow HTTP/HTTPS (ports 80, 443)
4. Rate limit ICMP (ping)
5. Drop invalid packets
6. Log and drop all other traffic

Status: Firewall rules configured successfully (simulation mode)
Note: In production, these rules would be applied with root privileges`;
      artifactPath = `/artifacts/${taskInstanceId}-firewall.txt`;
      break;
    
    default:
      output = `Executed ${taskId} against ${target}`;
  }

  res.json({
    success: true,
    taskInstanceId,
    output,
    artifactPath,
    exitCode: 0,
    duration
  });
});

// Catch-all route to serve React app
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'build', 'index.html'));
});

// Ensure all other routes not handled before are returned to React router
app.use((req, res) => {
  if (!req.path.startsWith('/api/')) {
    res.sendFile(path.join(__dirname, 'frontend', 'build', 'index.html'));
  } else {
    res.status(404).json({ error: 'API endpoint not found' });
  }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Standalone Lab Control Server running on port ${PORT}`);
  console.log(`👉 Open http://localhost:${PORT} in your browser`);
  console.log(`📝 API keys: op_1234567890abcdef (operator) or adm_fedcba0987654321 (admin)`);
});