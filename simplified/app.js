/**
 * Simplified Lab Control System - Single Server
 * Combines both backend API and frontend serving in one server
 */

const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const { v4: uuidv4 } = require('uuid');
const app = express();
const PORT = 8080;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// API Keys
const API_KEYS = {
  'op_1234567890abcdef': { role: 'operator', id: 'operator-key-1' },
  'adm_fedcba0987654321': { role: 'admin', id: 'admin-key-1' }
};

// Tasks List
const TASKS = {
  'nmap-scan': {
    enabled: true,
    script: 'nmap-scan.sh',
    description: 'Network port scan with service detection',
    requiredRole: 'operator',
    sensitive: false
  },
  'nikto-scan': {
    enabled: true,
    script: 'nikto-scan.sh',
    description: 'Web vulnerability scanner',
    requiredRole: 'operator',
    sensitive: false
  },
  'list-captures': {
    enabled: true,
    script: 'list-captures.sh',
    description: 'List saved packet captures',
    requiredRole: 'operator',
    sensitive: false
  }
};

// Allowed targets
const ALLOWED_TARGETS = ['192.168.56.101', '192.168.56.102', '127.0.0.1'];

// Auth middleware
function authenticate(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey || !API_KEYS[apiKey]) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  req.auth = API_KEYS[apiKey];
  next();
}

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Execute task
app.post('/api/tasks', authenticate, async (req, res) => {
  const { taskId, target } = req.body;
  
  // Validate task
  if (!TASKS[taskId] || !TASKS[taskId].enabled) {
    return res.status(400).json({ error: 'Invalid or disabled task' });
  }
  
  // Validate target
  if (!ALLOWED_TARGETS.includes(target)) {
    return res.status(403).json({ error: 'Target not in allowed list' });
  }
  
  const taskInstanceId = `task_${uuidv4().split('-')[0]}`;
  
  // Simulate task execution
  const output = `SIMULATED_EXECUTION: ${TASKS[taskId].script} ${target}\nTask output for ${taskId} against ${target}\nScan completed successfully.\n`;
  const artifactPath = `/artifacts/simulated-${taskInstanceId}.txt`;
  
  // Create simulated directory and artifact file
  try {
    await fs.mkdir(path.join(__dirname, 'artifacts'), { recursive: true });
    await fs.writeFile(
      path.join(__dirname, 'artifacts', `simulated-${taskInstanceId}.txt`),
      `Simulated artifact for ${taskId} on ${target}\nCreated: ${new Date().toISOString()}\n`
    );
  } catch (err) {
    console.warn('Could not create artifact file:', err.message);
  }
  
  // Return response
  res.json({
    success: true,
    taskInstanceId,
    output,
    artifactPath,
    exitCode: 0,
    duration: 1.2
  });
});

// Serve simplified frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Create simplified frontend directory and files
async function setupFiles() {
  try {
    // Create public directory
    await fs.mkdir(path.join(__dirname, 'public'), { recursive: true });
    await fs.mkdir(path.join(__dirname, 'artifacts'), { recursive: true });
    
    // Create HTML file
    const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lab Control System (Simplified)</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      margin: 0;
      padding: 0;
      background: linear-gradient(to bottom right, #111827, #1f2937);
      color: white;
      min-height: 100vh;
    }
    .container {
      max-width: 1000px;
      margin: 0 auto;
      padding: 20px;
    }
    header {
      background-color: #111827;
      border-bottom: 1px solid #374151;
      padding: 1rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    h1 {
      margin: 0;
      font-size: 1.5rem;
    }
    .api-key {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background-color: red;
    }
    .status-dot.active {
      background-color: #10B981;
    }
    input {
      background-color: #374151;
      border: 1px solid #4B5563;
      color: white;
      padding: 0.5rem;
      border-radius: 4px;
    }
    .main-content {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-top: 20px;
    }
    .controls {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .target-input {
      background-color: #1F2937;
      padding: 16px;
      border-radius: 8px;
      border: 1px solid #374151;
    }
    .tasks-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: 12px;
    }
    .task-card {
      background-color: #1F2937;
      border: 1px solid #374151;
      border-radius: 8px;
      padding: 16px;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .task-card:hover {
      border-color: #60A5FA;
      background-color: #2D3748;
      transform: translateY(-2px);
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .task-icon {
      font-size: 1.5rem;
      margin-bottom: 8px;
    }
    .task-name {
      font-weight: 500;
      margin-bottom: 4px;
    }
    .task-desc {
      font-size: 0.875rem;
      color: #9CA3AF;
    }
    .output-panel {
      background-color: #1F2937;
      border: 1px solid #374151;
      border-radius: 8px;
      overflow: hidden;
    }
    .panel-header {
      background-color: #111827;
      border-bottom: 1px solid #374151;
      padding: 8px 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .output-content {
      padding: 16px;
      font-family: monospace;
      white-space: pre-wrap;
      max-height: 400px;
      overflow: auto;
      font-size: 0.875rem;
    }
    .notification {
      position: fixed;
      top: 20px;
      right: 20px;
      background-color: #111827;
      border-left: 4px solid;
      padding: 12px 16px;
      border-radius: 4px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
      display: flex;
      align-items: center;
      gap: 12px;
      min-width: 300px;
      opacity: 0;
      transform: translateX(100%);
      transition: all 0.3s ease;
    }
    .notification.error {
      border-left-color: #EF4444;
    }
    .notification.success {
      border-left-color: #10B981;
    }
    .notification.show {
      opacity: 1;
      transform: translateX(0);
    }
    .loading {
      display: inline-block;
      width: 16px;
      height: 16px;
      border: 2px solid rgba(255,255,255,0.3);
      border-radius: 50%;
      border-top-color: white;
      animation: spin 1s linear infinite;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
  </style>
</head>
<body>
  <header>
    <div style="display: flex; align-items: center; gap: 12px;">
      <div style="font-size: 1.5rem;">🛡️</div>
      <div>
        <h1>Lab Control System</h1>
        <div style="font-size: 0.75rem; color: #9CA3AF;">Isolated Lab Environment Only</div>
      </div>
    </div>
    <div class="api-key">
      <div class="status-dot" id="keyStatus"></div>
      <input type="password" id="apiKey" placeholder="API Key" value="">
    </div>
  </header>

  <div class="container">
    <div class="main-content">
      <!-- Left Column - Controls -->
      <div class="controls">
        <div class="target-input">
          <label style="display: block; font-size: 0.875rem; color: #9CA3AF; margin-bottom: 8px;">Target IP Address</label>
          <input type="text" id="targetInput" value="192.168.56.101" style="width: 100%;">
        </div>

        <div class="tasks-grid" id="tasksContainer">
          <!-- Tasks will be inserted here -->
        </div>
      </div>

      <!-- Right Column - Output -->
      <div class="output-panel">
        <div class="panel-header">
          <div style="display: flex; align-items: center; gap: 8px;">
            <div style="font-size: 0.875rem;">📊</div>
            <h3 style="margin: 0; font-size: 0.875rem;">Task Output</h3>
          </div>
          <div id="executingIndicator" style="display: none;">
            <div class="loading"></div>
            <span style="font-size: 0.75rem; color: #60A5FA; margin-left: 8px;">Running...</span>
          </div>
        </div>
        <pre class="output-content" id="outputContent">No output yet. Run a task to see results here.</pre>
      </div>
    </div>
  </div>

  <!-- Notifications -->
  <div class="notification" id="notification">
    <div id="notificationIcon">✓</div>
    <div id="notificationMessage"></div>
  </div>

  <script>
    // State
    let isExecuting = false;
    const apiKeyInput = document.getElementById('apiKey');
    const keyStatus = document.getElementById('keyStatus');
    const targetInput = document.getElementById('targetInput');
    const tasksContainer = document.getElementById('tasksContainer');
    const outputContent = document.getElementById('outputContent');
    const executingIndicator = document.getElementById('executingIndicator');
    const notification = document.getElementById('notification');
    const notificationMessage = document.getElementById('notificationMessage');
    const notificationIcon = document.getElementById('notificationIcon');

    // Define available tasks
    const tasks = [
      {
        id: 'nmap-scan',
        name: 'Nmap Scan',
        description: 'Port scan with service detection',
        icon: '🔍'
      },
      {
        id: 'nikto-scan',
        name: 'Nikto Scan',
        description: 'Web vulnerability scanner',
        icon: '🌐'
      },
      {
        id: 'list-captures',
        name: 'List Captures',
        description: 'Show saved captures',
        icon: '📋'
      }
    ];

    // Render tasks
    function renderTasks() {
      tasksContainer.innerHTML = '';
      tasks.forEach(task => {
        const taskCard = document.createElement('div');
        taskCard.className = 'task-card';
        taskCard.onclick = () => executeTask(task.id);
        
        taskCard.innerHTML = \`
          <div class="task-icon">\${task.icon}</div>
          <div class="task-name">\${task.name}</div>
          <div class="task-desc">\${task.description}</div>
        \`;
        
        tasksContainer.appendChild(taskCard);
      });
    }

    // Execute task
    async function executeTask(taskId) {
      if (isExecuting) return;
      
      const apiKey = apiKeyInput.value;
      const target = targetInput.value;
      
      if (!apiKey) {
        showNotification('Please enter an API key', 'error');
        return;
      }
      
      if (!target) {
        showNotification('Please enter a target IP', 'error');
        return;
      }
      
      try {
        isExecuting = true;
        executingIndicator.style.display = 'flex';
        const taskInfo = tasks.find(t => t.id === taskId);
        outputContent.textContent = \`Executing \${taskInfo.name} against \${target}...\n\n\`;
        
        const response = await fetch('/api/tasks', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': apiKey
          },
          body: JSON.stringify({
            taskId,
            target
          })
        });
        
        const data = await response.json();
        
        if (response.ok) {
          let outputText = \`Task ID: \${data.taskInstanceId}\n\`;
          outputText += \`Status: \${data.success ? 'Success' : 'Failed'}\n\`;
          outputText += \`Exit Code: \${data.exitCode}\n\`;
          outputText += \`Duration: \${data.duration?.toFixed(2)}s\n\n\`;
          
          if (data.artifactPath) {
            outputText += \`Artifact: \${data.artifactPath}\n\n\`;
          }
          
          outputText += \`Output:\n\${data.output}\`;
          
          outputContent.textContent = outputText;
          showNotification(\`\${taskInfo.name} completed successfully\`, 'success');
        } else {
          throw new Error(data.error || 'Task execution failed');
        }
      } catch (error) {
        outputContent.textContent = \`Error: \${error.message}\`;
        showNotification(error.message, 'error');
      } finally {
        isExecuting = false;
        executingIndicator.style.display = 'none';
      }
    }

    // Show notification
    function showNotification(message, type = 'success') {
      notificationMessage.textContent = message;
      notification.className = \`notification \${type}\`;
      
      if (type === 'error') {
        notificationIcon.textContent = '⚠️';
      } else {
        notificationIcon.textContent = '✓';
      }
      
      notification.classList.add('show');
      
      setTimeout(() => {
        notification.classList.remove('show');
      }, 3000);
    }

    // Update key status indicator
    apiKeyInput.addEventListener('input', () => {
      keyStatus.classList.toggle('active', apiKeyInput.value.length > 0);
    });

    // Initialize
    renderTasks();
  </script>
</body>
</html>
    `;
    
    await fs.writeFile(path.join(__dirname, 'public', 'index.html'), htmlContent);
    
    console.log('Simplified application files created successfully!');
  } catch (err) {
    console.error('Error setting up files:', err);
  }
}

// Setup files and start server
async function start() {
  await setupFiles();
  
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Simplified Lab Control System running on port ${PORT}`);
    console.log(`Access at: http://localhost:${PORT}`);
  });
}

start();
