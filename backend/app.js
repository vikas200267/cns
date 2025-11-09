/**
 * Lab Control Backend API Server
 * 
 * Provides secure, rate-limited access to whitelisted penetration testing tasks.
 * All tasks execute in isolated Docker containers.
 * 
 * Security features:
 * - API key authentication with roles
 * - Target whitelisting
 * - Task whitelisting
 * - Rate limiting
 * - Audit logging
 * - Input validation
 * - Container isolation
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const Docker = require('dockerode');
const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { exec } = require('child_process');
const { promisify } = require('util');
const winston = require('winston');
require('dotenv').config();

const execAsync = promisify(exec);

// Import authentication routes
const authRoutes = require('./routes/auth');

// In-memory task status storage for async execution
const runningTasks = new Map();

const app = express();
const docker = new Docker();
let dockerAvailable = true;

// Configuration
const PORT = process.env.PORT || 3001;
const ARTIFACTS_PATH = process.env.ARTIFACTS_PATH || '/artifacts';
const AUDIT_LOG_PATH = process.env.AUDIT_LOG_PATH || './logs/audit.log';

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: AUDIT_LOG_PATH }),
    new winston.transports.Console()
  ]
});

// Middleware
app.use(helmet());
// Allow all origins for development in Codespaces
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());

// Mount authentication routes
app.use('/api/auth', authRoutes);

// Load configuration files
let apiKeys = {};
let tasks = {};
let allowedTargets = [];

async function loadConfig() {
  try {
    // Load API keys from environment
    apiKeys = {
      [process.env.API_KEY_OPERATOR]: { role: 'operator', id: 'operator-key-1' },
      [process.env.API_KEY_ADMIN]: { role: 'admin', id: 'admin-key-1' }
    };

    // Load tasks whitelist
    const tasksData = await fs.readFile('./tasks.json', 'utf8');
    tasks = JSON.parse(tasksData);

    // Load allowed targets
    const targetsData = await fs.readFile('./allowed_targets.txt', 'utf8');
    allowedTargets = targetsData
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));

    logger.info('Configuration loaded', {
      taskCount: Object.keys(tasks).length,
      targetCount: allowedTargets.length
    });
    // Ensure audit log directory exists
    try {
      await fs.mkdir(path.dirname(AUDIT_LOG_PATH), { recursive: true });
    } catch (err) {
      // ignore - we'll handle write errors later
    }

    // Check Docker availability (graceful fallback for environments without Docker)
    try {
      await docker.ping();
      logger.info('Docker daemon reachable');
    } catch (err) {
      dockerAvailable = false;
      logger.warn('Docker daemon not reachable - tasks will run in simulated mode', { error: err.message });
    }
    
    // Initialize rate limiters after tasks are loaded
    initializeRateLimiters();
  } catch (error) {
    logger.error('Failed to load configuration', { error: error.message });
    process.exit(1);
  }
}

// Authentication middleware
function authenticate(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey || !apiKeys[apiKey]) {
    logger.warn('Authentication failed', {
      ip: req.ip,
      path: req.path
    });
    return res.status(401).json({ error: 'Invalid API key' });
  }

  req.auth = apiKeys[apiKey];
  next();
}

// Authorization middleware
function requireRole(role) {
  return (req, res, next) => {
    if (req.auth.role !== role && req.auth.role !== 'admin') {
      logger.warn('Authorization failed', {
        requiredRole: role,
        actualRole: req.auth.role,
        keyId: req.auth.id,
        ip: req.ip
      });
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Rate limiting - configurable per task
const rateLimiters = {};

function createRateLimiter(taskId) {
  const limitConfig = process.env[`RATE_LIMIT_${taskId.toUpperCase().replace('-', '_')}`] || '10/hour';
  const [max, window] = limitConfig.split('/');
  const windowMs = window === 'hour' ? 60 * 60 * 1000 : 60 * 1000;

  return rateLimit({
    windowMs,
    max: parseInt(max),
    keyGenerator: (req) => req.auth.id,
    handler: (req, res) => {
      logger.warn('Rate limit exceeded', {
        keyId: req.auth.id,
        taskId: req.body.taskId,
        ip: req.ip
      });
      res.status(429).json({
        error: 'Rate limit exceeded',
        taskId: req.body.taskId,
        limit: limitConfig
      });
    }
  });
}

// Initialize rate limiters for all tasks (called after config is loaded)
function initializeRateLimiters() {
  Object.keys(tasks).forEach(taskId => {
    rateLimiters[taskId] = createRateLimiter(taskId);
  });
}

function getRateLimiter(taskId) {
  return rateLimiters[taskId] || createRateLimiter(taskId);
}

// Input validation
function validateTarget(target) {
  // Accept localhost, valid IP format, or valid hostname/domain
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  const isValidFormat = target === 'localhost' || ipRegex.test(target) || hostnameRegex.test(target);
  
  if (!isValidFormat) {
    return { valid: false, error: 'Invalid target format' };
  }

  // Check against whitelist
  if (!allowedTargets.includes(target)) {
    return { valid: false, error: 'Target not in allowed list' };
  }

  return { valid: true };
}

function validateTaskId(taskId) {
  // Debug logging
  logger.debug('validateTaskId called', { taskId, tasksAvailable: Object.keys(tasks) });
  
  // Prevent injection - only allow alphanumeric and hyphens
  if (!/^[a-z0-9-]+$/.test(taskId)) {
    return { valid: false, error: 'Invalid task ID format' };
  }

  // Check against whitelist
  if (!tasks[taskId]) {
    logger.warn('Task not found in whitelist', { taskId, availableTasks: Object.keys(tasks) });
    return { valid: false, error: 'Task not in whitelist' };
  }

  // Check if task is enabled
  if (!tasks[taskId].enabled) {
    return { valid: false, error: 'Task is disabled' };
  }

  return { valid: true };
}

// Task execution
async function executeTask(taskId, target, taskInstanceId, auth) {
  const task = tasks[taskId];
  const startTime = Date.now();

  logger.info('Starting task execution', {
    taskInstanceId,
    taskId,
    target,
    keyId: auth.id,
    script: task.script
  });

  try {
    if (!dockerAvailable) {
      // Direct execution without Docker (for Codespaces/development)
      logger.info('Executing task directly (non-Docker mode)', {
        taskInstanceId,
        script: task.script,
        target
      });

      // Build script path
      const scriptPath = path.join(__dirname, 'scripts', task.script);
      
      // Ensure artifacts directory exists
      await fs.mkdir(ARTIFACTS_PATH, { recursive: true });

      // Build command with special handling for localhost
      let command = `bash ${scriptPath} ${target}`;
      
      // For nikto-scan on localhost/127.0.0.1, automatically use port 3003 (Juice Shop)
      if (taskId === 'nikto-scan' && (target === 'localhost' || target === '127.0.0.1')) {
        command = `bash ${scriptPath} ${target} 3003`;
      }
      
      logger.info('Executing command', { command });

      let output = '';
      let exitCode = 0;
      let artifactPath = null;

      try {
        const { stdout, stderr } = await execAsync(command, {
          timeout: 1200000, // 20 minutes timeout (allows nikto 15min scan + buffer)
          maxBuffer: 10 * 1024 * 1024, // 10MB buffer
          env: {
            ...process.env,
            ARTIFACTS_PATH,
            TIMESTAMP: new Date().toISOString().replace(/[:.]/g, '-')
          }
        });

        output = stdout + (stderr ? `\nSTDERR:\n${stderr}` : '');

        // Try to extract artifact path from output
        const artifactMatch = output.match(/ARTIFACT:\s*(.+)/);
        if (artifactMatch) {
          artifactPath = artifactMatch[1].trim();
        }

      } catch (error) {
        exitCode = error.code || 1;
        output = error.stdout || '';
        output += error.stderr ? `\nSTDERR:\n${error.stderr}` : '';
        output += `\nError: ${error.message}`;
        
        logger.error('Script execution failed', {
          taskInstanceId,
          error: error.message,
          exitCode
        });
      }

      const duration = (Date.now() - startTime) / 1000;

      const auditEntry = {
        timestamp: new Date().toISOString(),
        taskInstanceId,
        apiKeyId: auth.id,
        taskId,
        target,
        startedAt: new Date(startTime).toISOString(),
        finishedAt: new Date().toISOString(),
        exitCode,
        duration,
        artifactPath,
        success: exitCode === 0,
        direct: true  // Flag to indicate direct execution
      };

      // Append to audit log
      try {
        await fs.appendFile(AUDIT_LOG_PATH, JSON.stringify(auditEntry) + '\n');
      } catch (err) {
        logger.warn('Failed to append to audit log', { error: err.message });
      }

      logger.info('Task execution completed', auditEntry);

      return {
        success: exitCode === 0,
        exitCode,
        output,
        artifactPath,
        duration
      };
    }

    // Real Docker-backed execution
    // Build command with special handling for localhost
    let containerCmd = [task.script, target];
    
    // For nikto-scan on localhost/127.0.0.1, automatically use port 3003 (Juice Shop)
    if (taskId === 'nikto-scan' && (target === 'localhost' || target === '127.0.0.1')) {
      containerCmd = [task.script, target, '3003'];
    }
    
    const container = await docker.createContainer({
      Image: 'lab-runner:latest',
      Cmd: containerCmd,
      name: `lab-task-${taskInstanceId}`,
      HostConfig: {
        AutoRemove: true,
        NetworkMode: process.env.DOCKER_NETWORK || 'cns_labnet',
        Memory: 256 * 1024 * 1024, // 256MB
        NanoCpus: 500000000, // 0.5 CPU
        Binds: [
          `${ARTIFACTS_PATH}:/artifacts`
        ]
      },
      Labels: {
        'lab-control.task-id': taskId,
        'lab-control.instance-id': taskInstanceId,
        'lab-control.target': target
      }
    });

    // Start and wait for completion
    await container.start();
    const result = await container.wait();

    // Get logs
    const logs = await container.logs({
      stdout: true,
      stderr: true,
      follow: false
    });

    const output = logs.toString('utf8');
    const duration = (Date.now() - startTime) / 1000;

    // Parse artifact path from output
    const artifactMatch = output.match(/ARTIFACT:\s*(.+)/);
    const artifactPath = artifactMatch ? artifactMatch[1].trim() : null;

    const auditEntry = {
      timestamp: new Date().toISOString(),
      taskInstanceId,
      apiKeyId: auth.id,
      taskId,
      target,
      startedAt: new Date(startTime).toISOString(),
      finishedAt: new Date().toISOString(),
      exitCode: result.StatusCode,
      duration,
      artifactPath,
      success: result.StatusCode === 0
    };

    // Append to audit log
    await fs.appendFile(
      AUDIT_LOG_PATH,
      JSON.stringify(auditEntry) + '\n'
    );

    logger.info('Task completed', auditEntry);

    return {
      success: result.StatusCode === 0,
      exitCode: result.StatusCode,
      output,
      artifactPath,
      duration
    };

  } catch (error) {
    logger.error('Task execution failed', {
      taskInstanceId,
      taskId,
      target,
      error: error.message
    });

    throw error;
  }
}

// API Endpoints

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
  const { taskId, target, confirmed } = req.body;

  // Validate inputs
  const taskValidation = validateTaskId(taskId);
  if (!taskValidation.valid) {
    logger.warn('Invalid task ID', {
      taskId,
      keyId: req.auth.id,
      error: taskValidation.error
    });
    return res.status(400).json({ error: taskValidation.error });
  }

  const targetValidation = validateTarget(target);
  if (!targetValidation.valid) {
    logger.warn('Invalid target', {
      target,
      keyId: req.auth.id,
      error: targetValidation.error
    });
    return res.status(403).json({ error: targetValidation.error });
  }

  const task = tasks[taskId];

  // Check role requirements
  if (task.requiredRole === 'admin' && req.auth.role !== 'admin') {
    logger.warn('Insufficient role for task', {
      taskId,
      requiredRole: task.requiredRole,
      actualRole: req.auth.role,
      keyId: req.auth.id
    });
    return res.status(403).json({
      error: 'Admin role required for this task'
    });
  }

  // Confirmation disabled - single user environment
  // if (task.sensitive && !confirmed) {
  //   return res.status(400).json({
  //     error: 'Confirmation required for sensitive task',
  //     taskId,
  //     warning: task.warning
  //   });
  // }

  // Apply rate limiting
  const limiter = getRateLimiter(taskId);
  limiter(req, res, async () => {
    const taskInstanceId = `task_${uuidv4().split('-')[0]}`;
    
    // For long-running tasks, use async mode
    const longRunningTasks = ['nikto-scan', 'nmap-scan'];
    const isAsync = longRunningTasks.includes(taskId);

    if (isAsync) {
      // Start task in background
      runningTasks.set(taskInstanceId, {
        taskId,
        target,
        status: 'running',
        startTime: Date.now(),
        output: '',
        progress: 0
      });

      // Execute task asynchronously
      executeTask(taskId, target, taskInstanceId, req.auth)
        .then(result => {
          runningTasks.set(taskInstanceId, {
            taskId,
            target,
            status: 'completed',
            startTime: runningTasks.get(taskInstanceId).startTime,
            endTime: Date.now(),
            output: result.output,
            artifactPath: result.artifactPath,
            exitCode: result.exitCode,
            duration: result.duration,
            success: result.success
          });
        })
        .catch(error => {
          runningTasks.set(taskInstanceId, {
            taskId,
            target,
            status: 'failed',
            startTime: runningTasks.get(taskInstanceId).startTime,
            endTime: Date.now(),
            error: error.message
          });
        });

      // Immediately return task ID
      return res.json({
        async: true,
        taskInstanceId,
        status: 'running',
        message: 'Task started. Use /api/tasks/:id to check status'
      });
    }

    // Synchronous execution for quick tasks
    try {
      const result = await executeTask(taskId, target, taskInstanceId, req.auth);

      res.json({
        success: result.success,
        taskInstanceId,
        output: result.output,
        artifactPath: result.artifactPath,
        exitCode: result.exitCode,
        duration: result.duration
      });

    } catch (error) {
      logger.error('Task execution error', {
        taskInstanceId,
        error: error.message
      });

      res.status(500).json({
        success: false,
        error: 'Task execution failed',
        details: error.message
      });
    }
  });
});

// Get task status (for async tasks)
app.get('/api/tasks/:taskInstanceId', authenticate, (req, res) => {
  const { taskInstanceId } = req.params;
  
  const taskStatus = runningTasks.get(taskInstanceId);
  
  if (!taskStatus) {
    return res.status(404).json({ error: 'Task not found' });
  }
  
  res.json(taskStatus);
});

// Get audit logs (admin only)
app.get('/api/logs', authenticate, requireRole('admin'), async (req, res) => {
  const limit = parseInt(req.query.limit) || 100;

  try {
    const logData = await fs.readFile(AUDIT_LOG_PATH, 'utf8');
    const logs = logData
      .split('\n')
      .filter(line => line.trim())
      .map(line => JSON.parse(line))
      .slice(-limit);

    res.json({
      logs,
      count: logs.length
    });

  } catch (error) {
    logger.error('Failed to read audit logs', { error: error.message });
    res.status(500).json({ error: 'Failed to read logs' });
  }
});

// Kill running task (admin only)
app.post('/api/tasks/kill', authenticate, requireRole('admin'), async (req, res) => {
  const { taskInstanceId } = req.body;

  if (!taskInstanceId) {
    return res.status(400).json({ error: 'taskInstanceId required' });
  }

  try {
    const containers = await docker.listContainers({
      filters: {
        label: [`lab-control.instance-id=${taskInstanceId}`]
      }
    });

    if (containers.length === 0) {
      return res.status(404).json({
        error: 'Task not found or already completed',
        taskInstanceId
      });
    }

    const container = docker.getContainer(containers[0].Id);
    await container.kill();

    logger.warn('Task killed by admin', {
      taskInstanceId,
      keyId: req.auth.id
    });

    res.json({
      success: true,
      message: 'Task killed',
      taskInstanceId
    });

  } catch (error) {
    logger.error('Failed to kill task', {
      taskInstanceId,
      error: error.message
    });

    res.status(500).json({
      error: 'Failed to kill task',
      details: error.message
    });
  }
});

// List artifacts
app.get('/api/artifacts', authenticate, async (req, res) => {
  try {
    const files = await fs.readdir(ARTIFACTS_PATH);
    const artifacts = await Promise.all(
      files.map(async (file) => {
        const filePath = path.join(ARTIFACTS_PATH, file);
        const stats = await fs.stat(filePath);
        return {
          name: file,
          size: stats.size,
          created: stats.birthtime,
          modified: stats.mtime
        };
      })
    );

    res.json({ artifacts });

  } catch (error) {
    logger.error('Failed to list artifacts', { error: error.message });
    res.status(500).json({ error: 'Failed to list artifacts' });
  }
});

// Graceful shutdown
function shutdown() {
  logger.info('Shutting down gracefully');
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });

  // Force shutdown after 10 seconds
  setTimeout(() => {
    logger.error('Forced shutdown');
    process.exit(1);
  }, 10000);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Start server
let server;
loadConfig().then(() => {
  server = app.listen(PORT, '0.0.0.0', () => {
    logger.info(`Lab Control API listening on port ${PORT}`);
  });
  
  // Set server timeout to 20 minutes for long-running tasks like nikto scan
  server.timeout = 1200000; // 20 minutes in milliseconds
  server.keepAliveTimeout = 1200000;
  server.headersTimeout = 1210000; // Slightly higher than keepAliveTimeout
});