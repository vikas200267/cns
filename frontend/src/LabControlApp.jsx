/**
 * Lab Control Frontend Application
 * 
 * Provides web UI for executing whitelisted pentest tasks
 * against allowed targets in an isolated lab environment.
 */

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  XMarkIcon,
  CheckCircleIcon,
  ArrowPathIcon,
  Squares2X2Icon,
  ListBulletIcon,
  ShieldExclamationIcon,
  XCircleIcon,
} from '@heroicons/react/24/outline';
import axios from 'axios';

// API URL Configuration
// Use relative URLs to leverage the proxy in package.json
const getApiUrl = () => {
  // In development with proxy, use relative URLs (empty string means same origin)
  // This allows the webpack dev server proxy to forward requests to the backend
  if (process.env.NODE_ENV === 'development') {
    console.log('Development mode - using proxy (relative URLs)');
    return '';  // Relative URLs will be proxied to localhost:3001
  }
  
  // Check if running in Simple Browser or localhost
  const isLocalhost = window.location.hostname === 'localhost' || 
                      window.location.hostname === '127.0.0.1' ||
                      window.location.hostname === '0.0.0.0';
  
  if (isLocalhost) {
    console.log('Local access detected - using http://localhost:3001');
    return 'http://localhost:3001';
  }
  
  // Check for explicit environment variable
  if (process.env.REACT_APP_BACKEND_URL) {
    console.log('Using env backend URL:', process.env.REACT_APP_BACKEND_URL);
    return process.env.REACT_APP_BACKEND_URL;
  }
  
  // In Codespaces public URL, replace port 3000 with 3001
  if (window.location.hostname.includes('github.dev') || window.location.hostname.includes('app.github.dev')) {
    const backendUrl = window.location.origin.replace('-3000.', '-3001.');
    console.log('Codespaces public URL detected - using:', backendUrl);
    return backendUrl;
  }
  
  // Fallback to localhost
  console.log('Fallback to localhost backend');
  return 'http://localhost:3001';
};

const API_URL = getApiUrl();
console.log('✓ Frontend configured to connect to API at:', API_URL || 'same-origin (via proxy)');

const LabControlApp = () => {
  const [apiKey, setApiKey] = useState('');
  const [target, setTarget] = useState('192.168.56.101');
  const [tasks, setTasks] = useState([]);
  const [output, setOutput] = useState('');
  const [logs, setLogs] = useState([]);
  const [isExecuting, setIsExecuting] = useState(false);
  const [confirmTask, setConfirmTask] = useState(null);

  // Load tasks from backend (tasks.json via API or hardcoded)
  useEffect(() => {
    const defaultTasks = [
      {
        id: 'nmap-scan',
        name: 'Nmap Scan',
        description: 'Port scan with service detection',
        icon: '🔍',
        role: 'operator',
        sensitive: false
      },
      {
        id: 'nikto-scan',
        name: 'Nikto Scan',
        description: 'Web vulnerability scanner',
        icon: '🌐',
        role: 'operator',
        sensitive: false
      },
      {
        id: 'start-capture',
        name: 'Start Capture',
        description: 'Begin packet capture (60s)',
        icon: '📡',
        role: 'operator',
        sensitive: false
      },
      {
        id: 'stop-capture',
        name: 'Stop Capture',
        description: 'Stop packet capture',
        icon: '⏹️',
        role: 'operator',
        sensitive: false
      },
      {
        id: 'session-hijack',
        name: 'Session Hijack',
        description: 'Capture session cookies (HTTP)',
        icon: '🎯',
        role: 'operator',
        sensitive: true
      },
      {
        id: 'session-hijack-msf',
        name: 'MSF Session Hijack',
        description: 'Metasploit-style exploitation',
        icon: '💀',
        role: 'operator',
        sensitive: true
      },
      {
        id: 'session-protect',
        name: 'Session Protection',
        description: 'Monitor & secure sessions',
        icon: '🛡️',
        role: 'operator',
        sensitive: false
      },
      {
        id: 'add-firewall',
        name: 'Add Firewall',
        description: 'Configure firewall rules',
        icon: '🔥',
        role: 'operator',
        sensitive: false
      }
    ];
    setTasks(defaultTasks);
  }, []);

  // Load recent logs
  const loadLogs = async () => {
    if (!apiKey) return;
    
    try {
      const response = await axios.get(`${API_URL}/api/logs?limit=10`, {
        headers: { 'x-api-key': apiKey }
      });
      setLogs(response.data.logs || []);
    } catch (error) {
      // Only admin can view logs
      if (error.response?.status !== 403) {
        console.error('Failed to load logs:', error);
      }
    }
  };

  useEffect(() => {
    if (apiKey) {
      loadLogs();
      const interval = setInterval(loadLogs, 10000); // Refresh every 10s
      return () => clearInterval(interval);
    }
  }, [apiKey]);

  // Execute task
  const executeTask = async (taskId, confirmed = false) => {
    if (!apiKey) {
      toast.error('Please enter an API key', {
        position: 'top-right',
        theme: 'dark',
        icon: '🔑'
      });
      return;
    }

    if (!target) {
      toast.error('Please enter a target IP', {
        position: 'top-right',
        theme: 'dark',
        icon: '🎯'
      });
      return;
    }

    const task = tasks.find(t => t.id === taskId);

    setIsExecuting(true);
    setOutput(`Executing ${task.name} against ${target}...\n\n`);
    
    const toastId = toast.loading(`Running ${task.name}...`, {
      position: 'top-right',
      theme: 'dark',
    });

    console.log('=== Task Execution Debug ===');
    console.log('API URL:', API_URL);
    console.log('Task ID:', taskId);
    console.log('Target:', target);
    console.log('API Key:', apiKey ? '***' + apiKey.slice(-4) : 'NOT SET');

    try {
      const response = await axios.post(
        `${API_URL}/api/tasks`,
        {
          taskId,
          target
        },
        {
          headers: {
            'x-api-key': apiKey,
            'Content-Type': 'application/json'
          },
          timeout: 960000  // 16 minutes timeout to allow nikto scan to complete
        }
      );

      const result = response.data;
      
      // Handle async tasks (nikto, nmap)
      if (result.async && result.status === 'running') {
        const taskInstanceId = result.taskInstanceId;
        setOutput(`Task started: ${taskInstanceId}\nStatus: Running...\n\nPolling for results every 3 seconds...`);
        
        toast.update(toastId, {
          render: `${task.name} started - monitoring progress...`,
          type: 'info',
          isLoading: true
        });
        
        // Poll for task completion
        const pollInterval = setInterval(async () => {
          try {
            const statusResponse = await axios.get(
              `${API_URL}/api/tasks/${taskInstanceId}`,
              {
                headers: { 'x-api-key': apiKey }
              }
            );
            
            const status = statusResponse.data;
            
            if (status.status === 'completed') {
              clearInterval(pollInterval);
              setIsExecuting(false);
              
              let outputText = `Task ID: ${taskInstanceId}\n`;
              outputText += `Status: ${status.success ? 'Success' : 'Failed'}\n`;
              outputText += `Exit Code: ${status.exitCode}\n`;
              outputText += `Duration: ${status.duration?.toFixed(2)}s\n\n`;
              
              if (status.artifactPath) {
                const artifact = status.artifactPath;
                if (artifact.startsWith('http')) {
                  outputText += `Artifact: ${artifact}\n\n`;
                } else {
                  outputText += `Artifact path: ${artifact}\n\n`;
                }
              }
              
              outputText += `Output:\n${status.output}`;
              setOutput(outputText);
              loadLogs();
              
              toast.update(toastId, {
                render: `${task.name} completed successfully!`,
                type: 'success',
                isLoading: false,
                autoClose: 3000,
                icon: '✅'
              });
            } else if (status.status === 'failed') {
              clearInterval(pollInterval);
              setIsExecuting(false);
              
              setOutput(`Task ID: ${taskInstanceId}\nStatus: Failed\nError: ${status.error}`);
              
              toast.update(toastId, {
                render: `${task.name} failed`,
                type: 'error',
                isLoading: false,
                autoClose: 5000,
                icon: '❌'
              });
            } else {
              // Still running, update output
              const elapsed = Math.floor((Date.now() - status.startTime) / 1000);
              setOutput(`Task started: ${taskInstanceId}\nStatus: Running...\nElapsed: ${elapsed}s\n\nTask is executing in the background. Results will appear when complete.`);
            }
          } catch (pollError) {
            console.error('Poll error:', pollError);
          }
        }, 3000);  // Poll every 3 seconds
        
        // Set a safety timeout to stop polling after 20 minutes
        setTimeout(() => {
          clearInterval(pollInterval);
          if (isExecuting) {
            setIsExecuting(false);
            toast.update(toastId, {
              render: 'Task timeout - check logs for status',
              type: 'warning',
              isLoading: false,
              autoClose: 5000
            });
          }
        }, 1200000);  // 20 minutes
        
        return;
      }
      
      // Handle synchronous tasks
      let outputText = `Task ID: ${result.taskInstanceId}\n`;
      outputText += `Status: ${result.success ? 'Success' : 'Failed'}\n`;
      outputText += `Exit Code: ${result.exitCode}\n`;
      outputText += `Duration: ${result.duration?.toFixed(2)}s\n\n`;
      
      if (result.artifactPath) {
        // Provide a clickable link if artifact path looks like an HTTP URL, otherwise show path
        const artifact = result.artifactPath;
        if (artifact.startsWith('http')) {
          outputText += `Artifact: ${artifact}\n\n`;
        } else {
          outputText += `Artifact path: ${artifact}\n\n`;
        }
      }
      
      outputText += `Output:\n${result.output}`;
      
      setOutput(outputText);
      
      // Refresh logs
      loadLogs();

      toast.update(toastId, {
        render: `Task ${task.name} completed successfully!`,
        type: 'success',
        isLoading: false,
        autoClose: 3000,
        icon: '✅'
      });

    } catch (error) {
      console.error('=== Task Execution Error ===');
      console.error('Error object:', error);
      console.error('Error message:', error.message);
      console.error('Has response:', !!error.response);
      console.error('Error config:', error.config);
      
      let errorMsg = 'Task execution failed\n\n';
      
      if (error.response) {
        console.error('Response status:', error.response.status);
        console.error('Response data:', error.response.data);
        errorMsg += `Status: ${error.response.status}\n`;
        errorMsg += `Error: ${error.response.data.error || 'Unknown error'}\n`;
        
        if (error.response.data.details) {
          errorMsg += `Details: ${error.response.data.details}\n`;
        }
      } else if (error.request) {
        console.error('Request made but no response:', error.request);
        errorMsg += `Error: ${error.message}\n`;
        errorMsg += `\nNo response from backend. Check:\n`;
        errorMsg += `1. Backend is running: ${API_URL}/health\n`;
        errorMsg += `2. Network connectivity\n`;
        errorMsg += `3. Browser console for CORS errors\n`;
      } else {
        console.error('Error setting up request:', error.message);
        errorMsg += `Error: ${error.message}\n`;
      }
      
      setOutput(errorMsg);
      
      toast.update(toastId, {
        render: error.response?.data?.error || 'Task execution failed',
        type: 'error',
        isLoading: false,
        autoClose: 5000,
        icon: '❌'
      });
    } finally {
      setIsExecuting(false);
      setConfirmTask(null);
    }
  };

  // Confirmation modal for sensitive tasks
  const ConfirmationModal = ({ task, onConfirm, onCancel }) => (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 max-w-md mx-4 border border-red-500">
        <div className="flex items-start gap-3 mb-4">
          <ExclamationTriangleIcon className="w-6 h-6 text-red-500 flex-shrink-0 mt-1" />
          <div>
            <h3 className="text-xl font-bold text-white mb-2">
              Confirm Sensitive Task
            </h3>
            <p className="text-gray-300 mb-2">{task.warning}</p>
            <p className="text-sm text-gray-400">
              Task: <span className="text-white font-mono">{task.id}</span>
            </p>
            <p className="text-sm text-gray-400">
              Target: <span className="text-white font-mono">{target}</span>
            </p>
          </div>
        </div>
        
        <div className="bg-red-900 bg-opacity-30 border border-red-700 rounded p-3 mb-4">
          <p className="text-red-200 text-sm">
            This task can cause disruption. Only proceed if you understand the impact
            and have permission to test this target.
          </p>
        </div>
        
        <div className="flex gap-3">
          <button
            onClick={onCancel}
            className="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded"
          >
            Cancel
          </button>
          <button
            onClick={() => onConfirm(task.id, true)}
            className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded font-semibold"
          >
            Confirm & Execute
          </button>
        </div>
      </div>
    </div>
  );

  // Main render
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white"
    >
      {/* Header */}
      <motion.div 
        initial={{ y: -20 }}
        animate={{ y: 0 }}
        className="bg-gray-900 border-b border-gray-700 sticky top-0 z-40 backdrop-blur-md bg-opacity-80">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <ShieldCheckIcon className="w-8 h-8 text-cyan-400" />
              <div>
                <h1 className="text-2xl font-bold">Lab Control System</h1>
                <p className="text-sm text-gray-400">Isolated Lab Environment Only</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <div className={`w-3 h-3 rounded-full ${apiKey ? 'bg-green-500' : 'bg-red-500'}`} />
              <input
                type="password"
                placeholder="API Key"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                className="px-3 py-1 bg-gray-800 rounded border border-gray-700"
              />
            </div>
          </div>
        </div>
      </motion.div>

      {/* Main content */}
      <motion.div 
        initial={{ y: 20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.2 }}
        className="max-w-7xl mx-auto px-4 py-6"
      >
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          
          {/* Left column - Controls */}
          <div className="space-y-6">
            {/* Target input */}
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <label className="block text-sm font-medium text-gray-400 mb-2">
                Target IP Address
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="192.168.56.101"
                className="w-full px-3 py-2 bg-gray-900 rounded border border-gray-700"
              />
            </div>

            {/* Tasks grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {tasks.map((task) => (
                <motion.button
                  key={task.id}
                  onClick={() => executeTask(task.id)}
                  disabled={isExecuting}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className={`
                    p-4 rounded-lg border text-left transition-all duration-200 relative
                    ${isExecuting 
                      ? 'bg-gray-800 border-gray-700 cursor-not-allowed opacity-50'
                      : 'bg-gray-800 border-gray-700 hover:border-cyan-500 hover:bg-gray-700 hover:shadow-lg hover:shadow-cyan-500/20'
                    }
                  `}
                >
                  <div className="text-2xl mb-2 transform transition-transform group-hover:scale-110">{task.icon}</div>
                  <h3 className="font-medium mb-1 text-cyan-50">{task.name}</h3>
                  <p className="text-sm text-gray-400 group-hover:text-gray-300">{task.description}</p>
                </motion.button>
              ))}
            </div>
          </div>

          {/* Right column - Output & Logs */}
          <div className="space-y-6">
            {/* Task output */}
            <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
              <div className="flex items-center justify-between px-4 py-2 bg-gray-900 border-b border-gray-700">
                <div className="flex items-center gap-2">
                  <Squares2X2Icon className="w-4 h-4 text-gray-400" />
                  <h2 className="font-medium">Task Output</h2>
                </div>
                {isExecuting && (
                  <div className="flex items-center gap-2 text-cyan-400">
                    <ArrowPathIcon className="w-4 h-4 animate-spin" />
                    <span className="text-sm">Running...</span>
                  </div>
                )}
              </div>
              <pre className="p-4 text-sm font-mono whitespace-pre-wrap overflow-auto max-h-96">
                {output || 'No output yet. Run a task to see results here.'}
              </pre>
            </div>

            {/* Recent logs */}
            <div className="bg-gray-800 rounded-lg border border-gray-700">
              <div className="flex items-center justify-between px-4 py-2 bg-gray-900 border-b border-gray-700">
                <div className="flex items-center gap-2">
                  <ListBulletIcon className="w-4 h-4 text-gray-400" />
                  <h2 className="font-medium">Recent Activity</h2>
                </div>
                <button
                  onClick={loadLogs}
                  className="p-1 hover:bg-gray-800 rounded"
                >
                  <ArrowPathIcon className="w-4 h-4" />
                </button>
              </div>
              <div className="divide-y divide-gray-700">
                {logs.length === 0 ? (
                  <div className="px-4 py-3 text-sm text-gray-400">
                    No recent activity
                  </div>
                ) : (
                  logs.map((log) => (
                    <div key={log.taskInstanceId} className="px-4 py-3">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="font-medium">{log.taskId}</p>
                          <p className="text-sm text-gray-400">
                            Target: {log.target}
                          </p>
                        </div>
                        <div className="text-right">
                          <p className="text-sm text-gray-400">
                            {new Date(log.timestamp).toLocaleTimeString()}
                          </p>
                          <div className="flex items-center gap-1 mt-1">
                            {log.success ? (
                              <CheckCircle className="w-4 h-4 text-green-500" />
                            ) : (
                              <XCircle className="w-4 h-4 text-red-500" />
                            )}
                            <span className={`text-sm ${log.success ? 'text-green-500' : 'text-red-500'}`}>
                              {log.exitCode === 0 ? 'Success' : `Failed (${log.exitCode})`}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Confirmation modal */}
      {confirmTask && (
        <ConfirmationModal
          task={confirmTask}
          onConfirm={executeTask}
          onCancel={() => setConfirmTask(null)}
        />
      )}
      
      <ToastContainer
        position="top-right"
        autoClose={5000}
        hideProgressBar={false}
        newestOnTop
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme="dark"
      />
    </motion.div>
  );
};

export default LabControlApp;