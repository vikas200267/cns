/**
 * Integration test for lab control system
 */
const axios = require('axios');
const { spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');

const API_URL = 'http://localhost:3001';
const API_KEY = process.env.TEST_API_KEY || 'op_1234567890abcdef';

async function main() {
  console.log('Starting integration tests...');

  try {
    // Start docker compose
    console.log('Starting docker-compose...');
    const compose = spawn('docker-compose', ['up', '-d']);
    
    await new Promise((resolve, reject) => {
      compose.on('close', (code) => {
        if (code === 0) resolve();
        else reject(new Error(`docker-compose failed with code ${code}`));
      });
    });

    // Wait for backend to be ready
    console.log('Waiting for backend...');
    await new Promise(r => setTimeout(r, 5000));

    // Test health endpoint
    console.log('Testing health endpoint...');
    const health = await axios.get(`${API_URL}/health`);
    console.assert(health.data.status === 'healthy', 'Health check failed');

    // Test nmap scan
    console.log('Testing nmap scan...');
    const nmap = await axios.post(
      `${API_URL}/api/tasks`,
      {
        taskId: 'nmap-scan',
        target: '192.168.56.101'
      },
      {
        headers: { 'x-api-key': API_KEY }
      }
    );

    console.assert(nmap.data.success, 'Nmap scan failed');
    console.assert(nmap.data.artifactPath, 'No artifact path returned');

    // Verify artifact exists
    const artifactExists = await fs.access(nmap.data.artifactPath)
      .then(() => true)
      .catch(() => false);
    
    console.assert(artifactExists, 'Artifact file not created');

    // Test packet capture
    console.log('Testing packet capture...');
    const capture = await axios.post(
      `${API_URL}/api/tasks`,
      {
        taskId: 'start-capture',
        target: '192.168.56.101'
      },
      {
        headers: { 'x-api-key': API_KEY }
      }
    );

    console.assert(capture.data.success, 'Packet capture failed');
    
    // Wait for capture to complete
    await new Promise(r => setTimeout(r, 65000));

    // Verify pcap exists
    const pcapExists = await fs.access(capture.data.artifactPath)
      .then(() => true)
      .catch(() => false);
    
    console.assert(pcapExists, 'PCAP file not created');

    console.log('All tests passed!');

  } catch (error) {
    console.error('Test failed:', error);
    process.exit(1);
  } finally {
    // Cleanup
    console.log('Cleaning up...');
    spawn('docker-compose', ['down']);
  }
}

main().catch(console.error);