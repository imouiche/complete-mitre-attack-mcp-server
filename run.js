#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');

// Set PYTHONPATH to include src directory
const srcPath = path.join(__dirname, 'src');
const env = {
  ...process.env,
  PYTHONPATH: srcPath + (process.env.PYTHONPATH ? ':' + process.env.PYTHONPATH : '')
};

// Run the server
const server = spawn('python', ['-m', 'mitre_mcp_server.server'], {
  stdio: 'inherit',
  env: env,
  cwd: __dirname
});

server.on('error', (err) => {
  console.error('Failed to start server:', err.message);
  console.error('Make sure Python 3.12+ is installed');
  process.exit(1);
});

server.on('exit', (code) => {
  process.exit(code || 0);
});
