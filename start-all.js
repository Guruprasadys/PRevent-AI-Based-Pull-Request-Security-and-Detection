/**
 * Unified Full-Stack Launcher for PRevent (MERN Stack)
 * Automatically starts the Express + MongoDB Backend (port 5000)
 * and the React + Vite Frontend (port 5173) together so ECONNREFUSED never happens.
 */
const { spawn } = require('child_process');
const path = require('path');

const isWin = process.platform === 'win32';
const npmCmd = isWin ? 'npm.cmd' : 'npm';

console.log('==========================================================');
console.log('  PRevent MERN Stack — Starting Backend (5000) & UI (5173)');
console.log('==========================================================');

const backend = spawn(npmCmd, ['start'], {
  cwd: path.join(__dirname, 'backend'),
  stdio: 'inherit',
  shell: isWin
});

// Give backend 1.5s to bind port 5000 before Vite dev server starts proxying
setTimeout(() => {
  const frontend = spawn(npmCmd, ['run', 'dev'], {
    cwd: path.join(__dirname, 'frontend'),
    stdio: 'inherit',
    shell: isWin
  });

  frontend.on('exit', code => {
    backend.kill();
    process.exit(code || 0);
  });
}, 1500);

process.on('SIGINT', () => {
  backend.kill();
  process.exit(0);
});
