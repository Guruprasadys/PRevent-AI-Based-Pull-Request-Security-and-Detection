require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { connectDatabase, getDbStatus } = require('./config/db');
const { router: apiRouter, ensureSeeded } = require('./routes/api');

const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));

app.use('/api', apiRouter);

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    stack: 'MERN (MongoDB + Express + React + Node.js)',
    database: getDbStatus()
  });
});

const PORT = Number(process.env.PORT) || 5000;

function startListening(port, retriesLeft = 3) {
  const server = app.listen(port, () => {
    const dbStatus = getDbStatus();
    console.log(`[GitHub API] Token Active: ${dbStatus.github_token_configured ? 'YES (5,000 req/hr)' : 'NO (Public 60 req/hr)'}`);
    console.log(`[PRevent MERN Backend] Server listening on http://localhost:${port}`);
  });

  server.on('error', err => {
    if (err.code === 'EADDRINUSE' && retriesLeft > 0) {
      console.log(`[Server] Port ${port} is busy, waiting 1.5s for previous process to release port...`);
      setTimeout(() => {
        server.close();
        startListening(port, retriesLeft - 1);
      }, 1500);
    } else if (err.code === 'EADDRINUSE') {
      console.error(
        `[Server] Port ${port} is already running another instance of PRevent Backend. Stop the other terminal or use the running server at http://localhost:${port}`
      );
    } else {
      console.error('[Server] Startup error:', err.message);
    }
  });
}

if (require.main === module) {
  connectDatabase().then(async () => {
    await ensureSeeded();
    startListening(PORT);
  });
}

module.exports = { app };
