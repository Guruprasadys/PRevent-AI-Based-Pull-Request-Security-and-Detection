const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const { ScanReportModel } = require('../models/ScanReport');

// Smartly load environment variables from root .env.example, root .env, and backend/.env
// Never overwrite an already-populated variable with an empty string
const envPaths = [
  path.resolve(__dirname, '../../../.env.example'),
  path.resolve(__dirname, '../../../.env'),
  path.resolve(__dirname, '../../.env')
];

for (const envFile of envPaths) {
  if (fs.existsSync(envFile)) {
    const parsed = dotenv.parse(fs.readFileSync(envFile));
    for (const [k, v] of Object.entries(parsed)) {
      if (v && String(v).trim() !== '') {
        process.env[k] = String(v).trim();
      }
    }
  }
}

let isMongoConnected = false;
let connectedDbName = '';
const memoryStore = new Map();

function sanitizeMongoUri(rawUri) {
  let clean = String(rawUri || '').trim();
  // Remove accidental duplicate variable assignment like "MONGO_URI=mongodb+srv://..."
  clean = clean.replace(/^(?:MONGODB_URI|MONGO_URI)\s*=\s*/i, '');
  clean = clean.replace(/^['"]|['"]$/g, '').trim();
  return clean;
}

async function connectDatabase() {
  const rawUri =
    process.env.MONGODB_URI ||
    process.env.MONGO_URI ||
    'mongodb://127.0.0.1:27017/malicious_pr_detector';
  const uri = sanitizeMongoUri(rawUri);

  if (process.env.SKIP_MONGO === 'true') {
    isMongoConnected = false;
    return { mode: 'in-memory-fallback', connected: false };
  }

  try {
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000
    });
    isMongoConnected = true;
    connectedDbName = mongoose.connection.name || 'PR_issue_resolver';
    const isAtlas = uri.startsWith('mongodb+srv://');
    console.log(
      `[MongoDB] Successfully connected to ${isAtlas ? 'MongoDB Atlas Cloud' : 'MongoDB'} (Database: ${connectedDbName})`
    );
    return { mode: isAtlas ? 'mongodb-atlas' : 'mongodb', connected: true };
  } catch (err) {
    isMongoConnected = false;
    console.log(
      `[MongoDB] Connection warning (${err.message}). Using Mongoose-compatible in-memory collection store.`
    );
    return { mode: 'in-memory-fallback', connected: false };
  }
}

async function saveScanReport(report) {
  const cleanCopy = JSON.parse(JSON.stringify(report));
  memoryStore.set(cleanCopy.scan_id, cleanCopy);
  if (isMongoConnected) {
    // Non-blocking background sync to MongoDB Atlas so HTTP responses return in <5ms and never ECONNRESET
    ScanReportModel.findOneAndUpdate(
      { scan_id: cleanCopy.scan_id },
      cleanCopy,
      { upsert: true, new: true }
    ).catch(e => {
      console.error('[MongoDB] Background sync warning:', e.message);
    });
  }
  return serializeReport(cleanCopy);
}

async function getScanReport(scanId) {
  // Fast in-memory lookup first, fallback to MongoDB Atlas
  if (memoryStore.has(scanId)) {
    return memoryStore.get(scanId);
  }
  if (isMongoConnected) {
    try {
      const doc = await ScanReportModel.findOne({ scan_id: scanId }).lean();
      if (doc) {
        memoryStore.set(scanId, doc);
        return doc;
      }
    } catch (e) {
      // fall through
    }
  }
  return null;
}

async function getAllScanReports() {
  if (memoryStore.size === 0 && isMongoConnected) {
    try {
      const docs = await ScanReportModel.find({}).sort({ timestamp: -1 }).lean();
      if (docs && docs.length > 0) {
        for (const d of docs) {
          memoryStore.set(d.scan_id, d);
        }
      }
    } catch (e) {
      // fall through
    }
  }
  const all = Array.from(memoryStore.values());
  all.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
  return all.map(serializeReport);
}

async function clearAllScanReports() {
  memoryStore.clear();
  if (isMongoConnected) {
    try {
      await ScanReportModel.deleteMany({});
    } catch (e) {
      console.error('[MongoDB] Clear error:', e.message);
    }
  }
}

function serializeReport(record) {
  if (!record) return null;
  const copy = { ...record };
  delete copy._raw_static_findings;
  delete copy._raw_dep_findings;
  delete copy._id;
  delete copy.__v;
  return copy;
}

function getDbStatus() {
  const token = String(process.env.GITHUB_TOKEN || '')
    .replace(/^GITHUB_TOKEN\s*=\s*/i, '')
    .replace(/^['"]|['"]$/g, '')
    .trim();
  return {
    connected_to_mongod: isMongoConnected,
    engine: isMongoConnected
      ? `MongoDB Atlas Connected (${connectedDbName})`
      : 'Mongoose Schema + In-Memory Store',
    documents_count: memoryStore.size,
    github_token_configured: Boolean(token)
  };
}

module.exports = {
  connectDatabase,
  saveScanReport,
  getScanReport,
  getAllScanReports,
  clearAllScanReports,
  serializeReport,
  getDbStatus
};
