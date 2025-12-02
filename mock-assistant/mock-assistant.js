const http = require('http');
const fs = require('fs/promises');

const PORT = 3000;
let DATA_PATH = './creds.json';

const DATA_PATH_ENV = process.env.DATA_PATH;
if (DATA_PATH_ENV) {
  DATA_PATH = DATA_PATH_ENV;
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'POST' && req.url === '/chat') {
    try {
      const body = await fs.readFile(DATA_PATH, 'utf8');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(body);
      return;
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
      return;
    }
  }

  if (req.method === 'GET' && req.url === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
  return;
});

server.listen(PORT, () => {
  console.log(`Mock chat-assistant listening on http://localhost:${PORT}`);
});
// Allow user to set data path via the DATA_PATH environment variable
// Fallback to './creds.json' if not provided
