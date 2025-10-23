const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 8080;

// Configuration
const TARGET = 'https://ominous-yodel-7v54g6x9pgpqhwqg7-3000.app.github.dev';

// Proxy configuration
app.use('/', createProxyMiddleware({
  target: TARGET,
  changeOrigin: true,
  secure: true,
  onProxyReq: (proxyReq, req, res) => {
    console.log(`Proxying request to: ${TARGET}${req.url}`);
  },
  onError: (err, req, res) => {
    console.error('Proxy error:', err);
    res.status(500).send('Proxy error: ' + err.message);
  }
}));

app.listen(PORT, () => {
  console.log(`Proxy server running at http://localhost:${PORT}`);
});
