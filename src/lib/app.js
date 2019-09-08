/**
 * The process of the web application begins here - non-cluster mode.
 */

const setupExpressServer = require('./servers/express.server');
const setupRoutes = require('./routes/');
const packageJson = require('../../package.json');
const express = require('express');
const http = require('http');

// Set Node environment default to "development".
process.env.NODE_ENV = process.env.NODE_ENV || 'development';

const app = express();
const server = http.createServer(app);

setupExpressServer(app);
setupRoutes(app);

const ip = process.env.IP || packageJson.config.ip;
const port = process.env.PORT || packageJson.config.port;

const webServer = server.listen(port, ip, () => {
  console.log(
    'Express server listening on port: %d at IP: %s, in %s mode',
    webServer.address().port,
    webServer.address().address,
    app.get('env')
  );
});

// Cleans up whenever the app crashes.
process.on('uncaughtException', err => {
  console.log('Crashed...', err);
  process.exit(0);
});
// Cleans up whenever getting interrupted by an user (ctrl + c).
process.on('SIGINT', err => {
  console.log('Interrupted by an user...', err);
  process.exit(0);
});

// Cleans up whenever getting a default terminate signal.
process.on('SIGTERM', err => {
  console.log('Got a default terminate signal...', err);
  process.exit(0);
});

module.exports = exports = app;
