/**
 * The process of the web application begins here - cluster mode.
 *
 * Usage: Run `$ NODE_DEBUG=cluster node src/lib/cluster-app.js`.
 */

const setupExpressServer = require('./servers/express.server');
const setupRoutes = require('./routes/');
const packageJson = require('../../package.json');
const express = require('express');
const cluster = require('cluster');
const http = require('http');
const os = require('os');

// Set Node environment default to "development".
process.env.NODE_ENV = process.env.NODE_ENV || 'development';

const numCPUs = os.cpus().length;

if (cluster.isMaster) {
  // Forks the master worker.
  for (let i = 0; i < numCPUs; i += 1) {
    cluster.fork();
  }

  cluster.on('exit', (worker /*, code, signal*/) => {
    console.log(`Worker ${worker.process.pid} died`);
  });
} else {
  // Forked Workers can share a new TCP connection.
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
}

module.exports = exports = cluster;
