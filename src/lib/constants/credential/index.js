const prodCredential = require('./production');
const testCredential = require('./test');
const devCredential = require('./development');

const env = process.env.NODE_ENV;
let credential;

switch (env) {
  case 'production':
    credential = prodCredential;
    break;
  case 'test':
    credential = testCredential;
    break;
  default:
    credential = devCredential;
    break;
}

module.exports = exports = credential;
