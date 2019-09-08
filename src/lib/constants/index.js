const systemConstants = require('./system');
const storeConstants = require('./store');
const authConstants = require('./auth');
const credentialConstants = require('./credential/');

module.exports = exports = {
  SYSTEM: systemConstants,
  STORE: storeConstants,
  AUTH: authConstants,
  CREDENTIAL: credentialConstants,
};
