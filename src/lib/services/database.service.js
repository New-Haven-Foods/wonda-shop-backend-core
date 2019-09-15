const storage = require('../storage/');
const packageJson = require('../../../package.json');
const constants = require('../constants/');

const { ConnectionPool, RepoFactory } = storage;

class DatabaseService {
  static async execute(strategy) {
    let connUri;
    const { storeType, tableName, operation } = strategy;
    const packageJsonDbConfig = packageJson.config.databases[storeType];

    switch (storeType) {
      case constants.STORE.TYPES.MONGO_DB:
        connUri = process.env.MONGODB_URI;
        break;
      case constants.STORE.TYPES.POSTGRES:
        connUri = process.env.DATABASE_URL;
        break;
      default:
        throw new Error(constants.STORE.ERROR_MSG.STORAGE_TYPE_NOT_FOUND);
    }

    const dbHost = connUri ? connUri.split('@')[1].split(':')[0] : packageJsonDbConfig.host;
    const dbPort = connUri
      ? connUri
          .split('@')[1]
          .split(':')[1]
          .split('/')[0]
      : packageJsonDbConfig.port;
    const dbName = connUri ? connUri.split('://')[1].split('/')[1] : packageJsonDbConfig.dbName;
    const dbUser = connUri
      ? connUri
          .split('@')[0]
          .split('://')[1]
          .split(':')[0]
      : null;
    const dbPassword = connUri
      ? connUri
          .split('@')[0]
          .split('://')[1]
          .split(':')[1]
      : null;

    const conn = new ConnectionPool(storeType, dbHost, dbPort, dbName, dbUser, dbPassword);
    const repo = RepoFactory.manufacture(storeType);
    const operationType = operation.type;
    const operationData = operation.data;

    return repo[operationType](conn, tableName, ...operationData);
  }
}

module.exports = exports = DatabaseService;
