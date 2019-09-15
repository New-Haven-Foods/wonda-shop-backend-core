const BaseStore = require('./base');
const constants = require('../../constants/');
const packageJson = require('../../../../package.json');
const Sequelize = require('sequelize');

const storeType = constants.STORE.TYPES.POSTGRES;
const packageJsonDbConfig = packageJson.config.databases[storeType];

/**
 * This class implements of the base store interface.  It should only contain static members.
 */
class PostgresStore extends BaseStore {
  static async insert(connection, tableName, newDoc) {
    return connection.client.model(tableName).create(newDoc);
  }

  static async select(connection, tableName, query) {
    return connection.client.model(tableName).findAll({ where: query });
  }

  static async update(connection, tableName, query, newFieldValue) {
    return connection.client.model(tableName).update(newFieldValue, { where: query });
  }

  static async delete(connection, tableName, query) {
    return connection.client.model(tableName).destroy({ where: query });
  }

  static async dropTable(connection, tableName) {
    return connection.client.model(tableName).drop();
  }

  static async dropDb(connection) {
    const { host, port, dbName } = connection;
    const switchedToAdminDb = 'postgres';
    const sequelize = new Sequelize(
      `postgres://${host}:${port}/${switchedToAdminDb}`,
      packageJsonDbConfig.options
    );

    return sequelize.query(`DROP DATABASE "${dbName}"`);
  }

  static async close(connection) {
    return connection.client.close();
  }

  static async createTable(connection, tableName, schema) {
    connection.client.define(tableName, schema);
    return connection.client.sync({ force: true });
  }

  static async createDb(
    host = packageJsonDbConfig.host,
    port = packageJsonDbConfig.port,
    dbName = packageJsonDbConfig.dbName
  ) {
    const sequelize = new Sequelize(`postgres://${host}:${port}`, packageJsonDbConfig.options);

    return sequelize.query(`CREATE DATABASE "${dbName}"`);
  }
}

PostgresStore.STORE_TYPE = storeType;

module.exports = exports = PostgresStore;
