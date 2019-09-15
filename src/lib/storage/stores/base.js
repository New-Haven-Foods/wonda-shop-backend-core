/* eslint-disable no-unused-vars */

const constants = require('../../constants/');

/**
 * This class defines the base store interface and implements the advanced ones, which only
 * uses the methods from the defined base store interface.  It should only contain static members.
 */
class BaseStore {
  static async insert(connection, collectionName, newDoc) {
    throw new Error(constants.STORE.ERROR_MSG.INTERFACE_NOT_IMPLEMENTED);
  }

  static async select(connection, collectionName, query = {}) {
    throw new Error(constants.STORE.ERROR_MSG.INTERFACE_NOT_IMPLEMENTED);
  }

  static async update(connection, tableName, query, newFieldValue) {
    throw new Error(constants.STORE.ERROR_MSG.INTERFACE_NOT_IMPLEMENTED);
  }

  static async delete(connection, tableName, query) {
    throw new Error(constants.STORE.ERROR_MSG.INTERFACE_NOT_IMPLEMENTED);
  }

  static async configIndex(connection) {
    throw new Error(constants.STORE.ERROR_MSG.INTERFACE_NOT_IMPLEMENTED);
  }

  static async dropTable(connection, tableName) {
    throw new Error(constants.STORE.ERROR_MSG.INTERFACE_NOT_IMPLEMENTED);
  }

  static async dropDb(connection) {
    throw new Error(constants.STORE.ERROR_MSG.INTERFACE_NOT_IMPLEMENTED);
  }

  static async close(connection) {
    throw new Error(constants.STORE.ERROR_MSG.INTERFACE_NOT_IMPLEMENTED);
  }

  static async on(connection, event) {
    throw new Error(constants.STORE.ERROR_MSG.INTERFACE_NOT_IMPLEMENTED);
  }

  static async upsert(connection, tableName, query, newRows) {
    const rows = await this.select(connection, tableName, query);

    if (rows.length) {
      return this.update(connection, tableName, query, newRows);
    }
    return this.insert(connection, tableName, newRows);
  }
}

module.exports = exports = BaseStore;
