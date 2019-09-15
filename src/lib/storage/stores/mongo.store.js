const BaseStore = require('./base');
const constants = require('../../constants/');

/**
 * This class implements the base store interface.  It should only contain static members.
 */
class MongoStore extends BaseStore {
  static async insert(connection, collectionName, newDoc) {
    return connection.client.collection(collectionName).saveAsync(newDoc);
  }

  static async select(connection, collectionName, query = {}) {
    return connection.client.collection(collectionName).findAsync(query);
  }

  static async update(connection, collectionName, query, newFieldValueMap, isReplacing = false) {
    if (isReplacing) {
      return connection.client
        .collection(collectionName)
        .findAndModify(query, newFieldValueMap, { multi: true });
    }
    return connection.client
      .collection(collectionName)
      .updateAsync(query, { $set: newFieldValueMap }, { multi: true });
  }

  static delete(connection, collectionName, query) {
    return connection.client.collection(collectionName).removeAsync(query);
  }

  static async dropTable(connection, tableName) {
    return connection.client.collection(tableName).dropAsync();
  }

  static async dropDb(connection) {
    return connection.client.dropDatabaseAsync();
  }

  static async close(connection) {
    return connection.client.closeAsync();
  }

  static async on(connection, event) {
    return connection.client.onAsync(event);
  }
}

MongoStore.STORE_TYPE = constants.STORE.TYPES.MONGO_DB;

module.exports = exports = MongoStore;
