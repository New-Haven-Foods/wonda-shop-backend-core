const MongoStore = require('./stores/mongo.store');
const PostgresStore = require('./stores/postgres.store');
const Validator = require('../utils/precondition-validator');
const constants = require('../constants/');

const stores = {
  [MongoStore.STORE_TYPE]: MongoStore,
  [PostgresStore.STORE_TYPE]: PostgresStore,
};

/**
 * A factory to manufacture a repository, which should implement base store interface
 */
class RepoFactory {
  static manufacture(storeType) {
    const repository = stores[storeType];

    if (repository) {
      RepoFactory.validateStoreInterface(repository);
    } else {
      throw new Error(constants.STORE.ERROR_MSG.STORAGE_TYPE_NOT_FOUND);
    }

    return repository;
  }

  static validateStoreInterface(repo) {
    Validator.shouldNotBeEmpty(repo.insert)
      .shouldNotBeEmpty(repo.select)
      .shouldNotBeEmpty(repo.update)
      .shouldNotBeEmpty(repo.delete)

      .shouldNotBeEmpty(repo.configIndex)
      .shouldNotBeEmpty(repo.dropTable)
      .shouldNotBeEmpty(repo.dropDb)
      .shouldNotBeEmpty(repo.close)
      .shouldNotBeEmpty(repo.on)

      .shouldNotBeEmpty(repo.upsert);
  }
}

module.exports = exports = RepoFactory;
