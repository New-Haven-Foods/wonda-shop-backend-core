exports.ERROR_MSG = {
  STORAGE_TYPE_NOT_FOUND: 'The requesting storage type is not found.',
  INTERFACE_NOT_IMPLEMENTED: 'The implementation for the requested interface is not found.',
};

exports.TYPES = {
  MONGO_DB: 'mongo-store',
  POSTGRES: 'postgres-store',
};

exports.OPERATIONS = {
  INSERT: 'insert',
  SELECT: 'select',
  UPDATE: 'update',
  DELETE: 'delete',
  UPSERT: 'upsert',
};

exports.TABLE_NAMES = {
  USER: 'user',
  SUBSCRIBER: 'subscriber',
};
