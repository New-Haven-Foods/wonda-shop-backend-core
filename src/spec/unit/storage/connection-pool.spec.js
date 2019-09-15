const ConnectionPool = require('../../../lib/storage/connection-pool');
const constants = require('../../../lib/constants/');

describe('Connection pool', function() {
  let connection;

  beforeEach(function() {
    connection = null;
  });

  it('can initiate a new connection with supported store type', function() {
    connection = new ConnectionPool(constants.STORE.TYPES.MONGO_DB);

    expect(connection).to.exist;
  });

  it('throws an error when initiating a new connection with an unsupported STORE type', function() {
    expect(() => {
      connection = new ConnectionPool('unsupported-store');
    }).to.throw();
  });
});
