const RepoFactory = require('../../../lib/storage/repo-factory');
const MongoStore = require('../../../lib/storage/stores/mongo.store');
const constants = require('../../../lib/constants/');

describe('Repo factory', function() {
  let repo;
  let stubFuncs;

  beforeEach(function() {
    stubFuncs = [];
  });

  afterEach(function() {
    for (const stubFunc of stubFuncs) {
      stubFunc.restore();
    }
  });

  it('can manufacture an existed fully-functional repo :: manufacture()', function() {
    stubFuncs.push(stub(RepoFactory, 'validateStoreInterface'));

    repo = RepoFactory.manufacture(constants.STORE.TYPES.MONGO_DB);

    expect(RepoFactory.validateStoreInterface).to.have.been.calledWith(repo);
    expect(repo).to.equal(MongoStore);
  });

  it('can check if the store interface implemented fully :: validateStoreInterface()', function() {
    repo = {
      insert: () => {},
      select: () => {},
      update: () => {},
      delete: () => {},
      configIndex: () => {},
      dropTable: () => {},
      dropDb: () => {},
      close: () => {},
      on: () => {},
      upsert: () => {},
    };

    expect(() => {
      RepoFactory.validateStoreInterface(repo);
    }).to.not.throw();
  });
});
