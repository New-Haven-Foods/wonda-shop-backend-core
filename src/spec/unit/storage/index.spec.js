const storeModule = require('../../../lib/storage/');

describe('Storage root', function() {
  context('for public exposed modules', function() {
    it('should include a repo factory class', function() {
      expect(storeModule.RepoFactory).to.exist;
    });

    it('should include a connection pool class', function() {
      expect(storeModule.ConnectionPool).to.exist;
    });
  });
});
