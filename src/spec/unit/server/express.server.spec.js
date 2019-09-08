const setupExpressServer = require('../../../lib/servers/express.server');

describe('Express server setup', function() {
  let expressApp;
  let app;

  beforeEach(function() {
    expressApp = { use: stub(), get: stub(), set: stub() };
    app = setupExpressServer(expressApp);
  });

  it('can be initialized', function() {
    expect(app).to.equal(expressApp);
  });

  it('attaches at least all the required middlewares', function() {
    expect(app.use.callCount).to.be.at.least(8);
  });

  it('sets Jade as view engine', function() {
    expect(app.set).to.have.been.calledWith('views');
    expect(app.set).to.have.been.calledWith('view engine', 'jade');
  });
});
