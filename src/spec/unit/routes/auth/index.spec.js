const authRouter = require('../../../../lib/routes/auth/');

describe('Auth router', function() {
  it('should have all the endpoints registered', function() {
    const routes = [];

    authRouter.stack.forEach(r => {
      if (r.route && r.route.path) {
        routes.push(r.route.path);
      }
    });

    expect(routes).to.include('/signup');
    expect(routes).to.include('/login');
  });
});
