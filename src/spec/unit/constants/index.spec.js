const constants = require('../../../lib/constants/');

describe('Constants root', function() {
  context(
    'should contain all object that will be exposed to public within constants component',
    function() {
      it('including a `SYSTEM` constant object', function() {
        expect(constants.SYSTEM).to.exist;
      });

      it('including a `STORE` constant object', function() {
        expect(constants.STORE).to.exist;
      });

      it('including a `AUTH` constant object', function() {
        expect(constants.AUTH).to.exist;
      });

      it('including a `CREDENTIAL` constant object', function() {
        expect(constants.CREDENTIAL).to.exist;
      });
    }
  );
});
