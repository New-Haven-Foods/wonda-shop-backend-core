const BaseStore = require('../../../../lib/storage/stores/base');

describe('Base store', function() {
  it('implements upsert functionality :: upsert()', function() {
    expect(BaseStore)
      .to.have.property('upsert')
      .that.is.a('function');
  });
});
