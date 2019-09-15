const MongoStore = require('../../../../lib/storage/stores/mongo.store');

describe('Mongo store', function() {
  let conn;
  let saveAsync;
  let findAsync;
  let updateAsync;
  let removeAsync;
  let dropAsync;
  let dropDatabaseAsync;
  let closeAsync;
  let onAsync;
  let collectionName;
  let mockDoc;
  let mockDoc2;

  beforeEach(function() {
    saveAsync = stub();
    findAsync = stub();
    updateAsync = stub();
    removeAsync = stub();
    dropAsync = stub();
    dropDatabaseAsync = stub();
    closeAsync = stub();
    onAsync = stub();

    conn = {
      client: {
        dropDatabaseAsync,
        closeAsync,
        onAsync,
        collection: () => ({
          saveAsync,
          findAsync,
          updateAsync,
          removeAsync,
          dropAsync,
        }),
      },
    };
    spy(conn.client, 'collection');

    collectionName = 'foo';
    mockDoc = {};
    mockDoc2 = {};
  });

  it('implements insert functionality :: insert()', function() {
    expect(MongoStore)
      .to.have.property('insert')
      .that.is.an('function');

    MongoStore.insert(conn, collectionName, mockDoc);

    expect(conn.client.collection).to.have.been.calledWith(collectionName);
    expect(saveAsync).to.have.been.calledWith(mockDoc);
  });

  it('implements select functionality :: select()', function() {
    expect(MongoStore)
      .to.have.property('select')
      .that.is.an('function');

    MongoStore.select(conn, collectionName, mockDoc);

    expect(conn.client.collection).to.have.been.calledWith(collectionName);
    expect(findAsync).to.have.been.calledWith(mockDoc);
  });

  it('implements update functionality :: update()', function() {
    expect(MongoStore)
      .to.have.property('update')
      .that.is.an('function');

    MongoStore.update(conn, collectionName, mockDoc, mockDoc2);

    expect(conn.client.collection).to.have.been.calledWith(collectionName);
    expect(updateAsync).to.have.been.calledWith(mockDoc, { $set: mockDoc2 });
  });

  it('implements delete functionality :: delete()', function() {
    expect(MongoStore)
      .to.have.property('delete')
      .that.is.an('function');

    MongoStore.delete(conn, collectionName, mockDoc);

    expect(conn.client.collection).to.have.been.calledWith(collectionName);
    expect(removeAsync).to.have.been.calledWith(mockDoc);
  });

  it('implements configuring index functionality :: configIndex() - [TODO]', function() {
    expect(MongoStore)
      .to.have.property('configIndex')
      .that.is.an('function');
  });

  it('implements drop table functionality :: dropTable()', function() {
    expect(MongoStore)
      .to.have.property('dropTable')
      .that.is.a('function');

    MongoStore.dropTable(conn, collectionName, mockDoc);

    expect(conn.client.collection).to.have.been.calledWith(collectionName);
    expect(dropAsync).to.have.been.called;
  });

  it('implements drop DB functionality :: dropDb()', function() {
    expect(MongoStore)
      .to.have.property('dropDb')
      .that.is.a('function');

    MongoStore.dropDb(conn, collectionName, mockDoc);

    expect(dropDatabaseAsync).to.have.been.called;
  });

  it('implements close connection functionality :: close()', function() {
    expect(MongoStore)
      .to.have.property('close')
      .that.is.a('function');

    MongoStore.close(conn);

    expect(closeAsync).to.have.been.called;
  });

  it('implements event handling functionality :: on()', function() {
    expect(MongoStore)
      .to.have.property('on')
      .that.is.a('function');

    const event = 'connect';

    MongoStore.on(conn, event);

    expect(onAsync).to.have.been.calledWith(event);
  });
});
