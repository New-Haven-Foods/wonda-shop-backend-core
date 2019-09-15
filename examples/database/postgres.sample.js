#!/usr/bin/env node

'use strict'; // eslint-disable-line strict, lines-around-directive

const storage = require('../../src/lib/storage/');
const constants = require('../../src/lib/constants/');
const Sequelize = require('sequelize'); // [TODO] Should not have to require `Sequelize` npm.
const Chance = require('chance');
const Promise = require('bluebird');

const { ConnectionPool, RepoFactory } = storage;
const repo = RepoFactory.manufacture(constants.STORE.TYPES.POSTGRES);
const tableName = 'testPerson';
const schema = {
  _id: {
    type: Sequelize.INTEGER,
    primaryKey: true,
    allowNull: false,
    autoIncrement: true,
  },
  firstName: {
    type: Sequelize.STRING,
    allowNull: false,
  },
  lastName: {
    type: Sequelize.STRING,
    allowNull: false,
  },
  age: {
    type: Sequelize.INTEGER,
    allowNull: false,
  },
  underAge: {
    type: Sequelize.BOOLEAN,
    allowNull: false,
  },
};
const seedDataLength = 5;
const chance = new Chance();
let conn;

repo
  .createDb()
  .then(() => {
    conn = new ConnectionPool(constants.STORE.TYPES.POSTGRES);
  })
  .then(() => repo.createTable(conn, tableName, schema))
  .then(() => {
    const promises = [];

    for (let i = 0; i < seedDataLength; i += 1) {
      promises.push(
        repo.insert(conn, tableName, {
          firstName: chance.first(),
          lastName: chance.last(),
          age: chance.age(),
          underAge: chance.bool(),
        })
      );
    }

    return Promise.all(promises);
  })
  .then(() => repo.select(conn, tableName))
  .then(validateResult.bind(null, 'inserting'))
  .then(() => repo.update(conn, tableName, { age: { $gte: 21 } }, { underAge: false }))
  .then(() => repo.update(conn, tableName, { age: { $lt: 21 } }, { underAge: true }))
  .then(() => repo.select(conn, tableName))
  .then(validateResult.bind(null, 'updating'))
  .then(() => repo.delete(conn, tableName, { age: { $lt: 21 } }))
  .then(() => repo.select(conn, tableName))
  .then(validateResult.bind(null, 'deleting'))
  .then(() => repo.dropTable(conn, tableName))
  .then(() => repo.dropDb(conn))
  .then(() => repo.close(conn))
  .catch(printErrorMsg);

function validateResult(type, rows) {
  console.log(`Validate ${type} result - ${JSON.stringify(rows, null, 2)}.`);
}
function printErrorMsg(err) {
  console.log(`Something breaks - ${JSON.stringify(err, null, 2)}.`);
}
