#!/usr/bin/env node

'use strict'; // eslint-disable-line strict, lines-around-directive

const storage = require('../../src/lib/storage/');
const constants = require('../../src/lib/constants/');
const Chance = require('chance');
const Promise = require('bluebird');

const { ConnectionPool, RepoFactory } = storage;
const conn = new ConnectionPool(constants.STORE.TYPES.MONGO_DB);
const repo = RepoFactory.manufacture(constants.STORE.TYPES.MONGO_DB);
const tableName = 'testPerson';
const seedDataLength = 5;
const chance = new Chance();

repo.on(conn, 'connect').then(() => {
  console.log('Connection established successfully.');
});
repo.on(conn, 'error').then(printErrorMsg);

Promise.try(() => {
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
