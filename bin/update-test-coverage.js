#!/usr/bin/env node

'use strict'; // eslint-disable-line strict, lines-around-directive

const packageJson = require('../package.json');
const childProcess = require('child_process');
const fs = require('fs');

const { exec, execSync } = childProcess;
const order = ['statements', 'branches', 'functions', 'lines'];

console.log('[Coverage Update] Updating threshold(s) for test coverage.');

// eslint-disable-next-line consistent-return
exec('npm run-script coverage:report', (error, stdOut, stdErr) => {
  if (error) {
    console.error(`[Coverage Update Error] ${stdErr}.`);
    return process.exit(1);
  }

  let changed = false;

  stdOut
    .split('\n')
    .filter(line => line.includes('All files'))
    .map(line => line.match(/([0-9]+(\.)*[0-9]*)/g))
    .reduce(() => null)
    .map(i => Number(i))
    .forEach((cov, i) => {
      if (cov > packageJson.nyc[order[i]]) {
        packageJson.nyc[order[i]] = cov;
        changed = true;
      }
    });

  if (changed) {
    fs.writeFile('package.json', JSON.stringify(packageJson, null, 2), err => {
      if (err) {
        console.error(`[Coverage Update Error] ${err}.`);
        return process.exit(1);
      }

      execSync('git add package.json');
      execSync('git commit -m "[System] Update each threshold for test coverage"');

      console.log('[Coverage Update] Each threshold is updated for test coverage.');
      return process.exit(0);
    });
  } else {
    console.log('[Coverage Update] No threshold is updated for test coverage.');
    return process.exit(0);
  }
});
