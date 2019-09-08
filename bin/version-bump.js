#!/usr/bin/env node

'use strict'; // eslint-disable-line strict, lines-around-directive

const packageJson = require('../package.json');
const Promise = require('bluebird');
const fs = require('fs');
const childProcess = require('child_process');

Promise.promisifyAll(fs);

const newVersion = process.argv[process.argv.length - 1];
const versionRegex = /[0-9]+\.[0-9]+\.[0-9]+/g;

if (!versionRegex.test(newVersion)) {
  console.error(
    `[Version Bump Error] Provided version - ${newVersion || 'N/A'} is invalid (or missing).`
  );
  process.exit(1);
}

console.log(`[Version Bump] Updating version to ${newVersion}`);

const promises = [];
const updateFilePaths = [];

for (const filePath of updateFilePaths) {
  const promise = fs.readFileAsync(filePath, 'utf8').then(content => {
    const newContent = content.replace(versionRegex, `${newVersion}`);

    return fs.writeFileAsync(filePath, newContent);
  });

  promises.push(promise);
}

const { execSync } = childProcess;
const packageJsonFileName = 'package.json';
const newPackageJson = JSON.parse(JSON.stringify(packageJson));

newPackageJson.version = newVersion;

const newPackageJsonContent = `${JSON.stringify(newPackageJson, null, 2)}\n`;

Promise.all(promises)
  .then(() => fs.writeFileAsync(packageJsonFileName, newPackageJsonContent))
  .then(() => {
    let gitAddExecString = 'git add ';
    const gitAddFilePaths = [packageJsonFileName].concat(updateFilePaths);

    for (const filePath of gitAddFilePaths) {
      gitAddExecString += `${filePath} `;
    }

    execSync(gitAddExecString);
    execSync(`git commit -m "[System] Bump the version to ${newVersion}"`);
  })
  .then(() => {
    console.log('[Version Bump] All files containing version number are updated.');
    return process.exit(0);
  })
  .catch(err => {
    console.error(`[Version Bump Error] ${err}.`);
    return process.exit(1);
  });
