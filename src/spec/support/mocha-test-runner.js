const chai = require('chai');
const sinon = require('sinon'); // eslint-disable-line newline-after-var
require('sinon-as-promised');
const sinonChai = require('sinon-chai');
const chaiAsPromised = require('chai-as-promised');
const chaiShallowDeepEqual = require('chai-shallow-deep-equal');

chai.use(sinonChai);
chai.use(chaiAsPromised);
chai.use(chaiShallowDeepEqual);

chai.config.includeStack = true;

// Exposes testing utility's methods to global scope.
global.expect = chai.expect;
global.spy = sinon.spy;
global.stub = sinon.stub;
global.mock = sinon.mock;
global.match = sinon.match;
