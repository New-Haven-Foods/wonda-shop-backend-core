/* eslint-disable */

var Jasmine = require('jasmine'),
  JasmineReporters = require('jasmine-reporters'),
  path = require('path');

var j = new Jasmine(),
  config,
  testType = 'default',
  reporter,
  reporterType = 'default',
  len,
  args;

if (process.argv) {
  args = process.argv;
  len = args.length;

  for (var i = 0; i < len; i++) {
    switch (args[i]) {
      case '-t':
        testType = args[i + 1];
        break;

      case '-r':
        reporterType = args[i + 1];
        break;

      default:
      //do nothing
    }
  }
}

function getPath(type) {
  var paths = {
    'unit': function () {
      return process.env.UNIT_TESTS_OUT_REL || 'spec/reports';
    },
    'integration': function () {
      return process.env.INTEGRATION_TESTS_OUT_REL || 'spec/reports';
    }
  };

  if (paths[type]) {
    return paths[type]();
  } else {
    return __dirname;
  }
}

function getReporter(type, path) {
  var reporters = {
    'junit': function () {
      return new JasmineReporters.JUnitXmlReporter({
        savePath: path,
        consolidateAll: false
      });
    },
    'terminal': function () {
      return new JasmineReporters.TerminalReporter({
        verbosity: 3,
        color: true,
        showStack: true,
        consolidateAll: true
      });
    }
  };

  if (reporters[type]) {
    return reporters[type]();
  } else {
    return [new JasmineReporters.TerminalReporter({
      verbosity: 3,
      color: true,
      showStack: true,
      consolidateAll: true
    }), new JasmineReporters.JUnitXmlReporter({
      savePath: path,
      consolidateAll: false
    })];
  }
}

function getTestConfiguration(type) {
  var configs = {
    'integration': function () {
      if (process.env.NODE_ENV === 'development') {
        return path.resolve(__dirname, 'jasmine_integration_dev.json');
      }
      return path.resolve(__dirname, 'jasmine_integration.json');
    },

    'unit': function () {
      if (process.env.NODE_ENV === 'development') {
        return path.resolve(__dirname, 'jasmine_dev.json');
      }
      return path.resolve(__dirname, 'jasmine.json');
    }
  };

  if (configs[type]) {
    return configs[type]();
  } else {
    return 'dist/spec/support/jasmine.json';
  }
}

reporter = getReporter(reporterType, getPath(testType));
config = getTestConfiguration(testType);

j.loadConfigFile(config);

reporter.forEach(function (report) {
  j.addReporter(report);
});

//This line is needed to exit the process.
j.defaultReporterAdded = true;

j.execute();
