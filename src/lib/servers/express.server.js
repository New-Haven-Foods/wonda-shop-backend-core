const constants = require('../constants/');
const cors = require('cors');
const bodyParser = require('body-parser');
const methodOverride = require('method-override');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const favicon = require('serve-favicon');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');

// Set Node environment default to "development".
process.env.NODE_ENV = process.env.NODE_ENV || 'development';

function setupExpressServer(app) {
  app.use(
    cors({
      optionsSuccessStatus: 200, // [Note] Some legacy browsers (IE 11, some SmartTVs) choke on 204.
      origin: constants.AUTH.CORS.WHITELIST,
      credentials: true,
      maxAge: 86400,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    })
  );

  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(bodyParser.json());
  app.use(
    bodyParser.json({
      type: 'application/vnd.api+json', // Parses "application/vnd.api+json" content-type as json.
    })
  );

  app.use(methodOverride()); // Simulates DELETE and PUT methods if browser doesn't support.
  app.use(cookieParser());
  app.use(compression());
  app.use(favicon(path.resolve(__dirname, '../assets/', 'favicon.png')));

  // For an 404 error page only.
  app.set('views', path.resolve(__dirname, '../views/'));
  app.set('view engine', 'jade');

  if (app.get('env') === 'production') {
    const accessLogStream = fs.createWriteStream(
      path.resolve(__dirname, '../../../', 'morgan.log'),
      { flags: 'a' }
    );

    app.use(morgan('combined', { stream: accessLogStream }));
  } else {
    // The Node environment should be either "test" or "development".
    app.use(morgan('dev'));
  }

  return app;
}

module.exports = exports = setupExpressServer;
