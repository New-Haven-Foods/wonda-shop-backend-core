const ValidationError = require('../utils/validation-error');
const constants = require('../constants/');

const errorHandler = (err, req, res, next) => {
  if (err instanceof ValidationError) {
    return res.status(constants.SYSTEM.HTTP_STATUS_CODES.BAD_REQUEST).send(err.message);
  }
  return res.status(constants.SYSTEM.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR).send(err.message);
};

module.exports = exports = errorHandler;
