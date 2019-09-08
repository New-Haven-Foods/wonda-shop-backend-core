exports.ERROR_MSG = {
  JWT_INVALID: 'The provided JWT is invalid.',
  JWT_GENERATION_ERROR: 'Something went wrong while generating JWT token.',
  PHONE_NUMBER_OR_EMAIL_ALREADY_SIGNUP: 'The provided phone number or email is already signed up.',
  LOGIN_INFO_INCORRECT: 'The provided login information is incorrect.',
  USER_EMAIL_NOT_FOUND: 'The provided email is not found in database.',
};

exports.CORS = {
  WHITELIST: [
    'https://wonda-shop.herokuapp.com',
    'http://0.0.0.0:8088',
    'http://127.0.0.1:8088',
    'http://localhost:8088',
  ],
};
