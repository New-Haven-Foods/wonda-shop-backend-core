const DatabaseService = require('../services/database.service');
const EmailSender = require('../utils/email-sender');
const tryMiddlewareDecorator = require('../utils/try-middleware-decorator');
const Validator = require('../utils/precondition-validator');
const constants = require('../constants/');
const couponCode = require('coupon-code');
const jwt = require('jsonwebtoken');
const mongojs = require('mongojs');

const jwtSecret = constants.CREDENTIAL.JWT.SECRET;
const jwtIssuer = constants.CREDENTIAL.JWT.ISSUER;
const jwtAudience = constants.CREDENTIAL.JWT.AUDIENCE;
const jwtExpiresIn = constants.CREDENTIAL.JWT.EXPIRES_IN;
const jwtNotBefore = constants.CREDENTIAL.JWT.NOT_BEFORE;

const subscribe = async (req, res) => {
  const email = req.body.email && req.body.email.trim();

  Validator.shouldNotBeEmpty(email, 'email');

  const subscribeStrategy = {
    storeType: constants.STORE.TYPES.MONGO_DB,
    operation: {
      type: constants.STORE.OPERATIONS.UPSERT,
      data: [
        { email },
        {
          email,
          isUnsubscribed: false,
          systemData: {
            dateCreated: new Date(),
            createdBy: 'N/A',
            dateLastModified: null,
            lastModifiedBy: 'N/A',
          },
        },
      ],
    },
    tableName: constants.STORE.TABLE_NAMES.SUBSCRIBER,
  };

  const result = await DatabaseService.execute(subscribeStrategy);

  return res.status(constants.SYSTEM.HTTP_STATUS_CODES.CREATED).json(result);
};

const signup = async (req, res) => {
  const displayName = req.body.displayName && req.body.displayName.trim();
  const email = req.body.email && req.body.email.trim().toLowerCase();
  const password = req.body.password && req.body.password.trim();

  Validator.shouldNotBeEmpty(displayName, 'displayName');
  Validator.shouldNotBeEmpty(email, 'email');
  Validator.shouldNotBeEmpty(password, 'password');

  const signupCheckStrategy = {
    storeType: constants.STORE.TYPES.MONGO_DB,
    operation: {
      type: constants.STORE.OPERATIONS.SELECT,
      data: [
        { $or: [{ email }] },
      ],
    },
    tableName: constants.STORE.TABLE_NAMES.USER,
  };

  const results = await DatabaseService.execute(signupCheckStrategy);

  if (results.length !== 0) {
    return res
      .status(constants.SYSTEM.HTTP_STATUS_CODES.BAD_REQUEST)
      .send(constants.AUTH.ERROR_MSG.EMAIL_ALREADY_SIGNUP);
  }

  const signupStrategy = {
    storeType: constants.STORE.TYPES.MONGO_DB,
    operation: {
      type: constants.STORE.OPERATIONS.INSERT,
      data: [
        {
          displayName,
          email,
          passwordHash: password, // [TODO] Should store hashed password instead.
          membershipType: 'guest',
          address: null,
          phoneNumber: null,
          note: null,
          isSuspended: false,
          systemData: {
            dateCreated: new Date(),
            createdBy: 'N/A',
            dateLastModified: null,
            lastModifiedBy: 'N/A',
          },
        },
      ],
    },
    tableName: constants.STORE.TABLE_NAMES.USER,
  };

  const result = await DatabaseService.execute(signupStrategy);

  const user = Object.assign({}, result);

  delete user.passwordHash;
  delete user.isSuspended;
  delete user.systemData;

  const jwtPayload = Object.assign({}, user, { sub: `${user.email}:${user._id}` });
  const jwtToken = jwt.sign(jwtPayload, jwtSecret, {
    issuer: jwtIssuer,
    audience: jwtAudience,
    expiresIn: jwtExpiresIn,
    notBefore: jwtNotBefore,
  });

  res.cookie(constants.CREDENTIAL.JWT.COOKIE_NAME, jwtToken, {
    httpOnly: constants.CREDENTIAL.JWT.COOKIE_HTTP_ONLY,
    secure: constants.CREDENTIAL.JWT.COOKIE_SECURE,
    path: constants.CREDENTIAL.JWT.COOKIE_PATH,
    maxAge: constants.CREDENTIAL.JWT.COOKIE_MAX_AGE,
    signed: constants.CREDENTIAL.JWT.COOKIE_SIGNED,
  });

  return res.status(constants.SYSTEM.HTTP_STATUS_CODES.CREATED).json(user);
};

const login = async (req, res) => {
  const email = req.body.email && req.body.email.trim().toLowerCase();
  const password = req.body.password && req.body.password.trim();

  Validator.shouldNotBeEmpty(email, 'email');
  Validator.shouldNotBeEmpty(password, 'password');

  const loginStrategy = {
    storeType: constants.STORE.TYPES.MONGO_DB,
    operation: {
      type: constants.STORE.OPERATIONS.SELECT,
      data: [
        {
          $or: [{ email }],
          passwordHash: password, // [TODO] Should only verify hashed password.
          isSuspended: false,
        },
      ],
    },
    tableName: constants.STORE.TABLE_NAMES.USER,
  };

  const result = await DatabaseService.execute(loginStrategy);

  if (result.length !== 1) {
    return res
      .status(constants.SYSTEM.HTTP_STATUS_CODES.UNAUTHENTICATED)
      .send(constants.AUTH.ERROR_MSG.LOGIN_INFO_INCORRECT);
  }

  const user = Object.assign({}, result[0]);

  delete user.passwordHash;
  delete user.isSuspended;
  delete user.systemData;

  const jwtPayload = Object.assign({}, user, { sub: `${user.email}:${user._id}` });
  const jwtToken = jwt.sign(jwtPayload, jwtSecret, {
    issuer: jwtIssuer,
    audience: jwtAudience,
    expiresIn: jwtExpiresIn,
    notBefore: jwtNotBefore,
  });

  res.cookie(constants.CREDENTIAL.JWT.COOKIE_NAME, jwtToken, {
    httpOnly: constants.CREDENTIAL.JWT.COOKIE_HTTP_ONLY,
    secure: constants.CREDENTIAL.JWT.COOKIE_SECURE,
    path: constants.CREDENTIAL.JWT.COOKIE_PATH,
    maxAge: constants.CREDENTIAL.JWT.COOKIE_MAX_AGE,
    signed: constants.CREDENTIAL.JWT.COOKIE_SIGNED,
  });

  return res.status(constants.SYSTEM.HTTP_STATUS_CODES.OK).json(user);
};

const logout = (req, res) => {
  res.clearCookie(constants.CREDENTIAL.JWT.COOKIE_NAME, {
    path: constants.CREDENTIAL.JWT.COOKIE_PATH,
  });

  return res.sendStatus(constants.SYSTEM.HTTP_STATUS_CODES.NO_CONTENT);
};

const forgotPassword = async (req, res) => {
  const email = req.body.email && req.body.email.trim().toLowerCase();

  Validator.shouldNotBeEmpty(email, 'email');

  const forgotPasswordStrategy = {
    storeType: constants.STORE.TYPES.MONGO_DB,
    operation: {
      type: constants.STORE.OPERATIONS.SELECT,
      data: [{ email }],
    },
    tableName: constants.STORE.TABLE_NAMES.USER,
  };

  const results = await DatabaseService.execute(forgotPasswordStrategy);

  if (results.length !== 1) {
    return res
      .status(constants.SYSTEM.HTTP_STATUS_CODES.BAD_REQUEST)
      .send(constants.AUTH.ERROR_MSG.USER_EMAIL_NOT_FOUND);
  }

  const user = Object.assign({}, results[0]);
  const newPassword = couponCode.generate({
    parts: 1,
    partLen: 8,
  });

  // [TODO] Needs to setup Google API: https://developers.google.com/oauthplayground/?code=4/AADEq_FelDR_T5qhDG_3-J0oO1fYh7J70YMSQSHU_WIlO5TFDUBqgFAIdH6UvlPxymi2CuQtdi7Br9rOD81zpbg#
  //const emailSender = new EmailSender('Gmail', 'wonda@gmail.com');
  //const from = '"Wonda Team" <wonda@gmail.com>';
  //const to = email;
  //const subject = "How to reset your Wonda account's Password";
  //const html = `
  //  <div>
  //      <p>Dear ${user.firstName},</p>
  //      <h4>Here is your new password ${newPassword}</h4>
  //      <p>Please follow the instructions below to change back to your preferred password.</p>
  //      <ol>
  //          <li>
  //            Visit https://wonda-shop.herokuapp.com/register/login
  //          </li>
  //          <li>
  //            Enter the new password that you received in this email above and log in.
  //          </li>
  //          <li>
  //            Under Account tab in Profile section, change your password to what you would
  //            like your new password to be.
  //          </li>
  //      </ol>
  //      <br />
  //      <p>Thank you,</p>
  //      <p>Wonda Support</p>
  //   </div>
  //`;
  //const info = await emailSender.sendMail(from, to, subject, html);
  //
  //console.log('Forgot-password email message ID - %s sent: %s', info.messageId, info.response);

  const updatePasswordStrategy = {
    storeType: constants.STORE.TYPES.MONGO_DB,
    operation: {
      type: constants.STORE.OPERATIONS.UPDATE,
      data: [{ email }, { passwordHash: newPassword }],
    },
    tableName: constants.STORE.TABLE_NAMES.USER,
  };

  const result = await DatabaseService.execute(updatePasswordStrategy);

  return res.status(constants.SYSTEM.HTTP_STATUS_CODES.OK).json(result);
};

const getToken = async (req, res) => {
  try {
    const jwtPayload = Object.assign({}, req.query, {
      sub: `${req.query.email}:${req.query._id}`,
    });
    const jwtToken = jwt.sign(jwtPayload, jwtSecret, {
      issuer: jwtIssuer,
      audience: jwtAudience,
      expiresIn: jwtExpiresIn,
      notBefore: jwtNotBefore,
    });

    res.cookie(constants.CREDENTIAL.JWT.COOKIE_NAME, jwtToken, {
      httpOnly: constants.CREDENTIAL.JWT.COOKIE_HTTP_ONLY,
      secure: constants.CREDENTIAL.JWT.COOKIE_SECURE,
      path: constants.CREDENTIAL.JWT.COOKIE_PATH,
      maxAge: constants.CREDENTIAL.JWT.COOKIE_MAX_AGE,
      signed: constants.CREDENTIAL.JWT.COOKIE_SIGNED,
    });

    return res.redirect(
      constants.SYSTEM.HTTP_STATUS_CODES.PERMANENT_REDIRECT,
      req.query.callback_url || '.'
    );
  } catch (_err) {
    return res
      .status(constants.SYSTEM.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR)
      .send((_err && _err.message) || constants.AUTH.ERROR_MSG.JWT_GENERATION_ERROR);
  }
};

const getUserInfo = async (req, res) => {
  const { _id } = req.user;

  const getUserInfoStrategy = {
    storeType: constants.STORE.TYPES.MONGO_DB,
    operation: {
      type: constants.STORE.OPERATIONS.SELECT,
      data: [{ _id: mongojs.ObjectId(_id) }],
    },
    tableName: constants.STORE.TABLE_NAMES.USER,
  };

  const results = await DatabaseService.execute(getUserInfoStrategy);

  const user = Object.assign({}, results[0]);

  delete user.passwordHash;
  delete user.isSuspended;
  delete user.systemData;

  const jwtPayload = Object.assign({}, user, { sub: `${user.email}:${user._id}` });
  const jwtToken = jwt.sign(jwtPayload, jwtSecret, {
    issuer: jwtIssuer,
    audience: jwtAudience,
    expiresIn: jwtExpiresIn,
    notBefore: jwtNotBefore,
  });

  res.cookie(constants.CREDENTIAL.JWT.COOKIE_NAME, jwtToken, {
    httpOnly: constants.CREDENTIAL.JWT.COOKIE_HTTP_ONLY,
    secure: constants.CREDENTIAL.JWT.COOKIE_SECURE,
    path: constants.CREDENTIAL.JWT.COOKIE_PATH,
    maxAge: constants.CREDENTIAL.JWT.COOKIE_MAX_AGE,
    signed: constants.CREDENTIAL.JWT.COOKIE_SIGNED,
  });

  return res.status(constants.SYSTEM.HTTP_STATUS_CODES.OK).json(user);
};

const updateUserInfo = async (req, res) => {
  const { id, ...newUserInfo } = req.body;

  Validator.shouldNotBeEmpty(id, 'id');

  const updateUserInfoStrategy = {
    storeType: constants.STORE.TYPES.MONGO_DB,
    operation: {
      type: constants.STORE.OPERATIONS.UPDATE,
      data: [{ _id: mongojs.ObjectId(id) }, newUserInfo],
    },
    tableName: constants.STORE.TABLE_NAMES.USER,
  };

  const result = await DatabaseService.execute(updateUserInfoStrategy);

  return res.status(constants.SYSTEM.HTTP_STATUS_CODES.OK).json(result);
};

module.exports = exports = {
  subscribe: tryMiddlewareDecorator(subscribe),
  signup: tryMiddlewareDecorator(signup),
  login: tryMiddlewareDecorator(login),
  logout,
  forgotPassword: tryMiddlewareDecorator(forgotPassword),
  getToken: tryMiddlewareDecorator(getToken),
  getUserInfo: tryMiddlewareDecorator(getUserInfo),
  updateUserInfo: tryMiddlewareDecorator(updateUserInfo),
};
