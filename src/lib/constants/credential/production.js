exports.JWT = {
  SECRET: '80026A186D8328ADF0D929DE1F5C060E5A4A217080E749722883C0366049FEEA',
  ISSUER: 'wonda-shop-backend-core.herokuapp.com',
  AUDIENCE: 'society-risk-analysis.herokuapp.com',
  EXPIRES_IN: '31 days',
  NOT_BEFORE: 0,

  COOKIE_NAME: 'jwt',
  COOKIE_HTTP_ONLY: true,
  COOKIE_SECURE: true,
  COOKIE_PATH: '/api',
  COOKIE_MAX_AGE: 31 * 24 * 60 * 60 * 1000,
  COOKIE_SIGNED: false,
};
