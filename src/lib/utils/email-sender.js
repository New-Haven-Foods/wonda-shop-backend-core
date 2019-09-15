const nodemailer = require('nodemailer');

class EmailSender {
  constructor(senderService, senderEmail) {
    // eslint-disable-next-line max-len
    // Google API Setup URL: https://developers.google.com/oauthplayground/?code=4/AADEq_FelDR_T5qhDG_3-J0oO1fYh7J70YMSQSHU_WIlO5TFDUBqgFAIdH6UvlPxymi2CuQtdi7Br9rOD81zpbg#
    this.transporter = nodemailer.createTransport('SMTP', {
      service: senderService,
      auth: {
        XOAuth2: {
          user: senderEmail,
          clientId: '264731733927-q3g1b1dj1rgqe7q4po5k85f8i6cs862t.apps.googleusercontent.com',
          clientSecret: 'eI7kzE5GTX-LkWKDyCIep_8K',
          refreshToken: '1/ZrMXbbhUv5Z7lrJPLwEng8uzcKufaLLJiVFXk9f22Jg',
        },
      },
    });
  }

  sendMail(from, to, subject, html) {
    return new Promise((resolve, reject) => {
      this.transporter.sendMail({ from, to, subject, html }, (err, info) => {
        if (err) {
          return reject(err);
        }
        return resolve(info);
      });
    });
  }
}

module.exports = exports = EmailSender;
