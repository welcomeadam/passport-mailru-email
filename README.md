# passport-mailru-email

[Passport](http://passportjs.org/) strategy for authenticating form E-mail with [Mail.ru](http://mail.ru/)
using the OAuth 2.0 API.

## Create app
[Create an application](https://oauth.mail.ru/app/) and get clientID and clientSecret

## Install

    $ npm install passport-mailru-email

## Usage

```js
passport.use(new MailruStrategy({
    clientID: MAIL_APP_ID,
    clientSecret: MAIL_APP_SECRET,
    state: SERCRET_RANDOM_STRING,
    callbackURL: "http://localhost:3000/auth/mailru/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ mailId: profile.client_id }, function (err, user) {
      return cb(err, user);
    });
  }
));
```