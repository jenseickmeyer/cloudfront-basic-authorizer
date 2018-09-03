'use strict';

const crypto = require('crypto');

const UnauthorizedResponse = {
  status: '401',
  headers: {
    'www-authenticate': [{
      key: 'WWW-Authenticate',
      value: 'Basic realm="Secure Area"'
    }]
  }
};

exports.handler = async (event) => {
  const request = event.Records[0].cf.request;

  if (request.headers.authorization === undefined) {
    return UnauthorizedResponse;
  }

  const authorizationToken = request.headers.authorization[0].value;

  const credentials = decodeAuthToken(authorizationToken);
  if (credentials === null) {
    return UnauthorizedResponse;
  }

  const config = this.loadConfiguration();

  const username = credentials.username;
  const passwordHash = hashedPassword(credentials.password, config.password_salt);

  if (username !== config.username || passwordHash !== config.password_hash) {
    return UnauthorizedResponse;
  }

  return request;
};

function decodeAuthToken (authToken) {
  if (!authToken.startsWith('Basic ')) {
    console.log('Wrong header value: ' + authToken);
    return null;
  }

  var parts = Buffer.from(authToken.substring(6), 'base64').toString().split(':');

  if (parts.length !== 2) {
    console.log('Wrong format: Expected 2 parts but found ' + parts.length);
    return null;
  }

  return {
    username: parts[0],
    password: parts[1]
  };
}

function hashedPassword (password, salt) {
  const hash = crypto.createHash('sha256');
  hash.update(password + salt);
  return hash.digest('hex');
}

exports.loadConfiguration = () => {
  return require('./config.json');
};
