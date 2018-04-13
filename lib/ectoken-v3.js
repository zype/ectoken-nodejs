'use strict';

const buffer = require('buffer');
const crypto = require('crypto');

// constants
const IV_SIZE = 12;
const TAG_SIZE = 16;

/**
 * Determines if a string is alphanumeric
 * @param  {String} str
 * @return {Boolean}
 */
function isAlphanumeric(str) {
  return !/[^0-9a-z\xDF-\xFF]/.test(str.toLowerCase());
}

/**
 * base64 encodes and replaces characters just like urlsafe_b64encode
 * @param  {Buffer} buffer
 * @return {String}
 */
function encode(buffer) {
  // ghetto fabulous
  let encoded = encodeURI(buffer.toString('base64'));
  encoded = encoded.split('=').join('');
  encoded = encoded.split('+').join('-');
  encoded = encoded.split('/').join('_');

  return encoded;
}

/**
 * base64 decodes and re-replaces cbaracters just like urlsafe_b64decode
 * @param  {String} token
 * @return {Buffer}
 */
function decode(token) {
  let decoded = decodeURI(token);
  decoded = decoded.split('-').join('+');
  decoded = decoded.split('_').join('/');
  switch (decoded % 4) {
    case 2:
      decoded += '==';
      break;
    case 3:
      decoded += '=';
      break;
  }

  return new Buffer(decoded, 'base64');
}


/**
 * Generates an encrypted authentication token [version 3]
 * @param  {String}  key
 * @param  {String}  params
 * @param  {Boolean} verbose
 * @return {String}
 */
exports.encrypt = function(key, params, verbose) {
  // verify input
  if (!key || !params) {
    throw new Error('key and params are required');
  }

  // validate key is alphanumeric
  if (!isAlphanumeric(key)) {
    throw new Error('key must be alphanumeric');
  }

  // create iv
  const iv = crypto.randomBytes(IV_SIZE);

  // sha256 hash key
  const hash = crypto.createHash('sha256').update(key).digest();

    // create cipher
  const cipher = crypto.createCipheriv('aes-256-gcm', hash, iv);

  // encrypt the params
  const cipherText = Buffer.concat([cipher.update(params, 'utf8'), cipher.final()]);

  // create tag
  const tag = cipher.getAuthTag();

  // create token (iv + encypted + tag)
  const token = Buffer.concat([iv, cipherText, tag]);

  // debug output
  if (verbose) {
    console.log('+-------------------------------------------------------------');
    console.log('| iv:                %s', iv.toString('hex'));
    console.log('| cipherText:        %s', cipherText.toString('hex'));
    console.log('| tag:               %s', tag.toString('hex'));
    console.log('+-------------------------------------------------------------');
    console.log('| token:             %s', token.toString('hex'));
    console.log('+-------------------------------------------------------------');
  }

  return encode(token);
}

/**
 * Decrypts an authentication token [version 3]
 * @param  {String}  key
 * @param  {String}  token
 * @param  {Boolean} verbose
 * @return {String}
 */
exports.decrypt = function(key, token, verbose) {
  // verify input
  if (!key || !token) {
    throw new Error('key and token are required');
  }

  // sha256 hash key
  const hash = crypto.createHash('sha256').update(key).digest();

  // decode token
  const decodedToken = decode(token);

  // convert token to buffer
  const buffer = new Buffer(decodedToken, 'base64');

  // parse iv
  const iv = buffer.slice(0, IV_SIZE);

  // parse cipherText
  const cipherLength = (buffer.length - TAG_SIZE);
  const cipherText = buffer.slice(IV_SIZE, cipherLength);

  // parse tag
  const tag = buffer.slice(cipherLength, buffer.length);

  // decrypt the params
  const decipher = crypto.createDecipheriv('aes-256-gcm', hash, iv);
  decipher.setAuthTag(tag);
  const params = decipher.update(cipherText, 'binary') + decipher.final('utf8');

  // debug output
  if (verbose) {
    console.log('+-------------------------------------------------------------');
    console.log('| iv:                %s', iv.toString('hex'));
    console.log('| cipherText:        %s', cipherText.toString('hex'));
    console.log('| tag:               %s', tag.toString('hex'));
    console.log('+-------------------------------------------------------------');
    console.log('| params:            %s', params.toString('hex'));
    console.log('+-------------------------------------------------------------');
  }

  return params;
}
