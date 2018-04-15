'use strict';

const chai = require('chai');
const expect = chai.expect;
const stdMocks = require('std-mocks');
const ectoken = require('../index').V3;

describe('ECToken V3', function(){
  const key = 'GF8PHCp3xy5ypSaJKmPMH2M4';
  const params = 'ec_expire=1257642471&ec_clientip=11.22.33.1'
  let token;

  it('should successfully create a V3 token', function() {
    token = ectoken.encrypt(key, params);
  });

  it('should successfully decrypt the V3 token', function() {
    const result = ectoken.decrypt(key, token);
    expect(result).to.equal(params);
  });

  it('should successfully decrypt the V3 token created from the customer portal', function() {
    const result = ectoken.decrypt(key, 'yfuuiWuy8LMiNR1Au3b9-LSNln-X5W-enqvNBlhlpwQspOoLlMX4fIecVLTQJTLMGET14FtLxmp8U6zaDSq5eD-gYMHz9V0');
    expect(result).to.equal(params);
  });

  it('should successfully create a V3 token (verbose = true)', function() {
    stdMocks.use();
    token = ectoken.encrypt(key, params, true);
    stdMocks.restore();
    const output = stdMocks.flush();
    expect(output.stdout.length).to.equal(7);
  });

  it('should successfully decrypt the V3 token (verbose = true)', function() {
    stdMocks.use();
    const result = ectoken.decrypt(key, token, true);
    expect(result).to.equal(params);
    stdMocks.restore();
    const output = stdMocks.flush();
    expect(output.stdout.length).to.equal(7);
  });

  it('should fail to create a V3 token when the key is not alphanumeric', function() {
      try {
        ectoken.encrypt('_' + key, params);
      }
      catch(e) {
        expect(e.message).to.equal('ValidationError: child "key" fails because ["key" must only contain alpha-numeric characters]');
      }
  });

  it('should fail to create a V3 token when the key is missing', function() {
      try {
        ectoken.encrypt(undefined, params);
      }
      catch(e) {
        expect(e.message).to.equal('ValidationError: child "key" fails because ["key" is required]');
      }
  });

  it('should fail to create a V3 token when the params is missing', function() {
      try {
        ectoken.encrypt(key);
      }
      catch(e) {
        expect(e.message).to.equal('ValidationError: child "params" fails because ["params" is required]');
      }
  });

  it('should fail to decrypt the V3 token when the key is not alphanumeric', function() {
      try {
        ectoken.decrypt('_' + key, params);
      }
      catch(e) {
        expect(e.message).to.equal('ValidationError: child "key" fails because ["key" must only contain alpha-numeric characters]');
      }
  });

  it('should fail to decrypt the V3 token when the key is missing', function() {
      try {
        ectoken.decrypt(undefined, token);
      }
      catch(e) {
        expect(e.message).to.equal('ValidationError: child "key" fails because ["key" is required]');
      }
  });

  it('should fail to decrypt a V3 token when the token is missing', function() {
      try {
        ectoken.decrypt(key);
      }
      catch(e) {
        expect(e.message).to.equal('ValidationError: child "token" fails because ["token" is required]');
      }
  });
});