'use strict';

const app = require('../../index.js');
const chai = require('chai');
const sinon = require('sinon');
const expect = chai.expect;

describe('Authorization tests', () => {
  it('verifies missing Authorization header', async () => {
    let event = {
      Records: [
        {
          cf: {
            request: {
              headers: {}
            }
          }
        }
      ]
    };

    const response = await app.handler(event);
    expect(response).to.be.an('object');
    expect(response.status).to.equal('401');
    expect(response.headers).to.be.an('object');
    expect(response.headers['www-authenticate'][0].key).to.equal('WWW-Authenticate');
  });

  it('verifies invalid authentication token', async () => {
    let event = {
      Records: [
        {
          cf: {
            request: {
              headers: {
                authorization: [
                  {
                    value: 'test1234'
                  }
                ]
              }
            }
          }
        }
      ]
    };

    let response = await app.handler(event);
    expect(response).to.be.an('object');
    expect(response.status).to.equal('401');
    expect(response.headers).to.be.an('object');
    expect(response.headers['www-authenticate'][0].key).to.equal('WWW-Authenticate');

    event = {
      Records: [
        {
          cf: {
            request: {
              headers: {
                authorization: [
                  {
                    value: 'Basic test1234'
                  }
                ]
              }
            }
          }
        }
      ]
    };

    response = await app.handler(event);
    expect(response).to.be.an('object');
    expect(response.status).to.equal('401');
    expect(response.headers).to.be.an('object');
    expect(response.headers['www-authenticate'][0].key).to.equal('WWW-Authenticate');
  });

  it('verifies invalid credentials', async () => {
    let event = {
      Records: [
        {
          cf: {
            request: {
              headers: {
                authorization: [
                  {
                    value: 'Basic YWxpY2U6Ym9i'
                  }
                ]
              }
            }
          }
        }
      ]
    };

    let loadConfigurationStub = sinon.stub(app, 'loadConfiguration').callsFake(() => {
      return {
        username: 'foo',
        password_hash: '3eb1d0426280814e22932efd6717812dada0b83925ceffcbf4c24d5370da31e4',
        password_salt: '1234'
      };
    });

    let response = await app.handler(event);
    expect(response).to.be.an('object');
    expect(response.status).to.equal('401');
    expect(response.headers).to.be.an('object');
    expect(response.headers['www-authenticate'][0].key).to.equal('WWW-Authenticate');

    loadConfigurationStub.restore();
  });

  it('verifies valid credentials', async () => {
    let event = {
      Records: [
        {
          cf: {
            request: {
              headers: {
                authorization: [
                  {
                    value: 'Basic YWxpY2U6Ym9i'
                  }
                ]
              }
            }
          }
        }
      ]
    };

    let loadConfigurationStub = sinon.stub(app, 'loadConfiguration').callsFake(() => {
      return {
        username: 'alice',
        password_hash: '550c7a6d0859d0773541dd478bd49214188b9358549d3519ea542442f86e079c',
        password_salt: '1234'
      };
    });

    let response = await app.handler(event);
    expect(response).to.be.an('object');
    expect(response).to.deep.equal({
      headers: {
        authorization: [
          {
            value: 'Basic YWxpY2U6Ym9i'
          }
        ]
      }
    });

    loadConfigurationStub.restore();
  });
});
