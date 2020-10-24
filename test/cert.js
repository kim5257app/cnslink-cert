const expect = require('chai').expect;
const Cert = require('../dist').default;

describe('Sign/Verify 시험', () => {
  const config = {
    secret: '43e5a173',
    key: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6],
    expiresIn: '1y',
  };

  const cert = new Cert(config);

  it('기본 시험', () => {
    let ret = true;

    const payload = {
      id: 'test',
      info: { a: 'a', b: 'b' },
    };

    const accessKey = cert.sign(payload.id, payload.info);

    const verifyInfo = cert.verify(accessKey);

    ret = ret && (verifyInfo.id != null);
    ret = ret && ( verifyInfo.info != null && verifyInfo.info.a != null && verifyInfo.info.b != null);

    expect(ret).to.equal(true);
  });

  it('올바르지 않은 Access Key 생성', () => {

  });

  it('올바르지 않은 Access Key 인증', () => {

  });
});
