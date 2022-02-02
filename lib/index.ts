import Error from '@kim5257app/js-error';
import * as jwt from 'jsonwebtoken';
import * as aes from 'aes-js';

interface Options {
  secret: string;
  key: number [];
  expiresIn: string;
}

type Token = string;

type AccessKey = string;

export default class Cert {
  private readonly secret: string; // JWT 비밀키

  private readonly key: number []; // AES CTR key

  private readonly options: jwt.SignOptions;

  constructor(options: Options) {
    this.secret = options.secret;

    this.key = options.key;

    this.options = {
      algorithm: 'HS256',
      expiresIn: options.expiresIn,
    };
  }

  public sign(id: string, info: any): AccessKey {
    try {
      const token: Token = jwt.sign(
        { id, info },
        this.secret,
        this.options
      );

      const tokenBytes = aes.utils.utf8.toBytes(token);
      const ctr = new aes.ModeOfOperation.ctr(this.key, new aes.Counter(5));
      const encryptedBytes = ctr.encrypt(tokenBytes);

      return aes.utils.hex.fromBytes(encryptedBytes);
    } catch (error) {
      throw Error.make(error);
    }
  }

  public verify(accessKey: AccessKey): { id: string, info: any } {
    try {
      const encryptBytes = aes.utils.hex.toBytes(accessKey);
      const ctr = new aes.ModeOfOperation.ctr(this.key, new aes.Counter(5));
      const decryptedBytes = ctr.decrypt(encryptBytes);

      return jwt.verify(
        aes.utils.utf8.fromBytes(decryptedBytes),
        this.secret,
        this.options,
      ) as { id: string, info: any };
    } catch (error) {
      throw Error.make(error);
    }
  }
}
