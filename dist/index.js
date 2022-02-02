"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const js_error_1 = require("@kim5257app/js-error");
const jwt = require("jsonwebtoken");
const aes = require("aes-js");
class Cert {
    constructor(options) {
        this.secret = options.secret;
        this.key = options.key;
        this.options = {
            algorithm: 'HS256',
            expiresIn: options.expiresIn,
        };
    }
    sign(id, info) {
        try {
            const token = jwt.sign({ id, info }, this.secret, this.options);
            const tokenBytes = aes.utils.utf8.toBytes(token);
            const ctr = new aes.ModeOfOperation.ctr(this.key, new aes.Counter(5));
            const encryptedBytes = ctr.encrypt(tokenBytes);
            return aes.utils.hex.fromBytes(encryptedBytes);
        }
        catch (error) {
            throw js_error_1.default.make(error);
        }
    }
    verify(accessKey) {
        try {
            const encryptBytes = aes.utils.hex.toBytes(accessKey);
            const ctr = new aes.ModeOfOperation.ctr(this.key, new aes.Counter(5));
            const decryptedBytes = ctr.decrypt(encryptBytes);
            return jwt.verify(aes.utils.utf8.fromBytes(decryptedBytes), this.secret, this.options);
        }
        catch (error) {
            throw js_error_1.default.make(error);
        }
    }
}
exports.default = Cert;
