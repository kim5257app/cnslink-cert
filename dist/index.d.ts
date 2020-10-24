interface Options {
    secret: string;
    key: number[];
    expiresIn: string;
}
declare type AccessKey = string;
export default class Cert {
    private readonly secret;
    private readonly key;
    private readonly options;
    constructor(options: Options);
    sign(id: string, info: any): AccessKey;
    verify(accessKey: AccessKey): {
        id: string;
        info: any;
    };
}
export {};
