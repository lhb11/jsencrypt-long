import { b64tohex, hex2b64 } from "./lib/jsbn/base64";
import { JSEncryptRSAKey } from "./JSEncryptRSAKey";
import version from './version.json';

export interface IJSEncryptOptions {
    default_key_size?:string;
    default_public_exponent?:string;
    log?:boolean;
}

/**
 *
 * @param {Object} [options = {}] - An object to customize JSEncrypt behaviour
 * possible parameters are:
 * - default_key_size        {number}  default: 1024 the key size in bit
 * - default_public_exponent {string}  default: '010001' the hexadecimal representation of the public exponent
 * - log                     {boolean} default: false whether log warn/error or not
 * @constructor
 */
export class JSEncrypt {
    constructor(options:IJSEncryptOptions = {}) {
        options = options || {};
        this.default_key_size = options.default_key_size ? parseInt(options.default_key_size, 10) : 1024;
        this.default_public_exponent = options.default_public_exponent || "010001"; // 65537 default openssl public exponent for rsa key type
        this.log = options.log || false;
        // The private and public key.
        this.key = null;
    }

    private default_key_size:number;
    private default_public_exponent:string;
    private log:boolean;
    private key:JSEncryptRSAKey;
    public static version:string = version.version;

    /**
     * Method to set the rsa key parameter (one method is enough to set both the public
     * and the private key, since the private key contains the public key paramenters)
     * Log a warning if logs are enabled
     * @param {Object|string} key the pem encoded string or an object (with or without header/footer)
     * @public
     */
    public setKey(key:string) {
        if (this.log && this.key) {
            console.warn("A key was already set, overriding existing.");
        }
        this.key = new JSEncryptRSAKey(key);
    }

    /**
     * Proxy method for setKey, for api compatibility
     * @see setKey
     * @public
     */
    public setPrivateKey(privkey:string) {
        // Create the key.
        this.setKey(privkey);
    }

    /**
     * Proxy method for setKey, for api compatibility
     * @see setKey
     * @public
     */
    public setPublicKey(pubkey:string) {
        // Sets the public key.
        this.setKey(pubkey);
    }

    /**
     * Proxy method for RSAKey object's decrypt, decrypt the string using the private
     * components of the rsa key object. Note that if the object was not set will be created
     * on the fly (by the getKey method) using the parameters passed in the JSEncrypt constructor
     * @param {string} str base64 encoded crypted string to decrypt
     * @return {string} the decrypted string
     * @public
     */
    public decrypt(str:string) {
        // Return the decrypted string.
        try {
            return this.getKey().decrypt(b64tohex(str));
        } catch (ex) {
            return false;
        }
    }

    /**
     * Proxy method for RSAKey object's decrypt, decrypt the string using the private
     * components of the rsa key object. Note that if the object was not set will be created
     * on the fly (by the getKey method) using the parameters passed in the JSEncrypt constructor
     * @param {string} str base64 encoded crypted string to decrypt
     * @return {string} the decrypted string
     * @public 分段解密，支持中文
     */
    public decryptUnicodeLong(str:string) {
        const k = this.getKey();
        //解密长度=key size.hex2b64结果是每字节每两字符，所以直接*2
        const maxLength = ((k.n.bitLength()+7)>>3)*2;
        try {
            const hexString = b64tohex(str);
            const decode = decodeURIComponent(hexString)
            let decryptedString = "";
            const rexStr=".{1," + maxLength  + "}";
            const rex =new RegExp(rexStr, 'g'); 
            const subStrArray = decode.match(rex);
            if(subStrArray) {
                subStrArray.forEach(function (entry) {
                    decryptedString += k.decrypt(entry);
                });
                return decryptedString;
            }
        } catch (ex) {
            return false;
        }
    }

    public hexToBytes(hex: string) {
        for (var bytes = [], c = 0; c < hex.length; c += 2)
            bytes.push(parseInt(hex.substr(c, 2), 16));
        return bytes;
    }

    public bytesToHex(bytes: any) {
        for (var hex = [], i = 0; i < bytes.length; i++) {
            hex.push((bytes[i] >>> 4).toString(16));
            hex.push((bytes[i] & 0xF).toString(16));
        }
        return hex.join("");
    }

    public decryptLong2(strr: string) {
        var k = this.getKey();
        var MAX_DECRYPT_BLOCK = 256;
        try {
            var ct = "";
            var t1;
            var bufTmp;
            var hexTmp;
            var str = b64tohex(strr);
            var buf = this.hexToBytes(str);
            var inputLen = buf.length;
            //开始长度
            var offSet = 0;
            //结束长度
            var endOffSet = MAX_DECRYPT_BLOCK;

            //分段加密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                    bufTmp = buf.slice(offSet, endOffSet);
                    hexTmp = this.bytesToHex(bufTmp);
                    t1 = k.decrypt(hexTmp);
                    ct += t1;
                    
                } else {
                    bufTmp = buf.slice(offSet, inputLen);
                    hexTmp = this.bytesToHex(bufTmp);
                    t1 = k.decrypt(hexTmp);
                    ct += t1;
                 
                }
                offSet += MAX_DECRYPT_BLOCK;
                endOffSet += MAX_DECRYPT_BLOCK;
            }
            return ct;
        } catch (ex) {
            return false;
        }
    }

    /**
     * Returns the pem encoded representation of the public key
     * If the key doesn't exists a new key will be created
     * @returns {string} pem encoded representation of the public key WITHOUT header and footer
     * @public
     */
     public decryptLong(strr:string) {
        var k = this.getKey();
        var MAX_DECRYPT_BLOCK = 128; //分段解密最大长度限制为128字节
        try {
            var ct = "";
            var t1;
            var bufTmp;
            var hexTmp;
            var str = this.bytesToHex(strr); //这块可能有些没有必要，因为sting参数已经及转为byte数组
            var buf = this.hexToBytes(str);
            var inputLen = buf.length;
            //开始长度
            var offSet = 0;
            //结束长度
            var endOffSet = MAX_DECRYPT_BLOCK;

            //分段解密
            while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                bufTmp = buf.slice(offSet, endOffSet);
                hexTmp = this.bytesToHex(bufTmp);
                t1 = k.decrypt(hexTmp);
                ct += t1;
            //   console.log('分段' + offSet)
            //   console.log(hexTmp)
            //   console.log(t1)
            } else {
                bufTmp = buf.slice(offSet, inputLen);
                hexTmp = this.bytesToHex(bufTmp);
                t1 = k.decrypt(hexTmp);
                ct += t1;
            //   console.log('分段' + offSet)
            //   console.log(hexTmp)
            //   console.log(t1)
            }
            offSet += MAX_DECRYPT_BLOCK;
            endOffSet += MAX_DECRYPT_BLOCK;
            }
            return ct;
        } catch (ex) {
            return false;
        }
    }

    /**
     * Proxy method for RSAKey object's encrypt, encrypt the string using the public
     * components of the rsa key object. Note that if the object was not set will be created
     * on the fly (by the getKey method) using the parameters passed in the JSEncrypt constructor
     * @param {string} str the string to encrypt
     * @return {string} the encrypted string encoded in base64
     * @public
     */
    public encrypt(str:string) {
        // Return the encrypted string.
        try {
            return hex2b64(this.getKey().encrypt(str));
        } catch (ex) {
            return false;
        }
    }

    /**
     * Proxy method for RSAKey object's encrypt, encrypt the string using the public
     * components of the rsa key object. Note that if the object was not set will be created
     * on the fly (by the getKey method) using the parameters passed in the JSEncrypt constructor
     * @param {string} str the string to encrypt
     * @return {string} the encrypted string encoded in base64
     * @public 分段加密，支持中文
     */
     public encryptUnicodeLong(str:string) {
        const k = this.getKey();
        //根据key所能编码的最大长度来定分段长度。key size - 11：11字节随机padding使每次加密结果都不同。
        const maxLength = ((k.n.bitLength()+7)>>3)-11;
        try {
            let subStr="", encryptedString = "";
            let subStart = 0, subEnd=0;
            let bitLen=0, tmpPoint=0;
            for(var i = 0, len = str.length; i < len; i++){
                //js 是使用 Unicode 编码的，每个字符所占用的字节数不同
                const charCode = str.charCodeAt(i);
                if(charCode <= 0x007f) {
                    bitLen += 1;
                }else if(charCode <= 0x07ff){
                    bitLen += 2;
                }else if(charCode <= 0xffff){
                    bitLen += 3;
                }else{
                    bitLen += 4;
                }
                //字节数到达上限，获取子字符串加密并追加到总字符串后。更新下一个字符串起始位置及字节计算。
                if(bitLen>maxLength){
                    subStr=str.substring(subStart,subEnd)
                    encryptedString += k.encrypt(subStr);
                    subStart=subEnd;
                    bitLen=bitLen-tmpPoint;
                }else{
                    subEnd=i;
                    tmpPoint=bitLen;
                }
            }
            subStr=str.substring(subStart, len)
            encryptedString += k.encrypt(subStr);
            return hex2b64(encryptedString);
        } catch (ex) {
            return false;
        }
     }

    /**
     * Proxy method for RSAKey object's sign.
     * @param {string} str the string to sign
     * @param {function} digestMethod hash method
     * @param {string} digestName the name of the hash algorithm
     * @return {string} the signature encoded in base64
     * @public
     */
    public sign(str:string, digestMethod:(str:string) => string, digestName:string):string|false {
        // return the RSA signature of 'str' in 'hex' format.
        try {
            return hex2b64(this.getKey().sign(str, digestMethod, digestName));
        } catch (ex) {
            return false;
        }
    }

    /**
     * Proxy method for RSAKey object's verify.
     * @param {string} str the string to verify
     * @param {string} signature the signature encoded in base64 to compare the string to
     * @param {function} digestMethod hash method
     * @return {boolean} whether the data and signature match
     * @public
     */
    public verify(str:string, signature:string, digestMethod:(str:string) => string):boolean {
        // Return the decrypted 'digest' of the signature.
        try {
            return this.getKey().verify(str, b64tohex(signature), digestMethod);
        } catch (ex) {
            return false;
        }
    }

    /**
     * Getter for the current JSEncryptRSAKey object. If it doesn't exists a new object
     * will be created and returned
     * @param {callback} [cb] the callback to be called if we want the key to be generated
     * in an async fashion
     * @returns {JSEncryptRSAKey} the JSEncryptRSAKey object
     * @public
     */
    public getKey(cb?:() => void) {
        // Only create new if it does not exist.
        if (!this.key) {
            // Get a new private key.
            this.key = new JSEncryptRSAKey();
            if (cb && {}.toString.call(cb) === "[object Function]") {
                this.key.generateAsync(this.default_key_size, this.default_public_exponent, cb);
                return;
            }
            // Generate the key.
            this.key.generate(this.default_key_size, this.default_public_exponent);
        }
        return this.key;
    }

    /**
     * Returns the pem encoded representation of the private key
     * If the key doesn't exists a new key will be created
     * @returns {string} pem encoded representation of the private key WITH header and footer
     * @public
     */
    public getPrivateKey() {
        // Return the private representation of this key.
        return this.getKey().getPrivateKey();
    }

    /**
     * Returns the pem encoded representation of the private key
     * If the key doesn't exists a new key will be created
     * @returns {string} pem encoded representation of the private key WITHOUT header and footer
     * @public
     */
    public getPrivateKeyB64() {
        // Return the private representation of this key.
        return this.getKey().getPrivateBaseKeyB64();
    }


    /**
     * Returns the pem encoded representation of the public key
     * If the key doesn't exists a new key will be created
     * @returns {string} pem encoded representation of the public key WITH header and footer
     * @public
     */
    public getPublicKey() {
        // Return the private representation of this key.
        return this.getKey().getPublicKey();
    }

    /**
     * Returns the pem encoded representation of the public key
     * If the key doesn't exists a new key will be created
     * @returns {string} pem encoded representation of the public key WITHOUT header and footer
     * @public
     */
    public getPublicKeyB64() {
        // Return the private representation of this key.
        return this.getKey().getPublicBaseKeyB64();
    }
}
