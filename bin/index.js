"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.handler = exports.main = exports.listS3Objects = exports.getS3PassThrough = exports.getS3ReadStream = exports.convertReadStreamToString = exports.decryptStreamToNewStream = exports.encryptStreamToNewStream = exports.getPrivateSecretByName = exports.decryptFileSym = exports.encryptFileSym = exports.decryptSecretWithPrivate = exports.encryptSecretWithPublic = void 0;
const openpgp = __importStar(require("openpgp"));
const AWS = __importStar(require("aws-sdk"));
const stream_1 = __importDefault(require("stream"));
/**
 *
 * Author: Eric Marcantonio
 *
 * There is also code in here needed to generate keys, store value and simulate a s3.
 * This will change once loading an encrypted file does not break
 *
 * Next steps:
 * 1. Pull from s3
 * 2. remove the locally sourced secret lookup, and pass it real test data
 */
/**
 *
 * @param secret - the secret you want to encrypt
 * @param publicKeyArmored - the publicKey used to encrypt that secret
 * @returns a Promise containing the encryted secret as a string
 */
function encryptSecretWithPublic(secret, publicKeyArmored) {
    return __awaiter(this, void 0, void 0, function* () {
        const publicKeys = yield openpgp.readKey({ armoredKey: publicKeyArmored });
        const message = yield openpgp.createMessage({ text: secret });
        return yield openpgp.encrypt({ message, publicKeys });
    });
}
exports.encryptSecretWithPublic = encryptSecretWithPublic;
/**
 *
 * @param encryptedSecret - a string containing the encrypted secret
 * @param privateKeyArmored - the private key used to decrypt the file
 * @returns - the original secret as a string
 */
function decryptSecretWithPrivate(encryptedSecret, privateKeyArmored) {
    return __awaiter(this, void 0, void 0, function* () {
        encryptedSecret = encryptedSecret.replace("/\r/", "");
        const privateKeys = yield openpgp.readKey({
            armoredKey: privateKeyArmored,
        });
        const message = yield openpgp.readMessage({
            armoredMessage: encryptedSecret,
        });
        const data = yield openpgp.decrypt({
            message,
            privateKeys,
        });
        return data.data;
    });
}
exports.decryptSecretWithPrivate = decryptSecretWithPrivate;
/**
 *
 * @param fileBuffer a stream containing the file to encrypt (i.e fs.createReadStream())
 * @param secret the secret used to symmetrically encrypt this file
 * @returns a NodeStream with the PGP encrypted payload in it
 */
function encryptFileSym(fileBuffer, secret) {
    return __awaiter(this, void 0, void 0, function* () {
        const message = yield openpgp.createMessage({ binary: fileBuffer });
        return yield openpgp.encrypt({
            message,
            passwords: secret,
            armor: true, // don't ASCII armor (for Uint8Array output)
        });
    });
}
exports.encryptFileSym = encryptFileSym;
/**
 *
 * @param fileBuffer - a stream containing the file to decrypt (i.e fs.createReadStream())
 * @param secret - the secret used to decrypt the file
 * @returns a NodeStream with the orginal file in it
 */
function decryptFileSym(fileBuffer, secret) {
    return __awaiter(this, void 0, void 0, function* () {
        const message = yield openpgp.readMessage({ armoredMessage: fileBuffer });
        return yield openpgp.decrypt({
            message,
            passwords: secret,
            format: "binary",
        });
    });
}
exports.decryptFileSym = decryptFileSym;
openpgp.config.allowUnauthenticatedStream = true;
openpgp.config.allowUnauthenticatedMessages = true;
function getPrivateSecretByName(secretName) {
    return __awaiter(this, void 0, void 0, function* () {
        var region = "ca-central-1";
        var client = new AWS.SecretsManager({
            region: region,
        });
        let awsBinaryData;
        return new Promise(function (resolve, reject) {
            client.getSecretValue({ SecretId: secretName }, function (err, data) {
                if (err)
                    reject(err.code);
                else {
                    //@ts-ignore
                    awsBinaryData = Buffer.from(data.SecretBinary, "base64");
                    let types = Buffer.from(awsBinaryData).toString("ascii");
                    resolve(types);
                }
            });
        });
    });
}
exports.getPrivateSecretByName = getPrivateSecretByName;
function encryptStreamToNewStream(srcStream, destStream, keyWriteStream, secret, publicKey) {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise(function (resolve, reject) {
            return __awaiter(this, void 0, void 0, function* () {
                let encryptedSecret = yield encryptSecretWithPublic(secret, publicKey);
                keyWriteStream.write(encryptedSecret);
                keyWriteStream.on("finish", function () {
                    return __awaiter(this, void 0, void 0, function* () {
                        //@ts-ignore
                        const encryptedData = yield encryptFileSym(srcStream, secret);
                        encryptedData.pipe(destStream);
                        destStream.on("finish", () => {
                            console.log("Done");
                            resolve();
                        });
                        destStream.on("error", (err) => {
                            console.log(err);
                            reject(err);
                        });
                    });
                });
                keyWriteStream.on("error", (err) => {
                    console.log(err);
                    reject(err);
                });
            });
        });
    });
}
exports.encryptStreamToNewStream = encryptStreamToNewStream;
function decryptStreamToNewStream(srcStream, destStream, encSecret, privateKey) {
    return __awaiter(this, void 0, void 0, function* () {
        const secret = yield decryptSecretWithPrivate(encSecret, privateKey);
        const decryptedData = yield decryptFileSym(srcStream, secret);
        decryptedData.data.pipe(destStream);
    });
}
exports.decryptStreamToNewStream = decryptStreamToNewStream;
function convertReadStreamToString(stream) {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise(function (resolve, reject) {
            let bytes = "";
            stream.on("data", function (data) {
                bytes += data;
            });
            stream.on("end", function () {
                resolve(bytes);
            });
            stream.on("error", function (err) {
                reject(err);
            });
        });
    });
}
exports.convertReadStreamToString = convertReadStreamToString;
function getS3ReadStream(s3, Bucket, Key) {
    return s3.getObject({ Bucket, Key }).createReadStream().setEncoding("utf-8");
}
exports.getS3ReadStream = getS3ReadStream;
function getS3PassThrough(s3, Bucket, Key) {
    const pass = new stream_1.default.PassThrough();
    return {
        writeStream: pass,
        upload: s3.upload({ Bucket, Key, Body: pass }).promise(),
    };
}
exports.getS3PassThrough = getS3PassThrough;
function listS3Objects(s3, Bucket) {
    return __awaiter(this, void 0, void 0, function* () {
        return s3.listObjects({ Bucket }).promise();
    });
}
exports.listS3Objects = listS3Objects;
function main(Bucket, encryptedFileName, encryptedSecretFileName, privateKeyName) {
    return __awaiter(this, void 0, void 0, function* () {
        const s3 = new AWS.S3();
        const encFile = getS3ReadStream(s3, Bucket, encryptedFileName);
        const encFileKey = getS3ReadStream(s3, Bucket, encryptedSecretFileName);
        const privateKey = (yield getPrivateSecretByName(privateKeyName));
        convertReadStreamToString(encFileKey).then(function (encKeyBytes) {
            return __awaiter(this, void 0, void 0, function* () {
                const { writeStream, upload } = getS3PassThrough(s3, Bucket, encryptedFileName.substr(encryptedFileName.indexOf("/"), encryptedFileName.length - 4));
                yield decryptStreamToNewStream(encFile, writeStream, encKeyBytes, privateKey);
                upload.then(function () {
                    s3.deleteObject({ Bucket, Key: encryptedFileName });
                    s3.deleteObject({ Bucket, Key: encryptedSecretFileName });
                });
            });
        });
    });
}
exports.main = main;
function handler(event, context, callback) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log(event);
        const Bucket = event.Records[0].s3.bucket.name;
        const filename = decodeURIComponent(event.Records[0].s3.object.key.replace(/\+/g, " "));
        const s3 = new AWS.S3();
        if (filename.endsWith(".enc")) {
            const isKey = filename.endsWith(".key.enc");
            listS3Objects(s3, Bucket).then(function (res) {
                var _a, _b, _c, _d;
                return __awaiter(this, void 0, void 0, function* () {
                    if (res.Contents) {
                        for (let eachObject of res.Contents) {
                            if (isKey) {
                                let targetFileName = (_a = eachObject.Key) === null || _a === void 0 ? void 0 : _a.substring(0, ((_b = eachObject.Key) === null || _b === void 0 ? void 0 : _b.length) - 4);
                                //we need to find the file with it. It might not be there
                                if (eachObject.Key === targetFileName && eachObject.Key) {
                                    yield main(Bucket, eachObject.Key, filename, "private-key7");
                                    callback("Found a Pair of files");
                                    break;
                                }
                            }
                            else {
                                //is a file. We need to find the key
                                let targetFileName = (_c = eachObject.Key) === null || _c === void 0 ? void 0 : _c.substring(0, ((_d = eachObject.Key) === null || _d === void 0 ? void 0 : _d.length) - 8);
                                targetFileName = targetFileName + ".enc";
                                if (eachObject.Key === targetFileName && eachObject.Key) {
                                    yield main(Bucket, filename, eachObject.Key, "private-key7");
                                    callback("Found a Pair of files");
                                    break;
                                }
                            }
                            callback("Waiting for the other file to be added");
                        }
                    }
                });
            });
        }
        else {
            console.log;
            callback(null, "Decryption Upload");
        }
    });
}
exports.handler = handler;
function testWithoutTrigger() {
    return __awaiter(this, void 0, void 0, function* () {
        const s3 = new AWS.S3();
        const Bucket = "ericmarcantoniobucket";
        const encFile = getS3ReadStream(s3, Bucket, "encryptedFiles/ChromeSetup.exe.enc");
        const encFileKey = getS3ReadStream(s3, Bucket, "encryptedFiles/ChromeSetup.exe.key.enc");
        const privateKey = (yield getPrivateSecretByName("private-key7"));
        convertReadStreamToString(encFileKey).then(function (encKeyBytes) {
            return __awaiter(this, void 0, void 0, function* () {
                const { writeStream, upload } = getS3PassThrough(s3, Bucket, "decryptedFiles/ChromeSetup.exe");
                yield decryptStreamToNewStream(encFile, writeStream, encKeyBytes, privateKey);
                upload.then(function () {
                    s3.deleteObject({ Bucket, Key: "encryptedFiles/ChromeSetup.exe.enc" });
                    s3.deleteObject({ Bucket, Key: "encryptedFiles/ChromeSetup.exe.key.enc" });
                });
            });
        });
    });
}
testWithoutTrigger();
