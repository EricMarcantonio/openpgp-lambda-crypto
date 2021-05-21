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
exports.handler = exports.main = exports.decryptStreamToNewStream = exports.decryptFileSym = exports.decryptSecretWithPrivate = exports.convertReadStreamToString = exports.listS3Objects = exports.getS3PassThrough = exports.getS3ReadStream = exports.getPrivateSecretByName = void 0;
const openpgp = __importStar(require("openpgp"));
const AWS = __importStar(require("aws-sdk"));
const stream_1 = __importDefault(require("stream"));
//----------AWS----------
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
//----------END----------
/**
 * Convert a stream to a string. Note, loads all data in memory. Used for small data (like private keys)
 * @param stream stream of data
 * @returns a Promise resolving to a string of data
 */
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
/**
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
/**
 * Function that decrypts a stream.Readable, and pipes plaintext data to a stream.Writable.
 * @param srcStream - the stream with the encrypted file
 * @param destStream - the destStream with the decrypted file should be piped
 * @param encSecret - the encrypted secret that will be decrypted with the private key
 * @param privateKey - the private key used to decrypt the encSecret
 */
function decryptStreamToNewStream(srcStream, destStream, encSecret, privateKey) {
    return __awaiter(this, void 0, void 0, function* () {
        const encSecretString = (yield convertReadStreamToString(encSecret));
        const secret = yield decryptSecretWithPrivate(encSecretString, privateKey);
        const decryptedData = yield decryptFileSym(srcStream, secret);
        decryptedData.data.pipe(destStream);
    });
}
exports.decryptStreamToNewStream = decryptStreamToNewStream;
/**
 * Needed to start decrypting files without loading them all into memory
 */
openpgp.config.allowUnauthenticatedStream = true;
openpgp.config.allowUnauthenticatedMessages = true;
function main(Bucket, encryptedFileName, encryptedSecretFileName, privateKeyName) {
    return __awaiter(this, void 0, void 0, function* () {
        const s3 = new AWS.S3();
        const encFile = getS3ReadStream(s3, Bucket, encryptedFileName);
        const encFileKey = getS3ReadStream(s3, Bucket, encryptedSecretFileName);
        const privateKey = (yield getPrivateSecretByName(privateKeyName));
        const { writeStream, upload } = yield getS3PassThrough(s3, Bucket, encryptedFileName.substr(0, encryptedFileName.length - 4));
        yield decryptStreamToNewStream(encFile, writeStream, encFileKey, privateKey);
        yield upload.then(function () {
            console.log("Finished Uploading");
        });
    });
}
exports.main = main;
function handler(event, context, callback) {
    return __awaiter(this, void 0, void 0, function* () {
        const Bucket = event.Records[0].s3.bucket.name;
        const filename = event.Records[0].s3.object.key;
        const s3 = new AWS.S3();
        const isKey = filename.endsWith(".key.enc");
        const objectsInBucket = yield listS3Objects(s3, Bucket);
        if (!objectsInBucket.Contents)
            callback(null, "No Objects Found ");
        else {
            for (let eachObject of objectsInBucket.Contents) {
                let targetFileName = isKey
                    ? filename.substring(0, filename.length - 8) + ".enc"
                    : filename.substring(0, filename.length - 4) + ".key.enc";
                if (eachObject.Key === targetFileName && eachObject.Key) {
                    isKey
                        ? yield main(Bucket, eachObject.Key, filename, "private-key7")
                        : yield main(Bucket, filename, eachObject.Key, "private-key7");
                    callback(null, "Found a Pair of files");
                    return;
                }
            }
            callback(null, "Pair not found");
        }
    });
}
exports.handler = handler;
