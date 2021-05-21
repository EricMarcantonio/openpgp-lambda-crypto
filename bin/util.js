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
exports.encryptSecretWithPublic = exports.encryptFileSym = exports.encryptStreamToNewStream = exports.generateKeysAndWriteToFile = void 0;
const openpgp = __importStar(require("openpgp"));
const fs_1 = __importDefault(require("fs"));
/**
 * @param privateKeyPath - path where the privateKey will be written
 * @param pubKeyPath - path where the publicKey will be written
 */
function generateKeysAndWriteToFile(privateKeyPath, pubKeyPath) {
    return __awaiter(this, void 0, void 0, function* () {
        const { privateKeyArmored, publicKeyArmored } = yield openpgp.generateKey({
            userIDs: [{ name: "person", email: "person@somebody.com" }],
        });
        fs_1.default.writeFileSync(privateKeyPath, privateKeyArmored);
        fs_1.default.writeFileSync(pubKeyPath, publicKeyArmored);
    });
}
exports.generateKeysAndWriteToFile = generateKeysAndWriteToFile;
/**
 * Function that takes a unencrypted stream, secret (string). Encrypts the srcStream with the secret, and pipes that to the destStream.
 * Encrypts the secret with the public key and writes that keyWriteStream
 * and
 * @param srcStream - raw file stream that you want to encrypt.
 * @param destStream - encryted file stream
 * @param keyWriteStream - the key that is encrypted with the public key
 * @param secret - the secret needed to encrypt the file
 * @param publicKey - the public key used to encrypt the secret
 */
function encryptStreamToNewStream(srcStream, destStream, keyWriteStream, secret, publicKey) {
    return __awaiter(this, void 0, void 0, function* () {
        let encryptedSecret = yield encryptSecretWithPublic(secret, publicKey);
        keyWriteStream.write(encryptedSecret);
        const encryptedData = yield encryptFileSym(srcStream, secret);
        encryptedData.pipe(destStream);
    });
}
exports.encryptStreamToNewStream = encryptStreamToNewStream;
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
