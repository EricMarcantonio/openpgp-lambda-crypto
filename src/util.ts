import * as openpgp from "openpgp";
import fs from "fs";
import stream from "stream";

/**
 * @param privateKeyPath - path where the privateKey will be written
 * @param pubKeyPath - path where the publicKey will be written
 */

export async function generateKeysAndWriteToFile(privateKeyPath: string, pubKeyPath: string) {
    const { privateKeyArmored, publicKeyArmored } = await openpgp.generateKey({
        userIDs: [{ name: "person", email: "person@somebody.com" }],
    });
    fs.writeFileSync(privateKeyPath, privateKeyArmored);
    fs.writeFileSync(pubKeyPath, publicKeyArmored);
}

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

export async function encryptStreamToNewStream(
    srcStream: stream.Readable,
    destStream: stream.Writable,
    keyWriteStream: stream.Writable,
    secret: string,
    publicKey: string
) {
    let encryptedSecret = await encryptSecretWithPublic(secret, publicKey);
    keyWriteStream.write(encryptedSecret);
    const encryptedData = await encryptFileSym(srcStream, secret);
    encryptedData.pipe(destStream);
}

/**
 *
 * @param fileBuffer a stream containing the file to encrypt (i.e fs.createReadStream())
 * @param secret the secret used to symmetrically encrypt this file
 * @returns a NodeStream with the PGP encrypted payload in it
 */
export async function encryptFileSym(fileBuffer: stream.Readable, secret: string) {
    const message = await openpgp.createMessage({ binary: fileBuffer });
    return await openpgp.encrypt({
        message, // input as Message object
        passwords: secret, // multiple passwords possible
        armor: true, // don't ASCII armor (for Uint8Array output)
    });
}

/**
 *
 * @param secret - the secret you want to encrypt
 * @param publicKeyArmored - the publicKey used to encrypt that secret
 * @returns a Promise containing the encryted secret as a string
 */
export async function encryptSecretWithPublic(secret: string, publicKeyArmored: string) {
    const publicKeys = await openpgp.readKey({ armoredKey: publicKeyArmored });
    const message = await openpgp.createMessage({ text: secret });
    return await openpgp.encrypt({ message, publicKeys });
}
