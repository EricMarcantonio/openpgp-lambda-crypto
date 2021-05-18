import * as openpgp from "openpgp";
import * as AWS from "aws-sdk";
import stream from "stream";
import * as fs from "fs";
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
export async function encryptSecretWithPublic(secret: string, publicKeyArmored: string) {
    const publicKeys = await openpgp.readKey({ armoredKey: publicKeyArmored });
    const message = await openpgp.createMessage({ text: secret });
    return await openpgp.encrypt({ message, publicKeys });
}

/**
 *
 * @param encryptedSecret - a string containing the encrypted secret
 * @param privateKeyArmored - the private key used to decrypt the file
 * @returns - the original secret as a string
 */
export async function decryptSecretWithPrivate(encryptedSecret: string, privateKeyArmored: string) {
    encryptedSecret = encryptedSecret.replace("/\r/", "");
    const privateKeys = await openpgp.readKey({
        armoredKey: privateKeyArmored,
    });
    const message = await openpgp.readMessage({
        armoredMessage: encryptedSecret,
    });
    const data = await openpgp.decrypt({
        message,
        privateKeys,
    });
    return data.data;
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
 * @param fileBuffer - a stream containing the file to decrypt (i.e fs.createReadStream())
 * @param secret - the secret used to decrypt the file
 * @returns a NodeStream with the orginal file in it
 */
export async function decryptFileSym(fileBuffer: stream.Readable, secret: string) {
    const message = await openpgp.readMessage({ armoredMessage: fileBuffer });
    return await openpgp.decrypt({
        message,
        passwords: secret,
        format: "binary",
    });
}

openpgp.config.allowUnauthenticatedStream = true;
openpgp.config.allowUnauthenticatedMessages = true;

export async function getPrivateSecretByName(secretName: string) {
    var region = "ca-central-1";
    var client = new AWS.SecretsManager({
        region: region,
    });
    let awsBinaryData;
    return new Promise(function (resolve, reject) {
        client.getSecretValue({ SecretId: secretName }, function (err, data) {
            if (err) reject(err.code);
            else {
                //@ts-ignore
                awsBinaryData = Buffer.from(data.SecretBinary, "base64");
                let types = Buffer.from(awsBinaryData).toString("ascii");
                resolve(types);
            }
        });
    });
}

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

export async function decryptStreamToNewStream(
    srcStream: stream.Readable,
    destStream: stream.Writable,
    encSecret: string,
    privateKey: string
) {
    const secret = await decryptSecretWithPrivate(encSecret, privateKey);
    const decryptedData = await decryptFileSym(srcStream, secret);
    decryptedData.data.pipe(destStream);
}

export async function convertReadStreamToString(stream: stream.Readable) {
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
}

export function getS3ReadStream(s3: AWS.S3, Bucket: string, Key: string) {
    return s3.getObject({ Bucket, Key }).createReadStream().setEncoding("utf-8");
}

export function getS3PassThrough(s3: AWS.S3, Bucket: string, Key: string) {
    const pass = new stream.PassThrough();
    return {
        writeStream: pass,
        upload: s3.upload({ Bucket, Key, Body: pass }).promise(),
    };
}

export async function listS3Objects(s3: AWS.S3, Bucket: string) {
    return s3.listObjects({ Bucket }).promise();
}

export async function main(
    Bucket: string,
    encryptedFileName: string,
    encryptedSecretFileName: string,
    privateKeyName: string
) {
    const s3 = new AWS.S3();
    const encFile = getS3ReadStream(s3, Bucket, encryptedFileName);
    const encFileKey = getS3ReadStream(s3, Bucket, encryptedSecretFileName);
    const privateKey = (await getPrivateSecretByName(privateKeyName)) as string;

    convertReadStreamToString(encFileKey).then(async function (encKeyBytes) {
        const { writeStream, upload } = getS3PassThrough(
            s3,
            Bucket,
            encryptedFileName.substr(encryptedFileName.indexOf("/"), encryptedFileName.length - 4)
        );
        await decryptStreamToNewStream(encFile, writeStream, encKeyBytes as string, privateKey);
        upload.then(function () {
            s3.deleteObject({ Bucket, Key: encryptedFileName });
            s3.deleteObject({ Bucket, Key: encryptedSecretFileName });
        });
    });
}

export async function handler(event: any, context: any, callback: any) {
    console.log(event);
    const Bucket = event.Records[0].s3.bucket.name;
    const filename = decodeURIComponent(event.Records[0].s3.object.key.replace(/\+/g, " "));
    const s3 = new AWS.S3();
    if (filename.endsWith(".enc")) {
        const isKey = filename.endsWith(".key.enc");
        listS3Objects(s3, Bucket).then(async function (res) {
            if (res.Contents) {
                for (let eachObject of res.Contents) {
                    if (isKey) {
                        let targetFileName = eachObject.Key?.substring(0, eachObject.Key?.length - 4);
                        //we need to find the file with it. It might not be there

                        if (eachObject.Key === targetFileName && eachObject.Key) {
                            await main(Bucket, eachObject.Key, filename, "private-key7");
                            callback("Found a Pair of files");
                            break;
                        }
                    } else {
                        //is a file. We need to find the key
                        let targetFileName = eachObject.Key?.substring(0, eachObject.Key?.length - 8);
                        targetFileName = targetFileName + ".enc";
                        if (eachObject.Key === targetFileName && eachObject.Key) {
                            await main(Bucket, filename, eachObject.Key, "private-key7");
                            callback("Found a Pair of files");
                            break;
                        }
                    }
                    callback("Waiting for the other file to be added");
                }
            }
        });
    } else {
        console.log;
        callback(null, "Decryption Upload");
    }
}

async function testWithoutTrigger() {
    const s3 = new AWS.S3();
    const Bucket = "ericmarcantoniobucket";
    const encFile = getS3ReadStream(s3, Bucket, "encryptedFiles/ChromeSetup.exe.enc");
    const encFileKey = getS3ReadStream(s3, Bucket, "encryptedFiles/ChromeSetup.exe.key.enc");
    const privateKey = (await getPrivateSecretByName("private-key7")) as string;

    convertReadStreamToString(encFileKey).then(async function (encKeyBytes) {
        const { writeStream, upload } = getS3PassThrough(s3, Bucket, "decryptedFiles/ChromeSetup.exe");
        await decryptStreamToNewStream(encFile, writeStream, encKeyBytes as string, privateKey);
        upload.then(function () {
            s3.deleteObject({ Bucket, Key: "encryptedFiles/ChromeSetup.exe.enc" });
            s3.deleteObject({ Bucket, Key: "encryptedFiles/ChromeSetup.exe.key.enc" });
        });
    });
}

testWithoutTrigger();
