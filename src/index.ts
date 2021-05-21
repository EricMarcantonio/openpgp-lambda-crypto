import * as openpgp from "openpgp";
import * as AWS from "aws-sdk";
import stream from "stream";

//----------AWS----------
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
//----------END----------


/**
 * Convert a stream to a string. Note, loads all data in memory. Used for small data (like private keys)
 * @param stream stream of data
 * @returns a Promise resolving to a string of data
 */
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


/**
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



/**
 * Function that decrypts a stream.Readable, and pipes plaintext data to a stream.Writable.
 * @param srcStream - the stream with the encrypted file
 * @param destStream - the destStream with the decrypted file should be piped
 * @param encSecret - the encrypted secret that will be decrypted with the private key
 * @param privateKey - the private key used to decrypt the encSecret
 */
export async function decryptStreamToNewStream(
    srcStream: stream.Readable,
    destStream: stream.Writable,
    encSecret: stream.Readable,
    privateKey: string
) {
    const encSecretString = (await convertReadStreamToString(encSecret)) as string;
    const secret = await decryptSecretWithPrivate(encSecretString, privateKey);
    const decryptedData = await decryptFileSym(srcStream, secret);
    decryptedData.data.pipe(destStream);
}

/**
 * Needed to start decrypting files without loading them all into memory
 */
openpgp.config.allowUnauthenticatedStream = true;
openpgp.config.allowUnauthenticatedMessages = true;



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

    const { writeStream, upload } = await getS3PassThrough(
        s3,
        Bucket,
        encryptedFileName.substr(0, encryptedFileName.length - 4)
    );
    await decryptStreamToNewStream(encFile, writeStream, encFileKey, privateKey);
    await upload.then(function () {
        console.log("Finished Uploading");
    });
}

export async function handler(event: any, context: any, callback: any) {
    const Bucket = event.Records[0].s3.bucket.name;
    const filename = event.Records[0].s3.object.key;
    const s3 = new AWS.S3();
    const isKey = filename.endsWith(".key.enc");
    const objectsInBucket = await listS3Objects(s3, Bucket);
    if (!objectsInBucket.Contents) callback(null, "No Objects Found ");
    else {
        for (let eachObject of objectsInBucket.Contents) {
            let targetFileName = isKey
                ? filename.substring(0, filename.length - 8) + ".enc"
                : filename.substring(0, filename.length - 4) + ".key.enc";

            if (eachObject.Key === targetFileName && eachObject.Key) {
                isKey
                    ? await main(Bucket, eachObject.Key, filename, "private-key7")
                    : await main(Bucket, filename, eachObject.Key, "private-key7");
                callback(null, "Found a Pair of files");
                return;
            }
        }
        callback(null, "Pair not found");
    }
}
