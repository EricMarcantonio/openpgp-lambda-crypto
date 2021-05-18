const INDEX = require("../bin/index");
const UTIL = require("../bin/util");
const fs = require("fs");

test("Get Secret from AWS", async () => {
    let res = await INDEX.getPrivateSecretByName("private-key7");
    expect(res.length).toBeGreaterThan(0);
    expect(typeof res).toBe("string");
});

test("Encrypt a file with a secret", async () => {
    const clearTextFile = fs.createReadStream("./test/files/ChromeSetup.exe");
    const encFile = fs.createWriteStream("./test/files/ChromeSetup.exe.enc");
    const encKeyFile = fs.createWriteStream("./test/files/ChromeSetup.exe.key.enc");
    const publicKey = await INDEX.getPrivateSecretByName("public-key7");
    await INDEX.encryptStreamToNewStream(clearTextFile, encFile, encKeyFile, "helloworld", publicKey).then((){
        clearTextFile.on("end", () => {
            clearTextFile.close();
        })
        encFile.on("finish")
    })
    
    clearTextFile.close(), encFile.close(), encKeyFile.close()
    const keyRead = fs.readFileSync("./test/files/ChromeSetup.exe.key.enc")
    const binRead = fs.readFileSync("./test/files/ChromeSetup.exe.enc")
    expect(keyRead.length).toBeGreaterThan(0);
    expect(binRead.length).toBeGreaterThan(0);
});


test("Save public and private keys", async () => {
    await UTIL.generateKeysAndWriteToFile("./test/keys/private.asc", "./test/keys/public.asc")
    const privKey = fs.readFileSync("./test/keys/private.asc")
    const pubKey = fs.readFileSync("./test/keys/public.asc")
    expect(privKey.length).toBeGreaterThan(0)
    expect(pubKey.length).toBeGreaterThan(0)
});
