const UTIL = require("../bin/util");
const INDEX = require("../bin/index")
const fs = require("fs");
(async function () {
    const clearTextFile = fs.createReadStream("./test/files/ChromeSetup.exe");
    const encFile = fs.createWriteStream("./test/files/ChromeSetup.exe.enc");
    const encKeyFile = fs.createWriteStream("./test/files/ChromeSetup.exe.key.enc");
    const publicKey = await INDEX.getPrivateSecretByName("public-key7");
    await INDEX.encryptStreamToNewStream(clearTextFile, encFile, encKeyFile, "helloworld", publicKey);

})();
