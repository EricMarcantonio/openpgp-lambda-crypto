import * as openpgp from 'openpgp'
import fs from 'fs'
export async function generateKeysAndWriteToFile(privateKeyPath: string, pubKeyPath: string) {
    const {privateKeyArmored, publicKeyArmored} = await openpgp.generateKey({
        userIDs: [{ name: "person", email: "person@somebody.com" }],
    });
    fs.writeFileSync(privateKeyPath, privateKeyArmored)
    fs.writeFileSync(pubKeyPath, publicKeyArmored)
}