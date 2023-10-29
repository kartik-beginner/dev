const axios = require("axios")
const RSA = require("./RSA")

async function getAESkey(shaAadhar, RSAprivateKey){
    const store = await storage();
    const rsa = JSON.parse(store.public_keys[shaAadhar]).RSAencryptedcipherKey
    const key = RSA.decryptMessage(rsa, RSAprivateKey)
    // console.log(AES_KEY)
    return {key, rsa}
}

module.exports = { getAESkey};