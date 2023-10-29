const router = require("express").Router()
const axios = require("axios")
const { getAESkey} = require("./get_Storage")
const RSA = require("./RSA")
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const pinataSDK = require('@pinata/sdk');
const fs = require('fs');
const { Readable } = require('stream'); 

const pinata = new pinataSDK(process.env.CLIENT_ID, process.env.CLIENT_API)
const upload = multer().single('document')
router.post('/upload', (req, res) => {
    console.log('Request body:', req.body);
    console.log('Request file:', req.file);

    upload(req, res, async (uploadError) => {
        if (uploadError) {
            console.error('Error uploading:', uploadError);
            return res.status(400).json({ message: 'Error uploading file' });
        }

        console.log('Uploaded file:', req.file);

        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }

        const fileBuffer = req.file.buffer;

        try {
            // Create a readable stream from the Buffer data
            const fileStream = new Readable();
            fileStream.push(fileBuffer);
            fileStream.push(null); // Signal the end of the stream

            // Upload to Pinata IPFS
            const options = {
                pinataMetadata: {
                    name: 'File',
                },
                pinataOptions: {
                    cidVersion: 0,
                },
            };
            const ipfsResponse = await pinata.pinFileToIPFS(fileStream, options);

            res.status(200).json({
                ipfsResponse,
                fileHash: fileBuffer.toString(),
                document: "https://gateway.pinata.cloud/ipfs/"+ipfsResponse.IpfsHash
            });
        } catch (error) {
            console.error('Error uploading to IPFS:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    });
});

router.post("/makeSHAhash", async (req, res) => {
    const hashedAadhar = crypto.createHash('sha256').update(req.body.aadhar).digest('hex');
    return res.status(200).json({
        hashedAadhar: hashedAadhar,
        message: "Success"
    })
})

router.post("/login", async (req, res) => {

    // req.body - name sex age publicKey privateKey RSAencryptedAESKEY
 
        let aadhar = req.body.aadhar;
            try{    
            // const publicKeyinput = JSON.parse(storageObj.public_keys[AadharHash])
            // // console.log(publicKeyinput)
            let intermediate = RSA.decryptMessage(req.body.RSAencryptedAESKEY, req.body.privateKey)

            let key = JSON.parse(intermediate)
            
            const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key.encryptionKey, 'hex'), Buffer.from(key.iv, 'hex'));
            let name = decipher.update(req.body.name, 'hex', 'utf-8');
            name += decipher.final('utf-8');

            const decipher2 = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key.encryptionKey, 'hex'), Buffer.from(key.iv, 'hex'));
            let sex = decipher2.update(req.body.sex, 'hex', 'utf-8');
            sex += decipher2.final('utf-8');

            const decipher3 = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key.encryptionKey, 'hex'), Buffer.from(key.iv, 'hex'));
            let age = decipher3.update(req.body.age, 'hex', 'utf-8');
            age += decipher3.final('utf-8');

            const payload = {
                name,age,sex
            }

            const options = {
                expiresIn: '1h'
            }

            const token = jwt.sign(payload, process.env.JWT_SECRET,options)


            return res.status(200).json({
                message: "Success",
                name: name,
                age: age, 
                sex: sex,
                aadhar,
                token
            })
        }
        catch(err){
            return res.status(500).json({
                err: err,
                message: "Incorrect Private Key",
                input: req.body
            })
        }
    
});


router.post("/makeDiagnosis", async (req, res)=>{
    let aadhar = req.body.aadhar;

    try{
        let intermediate = RSA.decryptMessage(req.body.RSAencryptedAESKEY, req.body.privateKey)

        let key = JSON.parse(intermediate)

        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key.encryptionKey, 'hex'), Buffer.from(key.iv, 'hex'));
        let encryptedName = cipher.update(req.body.name, 'utf-8', 'hex');
        encryptedName += cipher.final('hex');

        const cipher2 = crypto.createCipheriv('aes-256-cbc', Buffer.from(key.encryptionKey, 'hex'), Buffer.from(key.iv, 'hex'));
        let diagnosis = cipher2.update(req.body.diagnosis, 'utf-8', 'hex');
        diagnosis += cipher2.final('hex');

        const cipher3 = crypto.createCipheriv('aes-256-cbc', Buffer.from(key.encryptionKey, 'hex'), Buffer.from(key.iv, 'hex'));
        let DocType = cipher3.update(req.body.docType, 'utf-8', 'hex');
        DocType += cipher3.final('hex');

        const cipher4 = crypto.createCipheriv('aes-256-cbc', Buffer.from(key.encryptionKey, 'hex'), Buffer.from(key.iv, 'hex'));
        let DocName = cipher4.update(req.body.docName, 'utf-8', 'hex');
        DocName += cipher4.final('hex');

        const cipher5 = crypto.createCipheriv('aes-256-cbc', Buffer.from(key.encryptionKey, 'hex'), Buffer.from(key.iv, 'hex'));
        let document = cipher5.update(req.body.document, 'utf-8', 'hex');
        document += cipher5.final('hex');

        const cipher6 = crypto.createCipheriv('aes-256-cbc', Buffer.from(key.encryptionKey, 'hex'), Buffer.from(key.iv, 'hex'));
        let symptoms = cipher6.update(req.body.symptoms, 'utf-8', 'hex');
        symptoms += cipher6.final('hex');


        return res.status(200).json({
            message: "Success",
            name: encryptedName,
            diagnosis: diagnosis,
            DocType: DocType,
            DocName: DocName,
            document: document,
            symptoms: symptoms,
            userAadhar: aadhar,
            RSAencryptedcipherKey: req.body.RSAencryptedAESKEY
        })

    }
    catch(e){
        res.status(404).json({
            message: "Incorrect Private Key", 
            e,
        })
    }
});

router.post("/decrypt_diagnosis", async (req, res)=> {
    try{
        let intermediate = RSA.decryptMessage(req.body.RSAencryptedAESKEY, req.body.privateKey)

        let key = JSON.parse(intermediate)

        let dia_list = req.body.diagnosisList;

        let decryptedList = [];

        for (let i=0;i<dia_list.length;i++){
            let element = dia_list[i];

            for(let field in element){
                const de = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key.encryptionKey, 'hex'), Buffer.from(key.iv, 'hex'));
                let decrypted = de.update(element[field], 'hex', 'utf-8');
                decrypted += de.final('utf-8');
                element[field] = decrypted;
            }

            decryptedList.push(element);
        }

        return res.status(200).json({
            data: decryptedList,
            message: "Success"
        });

    }
    catch(e){
        res.status(404).json({
            e, 
            message: "something went wrong while decrypting"
        })
    }
})


module.exports = router