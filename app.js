const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const FormData = require('form-data');
const fs = require('fs');
const tweetnacl = require('tweetnacl');
const Jimp = require('jimp');
const path = require('path');
const cors = require('cors');

const app = express();
const port = 88; // You can change this port as needed

// Middleware to parse JSON requests
app.use(bodyParser.json());
app.use(cors());

// Set up multer to handle file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Serve images from the 'images_after' directory
app.use('/images_after', express.static(path.join(__dirname, 'images_after')));

// Download route for BMP files in the '/images_after' directory
app.get('/steganography/download/images_after/*', (req, res) => {
  const fileName = req.params[0]; // Extract the filename from the wildcard parameter

  // Set the Content-Disposition header to prompt the user to download the file
  res.setHeader('Content-Disposition', `attachment; filename=${fileName}`);

  // Send the file
  res.sendFile(path.join(__dirname, 'images_after', fileName));
});

// Serve static files from the 'public' folder
app.get('/steganography', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'cryptography.html'));
});

// Endpoint for encoding
app.post('/steganography/encode', upload.single('image'), (req, res) => {
  try {
    if (!req.body || !req.body.message) {
      return res.status(400).json({ error: 'Message field is missing in the request body' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    let imagePath = saveImage(req)
    
    // Generate key pair
    const publicKeyBox = tweetnacl.box.keyPair();
    const privateKeyBox = tweetnacl.box.keyPair();
    const publicKey = publicKeyBox.publicKey;
    const publicSecret = publicKeyBox.secretKey
    const privateKey = privateKeyBox.publicKey
    const privateSecret = privateKeyBox.secretKey
    const nonce = tweetnacl.randomBytes(tweetnacl.box.nonceLength);
    let message = req.body.message
    
    const messageInUint8Array = Buffer.from(message, 'utf-8')
    const encryptedMessage = encrypt(messageInUint8Array, nonce, privateKey, publicSecret)

    // Use the callback approach for encodeToImage
    encodeToImage(imagePath, encryptedMessage, (err, _) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Error encoding image' });
        }

        res.json({ 
            publicKeyHex: Buffer.from(publicKey).toString('hex'), 
            privateSecretHex: Buffer.from(privateSecret).toString('hex'), 
            nonceHex: Buffer.from(nonce).toString('hex'), 
            imagePath: imagePath.split(path.sep).slice(-2).join('/').replace("before", "after"),
        });
    });
  } catch(err) {
    const timeZone = 'Asia/Jakarta';
    const currentTimestamp = new Date().toLocaleString('en-US', { timeZone, timeZoneName: 'short' });
    console.log("\n\nError: ", error, " Date: " + currentTimestamp);
    res.status(500).json({"error": "Make sure all input is correct!"})  }
});

app.post('/steganography/decode', upload.single('image'), async (req, res) => {
  try {
    const { publicKeyHex, privateSecretHex, nonceHex } = req.body;

    let publicKey = hexToUint8Array(publicKeyHex)
    let privateSecret = hexToUint8Array(privateSecretHex)
    let nonce = hexToUint8Array(nonceHex)
    let imagePath = saveImage(req);
    let binarySecretText = await decodeImage(imagePath);
    let encryptedMessageInUInt8Array = binaryStringToUint8Array(binarySecretText)

    decryptedMessageInUInt8Array = tweetnacl.box.open(encryptedMessageInUInt8Array, nonce, publicKey, privateSecret);

    if (decryptedMessageInUInt8Array === null) {
      // Handle error
      const timeZone = 'Asia/Jakarta';
      const currentTimestamp = new Date().toLocaleString('en-US', { timeZone, timeZoneName: 'short' });
      console.log("Error: ", error, " Date: " + currentTimestamp);
      res.json({"error": "Failed to decrypt, please check the credential"})
      return
    }

    decryptedMessageInString = uint8ArrayToString(decryptedMessageInUInt8Array)
  
    // Send the decoded message in the response
    res.json({ message: decryptedMessageInString });
  } catch (error) {
    const timeZone = 'Asia/Jakarta';
    const currentTimestamp = new Date().toLocaleString('en-US', { timeZone, timeZoneName: 'short' });
    console.log("\n\nError: ", error, " Date: " + currentTimestamp);
    res.status(500).json({"error": "Make sure all input is correct!"})
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});

function encodeToImage(originalImagePath, secretText, callback) {
  Jimp.read(originalImagePath, (err, image) => {
      if (err) {
          console.error(err);
          return callback(err);
      }

      // Convert the secret text to binary
      let textIndex = 0;
      const messageLength = secretText.length;

      image.scan(0, 0, image.bitmap.width, image.bitmap.height, (x, y, _) => {
        if (x === image.bitmap.width - 3 && y === image.bitmap.height - 3) {
          const messageLengthInBinary = padBinary(messageLength.toString(2), 9);

          for (let index = 3; index > 0; index--) {
            x = image.bitmap.width - index
            y = image.bitmap.height - index

            let { r, g, b, a } = Jimp.intToRGBA(image.getPixelColor(x, y));
            r = (r & 0xFE) | (messageLengthInBinary[((3 - index) * 3) + 0] & 0x01)
            g = (g & 0xFE) | (messageLengthInBinary[((3 - index) * 3) + 1] & 0x01)
            b = (b & 0xFE) | (messageLengthInBinary[((3 - index) * 3) + 2] & 0x01)

            image.setPixelColor(Jimp.rgbaToInt(r, g, b, a), x, y);
          }
        } else {
          if (textIndex < messageLength) {
              let { r, g, b, a } = Jimp.intToRGBA(image.getPixelColor(x, y));

              r = (r & 0xFE) | (secretText[textIndex] & 0x01)
              textIndex++;

              if (textIndex < messageLength) {
                g = (g & 0xFE) | (secretText[textIndex] & 0x01)
                textIndex++;
              }
    
              if (textIndex < messageLength) {
                b = (b & 0xFE) | (secretText[textIndex] & 0x01)
                textIndex++;
              }
              image.setPixelColor(Jimp.rgbaToInt(r, g, b, a), x, y);
          }
        }
      });

      // Save the modified image
      let savePath = originalImagePath.replace("before", "after")
      image.write(savePath, (err) => {
          if (err) {
              console.error(err);
              return callback(err);
          }

          // Pass the result to the callback
          callback(null, 'Image encoded successfully');
      });
  })
}

async function decodeImage(steganographedImagePath) {
  const image = await Jimp.read(steganographedImagePath);

  let binarySecretText = '';
  let messageLength = '';
  let textIndex = 0;

  let messageLengthInBinary = ''
  for (let index = 3; index > 0; index--) {
    x = image.bitmap.width - index
    y = image.bitmap.height - index

    let { r, g, b } = Jimp.intToRGBA(image.getPixelColor(x, y));
    messageLengthInBinary += r & 0x01;
    messageLengthInBinary += g & 0x01;
    messageLengthInBinary += b & 0x01;
  }

  messageLength = parseInt(messageLengthInBinary, 2)

  image.scan(0, 0, image.bitmap.width, image.bitmap.height, (x, y, _) => { 
    if (x === image.bitmap.width - 1 && y === image.bitmap.height - 1) {
    } else {
      if (textIndex < messageLength) {
          let { r, g, b } = Jimp.intToRGBA(image.getPixelColor(x, y));
        if (textIndex < messageLength) {
            binarySecretText += r & 0x01;
            textIndex++

            if (textIndex < messageLength) {
              binarySecretText += g & 0x01;
              textIndex++
            }
        
            if (textIndex < messageLength) {
              binarySecretText += b & 0x01;
              textIndex++
            }
        }
      }
    }
  })

  // Convert the binary secret text to a Buffer and then to a string
  return binarySecretText;
}

function saveImage(req) {
  // Process the uploaded file as needed
  const imageBuffer = req.file.buffer;

  // Save the image to the images/ directory
  let imagePath = path.join(__dirname, 'images_before', `${Date.now()}-${req.file.originalname}`);

  fs.writeFile(imagePath, imageBuffer, (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error saving the image.');
    }
  });

  return imagePath
}

function hexToUint8Array(hexString) {
  // Remove the leading '0x' if present
  hexString = hexString.startsWith('0x') ? hexString.slice(2) : hexString;

  // Split the hex string into pairs of characters
  const pairs = hexString.match(/.{1,2}/g) || [];

  // Convert each pair to a byte value
  const byteArray = pairs.map(pair => parseInt(pair, 16));

  // Create a Uint8Array from the byte values
  return new Uint8Array(byteArray);
}

function encrypt(message, nonce, privateKey, publicSecret) {
  return tweetnacl.box(message, nonce, privateKey, publicSecret).reduce((binaryString, byte) => binaryString + byte.toString(2).padStart(8, '0'), '')
}

function binaryStringToUint8Array(binaryString) {
  const length = binaryString.length;
  const uint8Array = new Uint8Array(length / 8);

  for (let i = 0; i < length; i += 8) {
      const byte = binaryString.slice(i, i + 8);
      uint8Array[i / 8] = parseInt(byte, 2);
  }

  return uint8Array;
}

function uint8ArrayToString(uint8Array) {
  const decoder = new TextDecoder('utf-8');  // Adjust the encoding if necessary
  return decoder.decode(uint8Array);
}

function padBinary(binaryString, targetLength) {
  const currentLength = binaryString.length;
  
  if (currentLength >= targetLength) {
    return binaryString;
  }

  const padding = '0'.repeat(targetLength - currentLength);
  return padding + binaryString;
}