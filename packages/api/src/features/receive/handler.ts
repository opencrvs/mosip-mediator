import * as Hapi from '@hapi/hapi'
import * as forge from 'node-forge'
import fetch from 'node-fetch'
import * as fs from 'fs'
import { resolve } from 'url'
import { logger } from '@api/logger'
import {
  NONCE_SIZE,
  AAD_SIZE,
  GCM_TAG_LENGTH,
  KEY_SPLITTER,
  VERSION_RSA_2048,
  AUTH_URL,
  SYMMETRIC_ALGORITHM,
  ASYMMETRIC_ALGORITHM,
  OPENCRVS_PRIV_KEY,
  IS_THUMBRPINT,
  THUMBPRINT_LENGTH
} from '@api/constants'

export async function receiveNidHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) {
  const authHeaderValue = request.headers['authorization']
  if (!authHeaderValue) {
    return h.response(`{"message":"Unauthorized"}\n`).code(401)
  }
  const verifyStatus = await fetch(resolve(AUTH_URL, 'verifyToken'), {
    method: 'POST',
    body: `token=${authHeaderValue.replace('Bearer ', '')}`,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  })
    .then(response => {
      return response.json()
    })
    .catch(error => {
      logger.error(`failed verifying token: ${error.message}`)
      return undefined
    })
  if (verifyStatus === undefined || verifyStatus['valid'] !== true) {
    logger.error(`Invalid Token. Response: ${JSON.stringify(verifyStatus)}`)
    return h.response().code(400)
  }
  logger.info('Receive NID Handler - Verified Auth token')
  asyncReceiveNid(JSON.stringify(request.payload))
  return h.response().code(200)
}

async function asyncReceiveNid(payloadStr: string) {
  await new Promise(r =>
    setTimeout(() => {
      r()
    }, 2000)
  )

  const payload = JSON.parse(payloadStr)
  if (!payload.event) {
    logger.error('invalid packet structure')
    return
  }
  const birthRegNo = payload.event.data.opencrvsId
  const encryptedData = Buffer.from(payload.event.data.credential, 'base64')
  // const verifiableCredential = Buffer.from(payload.event.data.proof.signature,'base64')

  // verify the Verifiable Credentials here

  logger.info('Verified Credentials sent by MOSIP')

  // then decrypt data
  let decryptedData: string
  try {
    decryptedData = decryptData(encryptedData)
  } catch (e) {
    logger.error(`Error decrypting data : ${e.stack}`)
    return
  }

  ////
  logger.info(
    `here birth registration no : ${birthRegNo} . decrypted data : ${decryptedData}`
  )
  fs.readFile('cards/.template.html', 'utf8', (err, data) => {
    if (err) {
      logger.error(`ID - ${birthRegNo}. Error reading from file: ${err.stack}`)
      return
    }
    const result = data
      .replace(/\$\!CRVSID/g, birthRegNo)
      .replace(/\$\!UIN/g, JSON.parse(decryptedData).credentialSubject.UIN)
    fs.writeFile(`cards/${birthRegNo}.html`, result, 'utf8', err2 => {
      if (err2) {
        logger.error(`ID - ${birthRegNo}. Error Writing to file: ${err2.stack}`)
      }
    })
  })
}

function decryptData(requestData: Buffer): string {
  const keyDemiliterIndex: number = requestData.indexOf(KEY_SPLITTER)
  if (keyDemiliterIndex < 0) {
    throw new Error('Imporper encrypted data format')
  }

  let encryptedSymmetricKey: Buffer
  let nonce: Buffer
  let aad: Buffer = Buffer.alloc(0)
  let encryptedData: Buffer
  let authTag: Buffer

  if (requestData.indexOf(VERSION_RSA_2048) === 0) {
    encryptedSymmetricKey = requestData.subarray(
      THUMBPRINT_LENGTH + VERSION_RSA_2048.length,
      keyDemiliterIndex
    )
    nonce = requestData.subarray(
      keyDemiliterIndex + KEY_SPLITTER.length,
      keyDemiliterIndex + KEY_SPLITTER.length + NONCE_SIZE
    )
    aad = requestData.subarray(
      keyDemiliterIndex + KEY_SPLITTER.length,
      keyDemiliterIndex + KEY_SPLITTER.length + AAD_SIZE
    )
    encryptedData = requestData.subarray(
      keyDemiliterIndex + KEY_SPLITTER.length + AAD_SIZE,
      requestData.length - GCM_TAG_LENGTH
    )
    authTag = requestData.subarray(
      requestData.length - GCM_TAG_LENGTH,
      requestData.length
    )

    logger.info(`encKey Length: ${encryptedSymmetricKey.length}`)
  } else if (IS_THUMBRPINT) {
    encryptedSymmetricKey = requestData.subarray(
      THUMBPRINT_LENGTH,
      keyDemiliterIndex
    )
    encryptedData = requestData.subarray(
      keyDemiliterIndex + KEY_SPLITTER.length + AAD_SIZE,
      requestData.length - GCM_TAG_LENGTH
    )
    authTag = requestData.subarray(
      requestData.length - GCM_TAG_LENGTH,
      requestData.length
    )
    nonce = encryptedData.subarray(
      encryptedData.length - GCM_TAG_LENGTH,
      encryptedData.length
    )
  } else {
    encryptedSymmetricKey = requestData.subarray(0, keyDemiliterIndex)
    encryptedData = requestData.subarray(
      keyDemiliterIndex + KEY_SPLITTER.length,
      requestData.length - GCM_TAG_LENGTH
    )
    authTag = requestData.subarray(
      requestData.length - GCM_TAG_LENGTH,
      requestData.length
    )
    nonce = encryptedData.subarray(
      encryptedData.length - GCM_TAG_LENGTH,
      encryptedData.length
    )
  }
  const opencrvsPrivKey: forge.pki.rsa.PrivateKey = forge.pki.privateKeyFromPem(
    OPENCRVS_PRIV_KEY
  )
  const decryptedSymmetricKey = opencrvsPrivKey.decrypt(
    encryptedSymmetricKey.toString('binary'),
    ASYMMETRIC_ALGORITHM,
    {
      md: forge.md.sha256.create(),
      mgf1: {
        md: forge.md.sha256.create()
      }
    }
  )
  const decipher = forge.cipher.createDecipher(
    SYMMETRIC_ALGORITHM,
    decryptedSymmetricKey
  )
  decipher.start({
    iv: nonce.toString('binary'),
    additionalData: aad.toString('binary'),
    tagLength: GCM_TAG_LENGTH * 8,
    tag: forge.util.createBuffer(authTag)
  })
  decipher.update(forge.util.createBuffer(encryptedData))
  const pass: boolean = decipher.finish()
  if (!pass) {
    throw new Error('Unable to decrypt data')
  }
  return Buffer.from(decipher.output.getBytes(), 'binary').toString('utf8')
}
