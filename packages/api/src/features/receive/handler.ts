import * as Hapi from '@hapi/hapi'
import * as forge from 'node-forge'
import fetch from 'node-fetch'
import * as fs from 'fs'
import { resolve } from 'url'
import base64url from 'base64url'
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
  THUMBPRINT_LENGTH,
  OPENHIM_MEDIATOR_URL
} from '@api/constants'

export async function receiveNidHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) {
  const authHeaderValue = request.headers['authorization']
  if (!authHeaderValue) {
    return h.response(`{"message":"Unauthorized"}\n`).code(401)
  }
  const openCRVSToken = `${authHeaderValue.replace('Bearer ', '')}`
  const verifyStatus = await verifyAuthToken(AUTH_URL, openCRVSToken)
  if (verifyStatus === undefined || verifyStatus['valid'] !== true) {
    logger.error(`Invalid Token. Response: ${JSON.stringify(verifyStatus)}`)
    return h.response().code(400)
  }
  logger.info('Receive NID Handler - Verified Auth token')
  asyncReceiveUINToken(JSON.stringify(request.payload), openCRVSToken)
  return h.response().code(200)
}

async function asyncReceiveUINToken(payloadStr: string, openCRVSToken: string) {
  logger.debug(`Received payload: ${payloadStr}`)
  const payload = JSON.parse(payloadStr)
  if (!payload.data || !payload.signature) {
    logger.error('invalid packet structure')
    return
  }
  // skipping signature check
  // verify the Credentials here
  logger.info('Verified Credentials sent by MOSIP')

  const encryptedData = base64url.toBuffer(payload.data)

  // then decrypt data
  let decryptedData: string
  try {
    decryptedData = decryptData(encryptedData)
  } catch (e) {
    logger.error(`Error decrypting data : ${e.stack}`)
    return
  }
  const birthRegNo: string = JSON.parse(decryptedData).opencrvsBRN
  const uinToken: string = JSON.parse(decryptedData).uinToken

  ////
  logger.debug(
    `here birth registration no : ${birthRegNo} . decrypted data : ${decryptedData}`
  )

  // send data to OpenCRVS Country Configuration OpenHIM Mediator URL
  await putUINTokenToHIMMediator(openCRVSToken, uinToken, birthRegNo)

  fs.readFile('cards/.template.html', 'utf8', (err, data) => {
    if (err) {
      logger.error(`ID - ${birthRegNo}. Error reading from file: ${err.stack}`)
      return
    }
    const result = data
      .replace(/\$\!CRVSID/g, birthRegNo)
      .replace(/\$\!UINTOKEN/g, uinToken)
    fs.writeFile(`cards/${birthRegNo}.html`, result, 'utf8', err2 => {
      if (err2) {
        logger.error(`ID - ${birthRegNo}. Error Writing to file: ${err2.stack}`)
      }
    })
  })
}

async function putUINTokenToHIMMediator(
  openCRVSAuthToken: string,
  uinToken: string,
  birthRegNo: string
) {
  try {
    const nationalIdOpenHIMMediatorResponse = await fetch(
      OPENHIM_MEDIATOR_URL,
      {
        method: 'POST',
        body: JSON.stringify({
          BRN: birthRegNo,
          UINTOKEN: uinToken
        }),
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${openCRVSAuthToken}`
        }
      }
    )
      .then(response => {
        return response
      })
      .catch(error => {
        return Promise.reject(new Error(` request failed: ${error.message}`))
      })
    if (!nationalIdOpenHIMMediatorResponse) {
      throw new Error('Cannot get response from OpenHIM Mediator')
    }
  } catch (error) {
    logger.error(error)
  }
}

function decryptData(requestData: Buffer): string {
  const keyDemiliterIndex: number = requestData.indexOf(KEY_SPLITTER)
  if (keyDemiliterIndex < 0) {
    throw new Error('Improper encrypted data format')
  }

  let encryptedSymmetricKey: Buffer
  let nonce: Buffer
  let aad: Buffer = Buffer.alloc(0)
  let encryptedData: Buffer
  let authTag: Buffer

  if (requestData.indexOf(VERSION_RSA_2048) === 0) {
    encryptedSymmetricKey = requestData.subarray(
      IS_THUMBRPINT
        ? VERSION_RSA_2048.length + THUMBPRINT_LENGTH
        : VERSION_RSA_2048.length,
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
async function verifyAuthToken(authUrl: string, token: string) {
  if (!authUrl) {
    return { valid: true }
  }
  return await fetch(resolve(authUrl, 'verifyToken'), {
    method: 'POST',
    body: `token=${token}`,
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
}
