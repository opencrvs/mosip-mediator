import * as Hapi from '@hapi/hapi'
import * as crypto from 'crypto'
import fetch from 'node-fetch'
import { resolve } from 'url'
import { logger } from '@api/logger'
import {
  NONCE_SIZE,
  AAD_SIZE,
  GCM_TAG_LENGTH,
  KEY_SPLITTER,
  VERSION_RSA_2048,
  AUTH_URL,
  SIGN_ALGORITHM,
  SYMMETRIC_ENCRYPT_ALGORITHM,
  MOSIP_VERIFY_SIGN_KEY,
  OPENCRVS_PRIV_KEY
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
  asyncReceiveNid(request)
  return h.response().code(200)
}

async function asyncReceiveNid(request: Hapi.Request) {
  const payload = JSON.parse(JSON.stringify(request.payload))
  const birthRegNo = payload.event.data.opencrvsId
  const encryptedData = payload.event.data.credential
  const signature = payload.event.data.proof.signature

  logger.info(`here received encryted data: ${encryptedData}`)

  if (
    !crypto.verify(
      SIGN_ALGORITHM,
      encryptedData,
      MOSIP_VERIFY_SIGN_KEY,
      signature
    )
  ) {
    logger.error(`Cannot verify mosip signature in data`)
    return
  }
  logger.info(
    `here birth registration no : ${birthRegNo} . decrypted data : ${decryptData(
      encryptedData
    )}`
  )
}

function decryptData(requestData: Buffer) {
  const keyDemiliterIndex: number = requestData.indexOf(KEY_SPLITTER)
  if (keyDemiliterIndex < 0) {
    logger.error('Imporper encrypted data format')
    return undefined
  }
  try {
    if (requestData.indexOf(VERSION_RSA_2048) === 0) {
      const encryptedSymmetricKey: Buffer = requestData.subarray(
        VERSION_RSA_2048.length,
        keyDemiliterIndex
      )
      const nonce: Buffer = requestData.subarray(
        keyDemiliterIndex + KEY_SPLITTER.length,
        keyDemiliterIndex + KEY_SPLITTER.length + NONCE_SIZE
      )
      const aad: Buffer = requestData.subarray(
        keyDemiliterIndex + KEY_SPLITTER.length,
        keyDemiliterIndex + KEY_SPLITTER.length + AAD_SIZE
      )
      const encryptedData: Buffer = requestData.subarray(
        keyDemiliterIndex + KEY_SPLITTER.length + AAD_SIZE,
        requestData.length - GCM_TAG_LENGTH
      )
      const authTag: Buffer = requestData.subarray(
        requestData.length - GCM_TAG_LENGTH,
        requestData.length
      )

      const decryptedSymmetricKey = crypto.privateDecrypt(
        {
          key: OPENCRVS_PRIV_KEY,
          oaepHash: 'sha256',
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        },
        encryptedSymmetricKey
      )
      const cipher = crypto
        .createDecipheriv(
          SYMMETRIC_ENCRYPT_ALGORITHM,
          decryptedSymmetricKey,
          nonce
        )
        .setAAD(aad, { plaintextLength: GCM_TAG_LENGTH })
        .setAuthTag(authTag)
      return Buffer.concat([
        cipher.update(encryptedData),
        cipher.final()
      ]).toString('utf8')
    } else {
      const encryptedSymmetricKey: Buffer = requestData.subarray(
        0,
        keyDemiliterIndex
      )
      const encryptedData: Buffer = requestData.subarray(
        keyDemiliterIndex + KEY_SPLITTER.length,
        requestData.length - GCM_TAG_LENGTH
      )
      const authTag: Buffer = requestData.subarray(
        requestData.length - GCM_TAG_LENGTH,
        requestData.length
      )

      const decryptedSymmetricKey = crypto.privateDecrypt(
        {
          key: OPENCRVS_PRIV_KEY,
          oaepHash: 'sha256',
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        },
        encryptedSymmetricKey
      )
      const cipher = crypto
        .createDecipheriv(
          SYMMETRIC_ENCRYPT_ALGORITHM,
          decryptedSymmetricKey,
          encryptedData.subarray(
            encryptedData.length - GCM_TAG_LENGTH,
            encryptedData.length
          )
        )
        .setAuthTag(authTag)
      return Buffer.concat([
        cipher.update(encryptedData),
        cipher.final()
      ]).toString('utf8')
    }
  } catch (e) {
    logger.error(`Error decrypting data : ${e}`)
    return undefined
  }
}
