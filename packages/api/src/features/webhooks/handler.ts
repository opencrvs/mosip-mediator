import * as Hapi from '@hapi/hapi'
import * as crypto from 'crypto'
import fetch from 'node-fetch'
import { logger } from '@api/logger'
import {
  KEY_SPLITTER,
  VERSION_RSA_2048,
  PROXY_CALLBACK_URL,
  SIGN_ALGORITHM,
  SYMMETRIC_ENCRYPT_ALGORITHM,
  MOSIP_PUBLIC_KEY,
  OPENCRVS_PRIV_KEY,
  MOSIP_AUTH_URL,
  MOSIP_AUTH_CLIENT,
  MOSIP_AUTH_USER,
  MOSIP_AUTH_PASS
} from '@api/constants'
// import * as Joi from 'joi'

interface IRequestParams {
  [key: string]: string
}

export async function birthHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) {
  logger.info(`birthHandler has been called with some payload`)

  if (request.payload && request.payload['id']) {
    proxyCallback(request)
  }

  return h.response().code(200)
}

async function proxyCallback(request: Hapi.Request) {
  logger.info(`Here is the payload id : ${request.payload['id']}`)
  const keyHeader: Buffer = Buffer.from(VERSION_RSA_2048)
  const keySplitter: Buffer = Buffer.from(KEY_SPLITTER)
  const symmetricKey: Buffer = crypto.randomBytes(32)
  const nonce: Buffer = crypto.randomBytes(12)
  const aad: Buffer = crypto.randomBytes(20)
  const encryptedSymmetricKey: Buffer = crypto.publicEncrypt(
    {
      key: MOSIP_PUBLIC_KEY,
      padding: crypto.constants.RSA_PKCS1_PADDING
    },
    symmetricKey
  )
  const cipher = crypto
    .createCipheriv(SYMMETRIC_ENCRYPT_ALGORITHM, symmetricKey, nonce)
    .setAAD(Buffer.concat([nonce, aad]), { plaintextLength: 16 })
  const encryptedPayload = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(request.payload))),
    cipher.final()
  ])
  const encryptedData = Buffer.concat([
    keyHeader,
    encryptedSymmetricKey,
    keySplitter,
    nonce,
    aad,
    encryptedPayload,
    cipher.getAuthTag()
  ])

  const sign = crypto.sign(
    SIGN_ALGORITHM,
    Buffer.from(encryptedData),
    OPENCRVS_PRIV_KEY
  )

  const proxyRequest = JSON.stringify({
    id: request.payload['id'],
    data: encryptedData.toString('base64'),
    signature: sign.toString('base64')
  })

  let authToken
  authToken = await fetch(MOSIP_AUTH_URL, {
    method: 'POST',
    body: `client_id=${MOSIP_AUTH_CLIENT}&username=${MOSIP_AUTH_USER}&password=${MOSIP_AUTH_PASS}&grant_type=password`,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  })
    .then(response => {
      return response.json()
    })
    .catch(error => {
      logger.error(`failed getting mosip auth token. error: ${error.message}`)
      return undefined
    })
  if (authToken === undefined || authToken['access_token'] === undefined) {
    logger.error(
      `failed getting mosip auth token. response: ${JSON.stringify(authToken)}`
    )
    return
  }

  const res = await fetch(PROXY_CALLBACK_URL, {
    method: 'POST',
    body: proxyRequest,
    headers: {
      'Content-Type': 'application/json',
      cookie: `Authorization=${authToken['access_token']}`
    }
  })
    .then(response => {
      return response.text()
    })
    .catch(error => {
      logger.error(`failed sending data to mosip: ${error.message}`)
      return undefined
    })
  logger.info(`Sent data to Mosip. Response: ${res}`)
}

export async function subscriptionConfirmationHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) {
  const params = request.query as IRequestParams

  const mode = params['mode']
  const challenge = params['challenge']
  const topic = params['topic']

  if (
    !mode ||
    mode !== 'subscribe' ||
    !challenge ||
    !topic ||
    topic !== 'BIRTH_REGISTERED'
  ) {
    throw new Error('Params incorrect')
  } else {
    return h.response({ challenge: decodeURIComponent(challenge) }).code(200)
  }
}
