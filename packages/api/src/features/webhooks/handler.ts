import * as Hapi from '@hapi/hapi'
import fetch from 'node-fetch'
import * as forge from 'node-forge'
import { logger } from '@api/logger'
import {
  NONCE_SIZE,
  AAD_SIZE,
  GCM_TAG_LENGTH,
  KEY_SPLITTER,
  VERSION_RSA_2048,
  PROXY_CALLBACK_URL,
  ASYMMETRIC_ALGORITHM,
  SYMMETRIC_ALGORITHM,
  SYMMETRIC_KEY_SIZE,
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

export async function webhooksHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) {
  logger.info(`birthHandler has been called with some payload`)

  if (request.payload && request.payload['id']) {
    proxyCallback(request.payload['id'], JSON.stringify(request.payload))
  }

  return h.response().code(200)
}

async function proxyCallback(id: string, payload: string) {
  await new Promise(r =>
    setTimeout(() => {
      r()
    }, 2000)
  )

  let proxyRequest
  try {
    proxyRequest = encryptAndSign(id, payload)
  } catch (e) {
    logger.error(`Error encrypting and signing data: ${e.stack}`)
    return
  }

  logger.info(`Encryting Payload Complete. Here is the payload id : ${id}`)

  const authToken = await fetch(MOSIP_AUTH_URL, {
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

  logger.info(`ID - ${id}. Received MOSIP Auth token`)

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
  logger.info(`ID - ${id}. Sent data to Mosip. Response: ${res}`)
}

function encryptAndSign(payId: string, requestData: string): string {
  const opencrvsPrivateKey: forge.pki.rsa.PrivateKey = forge.pki.privateKeyFromPem(
    OPENCRVS_PRIV_KEY
  )
  const mosipPublicKey: forge.pki.rsa.PublicKey = forge.pki.certificateFromPem(
    MOSIP_PUBLIC_KEY
  ).publicKey as forge.pki.rsa.PublicKey

  const symmetricKey: string = forge.random.getBytesSync(SYMMETRIC_KEY_SIZE)
  const nonce: string = forge.random.getBytesSync(NONCE_SIZE)
  const aad: string = forge.random.getBytesSync(AAD_SIZE - NONCE_SIZE)

  const encryptedSymmetricKey: string = mosipPublicKey.encrypt(
    symmetricKey,
    ASYMMETRIC_ALGORITHM,
    {
      md: forge.md.sha256.create(),
      mgf1: {
        md: forge.md.sha256.create()
      }
    }
  )
  const encryptCipher = forge.cipher.createCipher(
    SYMMETRIC_ALGORITHM,
    symmetricKey
  )
  encryptCipher.start({
    iv: nonce,
    additionalData: nonce + aad,
    tagLength: GCM_TAG_LENGTH * 8
  })
  encryptCipher.update(forge.util.createBuffer(requestData))
  encryptCipher.finish()
  const encryptedData = Buffer.concat([
    Buffer.from(VERSION_RSA_2048),
    Buffer.from(encryptedSymmetricKey, 'binary'),
    Buffer.from(KEY_SPLITTER),
    Buffer.from(
      nonce +
        aad +
        encryptCipher.output.getBytes() +
        encryptCipher.mode.tag.getBytes(),
      'binary'
    )
  ])

  const digestSign = forge.md.sha256.create()
  digestSign.update(encryptedData.toString('binary'))
  const sign = opencrvsPrivateKey.sign(digestSign)

  return JSON.stringify({
    id: payId,
    data: encryptedData.toString('base64'),
    signature: forge.util.encode64(sign)
  })
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
