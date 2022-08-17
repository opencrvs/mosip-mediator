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
  MOSIP_BIRTH_PROXY_CALLBACK_URL,
  MOSIP_DEATH_PROXY_CALLBACK_URL,
  ASYMMETRIC_ALGORITHM,
  SYMMETRIC_ALGORITHM,
  SYMMETRIC_KEY_SIZE,
  MOSIP_PUBLIC_KEY,
  OPENCRVS_PRIV_KEY,
  MOSIP_AUTH_URL,
  MOSIP_AUTH_CLIENT_ID,
  MOSIP_AUTH_CLIENT_SECRET,
  MOSIP_AUTH_USER,
  MOSIP_AUTH_PASS,
  IS_THUMBRPINT,
  THUMBPRINT_LENGTH
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

  if (request.payload) {
    const pay = JSON.parse(JSON.stringify(request.payload))
    let sendingUrl
    if (pay.event && pay.event.hub && pay.event.hub.topic) {
      if (pay.event.hub.topic === 'BIRTH_REGISTERED') {
        sendingUrl = MOSIP_BIRTH_PROXY_CALLBACK_URL
      } else if (pay.event.hub.topic === 'DEATH_REGISTERED') {
        sendingUrl = MOSIP_DEATH_PROXY_CALLBACK_URL
      } else {
        sendingUrl = ''
      }
    } else {
      logger.error('{"message":"Error Parsing event hub topic"}\n')
      return h
        .response('{"message":"Error Parsing event hub topic"}\n')
        .code(500)
    }
    let payId: string = ''
    try {
      const entries = pay.event.context[0].entry
      for (const entry of entries) {
        if (
          entry.resource.resourceType.toUpperCase() === 'Task'.toUpperCase()
        ) {
          payId = entry.resource.focus.reference.split('/')[1]
          break
        }
      }
      if (!payId) {
        return h.response().code(500)
      }
    } catch (e) {
      return h.response().code(500)
    }
    logger.info(`ID - ${payId}. Able to get txnId`)
    proxyCallback(payId, JSON.stringify(request.payload), sendingUrl)
  }

  return h.response().code(200)
}

async function proxyCallback(id: string, payload: string, sendingUrl: string) {
  let proxyRequest
  try {
    proxyRequest = encryptAndSign(id, payload)
  } catch (e) {
    logger.error(`Error encrypting and signing data: ${e.stack}`)
    return
  }

  logger.info(`Encryting Payload Complete. Here is the payload id : ${id}`)

  const authToken = await getMosipAuthToken(
    MOSIP_AUTH_URL,
    MOSIP_AUTH_CLIENT_ID,
    MOSIP_AUTH_CLIENT_SECRET,
    MOSIP_AUTH_USER,
    MOSIP_AUTH_PASS
  )
  if (authToken === undefined || authToken['access_token'] === undefined) {
    logger.error(
      `failed getting mosip auth token. response: ${JSON.stringify(authToken)}`
    )
    return
  }

  logger.info(`ID - ${id}. Received MOSIP Auth token`)

  const res = await fetch(sendingUrl, {
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
  // putting random thumbprint temporarily
  const thumbprint: string = forge.random.getBytesSync(THUMBPRINT_LENGTH)

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
    Buffer.from(
      IS_THUMBRPINT ? VERSION_RSA_2048 + thumbprint : VERSION_RSA_2048
    ),
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

  const digestSign = forge.md.sha512.create()
  digestSign.update(encryptedData.toString('binary'))
  const sign = opencrvsPrivateKey.sign(digestSign)

  return JSON.stringify({
    id: payId,
    requestTime: new Date().toISOString(),
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
    !(topic === 'BIRTH_REGISTERED' || topic === 'DEATH_REGISTERED')
  ) {
    throw new Error('Params incorrect')
  } else {
    return h.response({ challenge: decodeURIComponent(challenge) }).code(200)
  }
}

export async function getMosipAuthToken(
  url: string,
  clientId: string,
  clientSecret: string,
  username: string,
  password: string
) {
  if (!url) {
    return { access_token: 'Authorization' }
  }
  return await fetch(url, {
    method: 'POST',
    body: `client_id=${clientId}&client_secret=${clientSecret}&username=${username}&password=${password}&grant_type=password`,
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
}
