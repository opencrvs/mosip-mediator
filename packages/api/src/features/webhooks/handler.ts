import * as Hapi from '@hapi/hapi'
import * as crypto from 'crypto'
import fetch from 'node-fetch'
import { logger } from '@api/logger'
import {
  PROXY_CALLBACK_URL,
  SIGN_ALGORITHM,
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

  proxyCallback(request)

  return h.response().code(200)
}

async function proxyCallback(request: Hapi.Request) {
  const encryptedData = crypto
    .publicEncrypt(MOSIP_PUBLIC_KEY, Buffer.from(request.payload.toString()))
    .toString('base64')
  const sign = crypto
    .sign(SIGN_ALGORITHM, Buffer.from(encryptedData), OPENCRVS_PRIV_KEY)
    .toString('base64')

  const proxyRequest = JSON.stringify({
    data: encryptedData,
    signature: sign
  })

  let authToken
  try {
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
        return Promise.reject(error)
      })
    if (authToken['access_token'] === undefined) {
      logger.error(
        `failed getting mosip auth token. response: ${JSON.stringify(
          authToken
        )}`
      )
      return
    }
  } catch (error) {
    logger.error(`failed getting mosip auth token. error: ${error.message}`)
    return
  }

  try {
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
        return Promise.reject(error)
      })
    logger.info(`Received Response From Mosip: ${res}`)
  } catch (error) {
    logger.error(`failed sending data to mosip: ${error.message}`)
    return
  }
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

export async function receiveNidHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) {
  return h.response().code(200)
}
