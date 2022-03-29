import * as Hapi from '@hapi/hapi'
import {
  WEBHOOK_URL,
  AUTH_URL,
  CALLBACK_URL,
  CLIENT_ID,
  CLIENT_SECRET,
  SHA_SECRET
} from '@api/constants'
import fetch from 'node-fetch'
import { resolve } from 'url'
import { logger } from '@api/logger'

export default async function subscribeHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) {
  const authPayload = JSON.stringify({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET
  })

  logger.info(`authPayload: ${authPayload}`)
  const createToken = await fetch(
    resolve(AUTH_URL, 'authenticateSystemClient'),
    {
      method: 'POST',
      body: authPayload,
      headers: {
        'Content-Type': 'application/json'
      }
    }
  )
    .then(response => {
      return response.json()
    })
    .catch(error => {
      return Promise.reject(new Error(` request failed: ${error.message}`))
    })
  if (!createToken) {
    throw new Error('Cannot create token')
  }

  logger.info(`createToken: ${createToken}`)
  const subscriptionResponse = await fetch(WEBHOOK_URL, {
    method: 'POST',
    body: JSON.stringify({
      hub: {
        callback: CALLBACK_URL,
        mode: 'subscribe',
        secret: SHA_SECRET,
        topic: 'BIRTH_REGISTERED'
      }
    }),
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${createToken.token}`
    }
  })
    .then(response => {
      return response
    })
    .catch(error => {
      return Promise.reject(new Error(` request failed: ${error.message}`))
    })
  if (!subscriptionResponse) {
    throw new Error('Cannot get response from subscription process')
  }
  return h.response().code(202)
}
