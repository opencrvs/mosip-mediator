import * as Hapi from 'hapi'
import { logger } from '@api/logger'
import { WEBHOOK_URL, AUTH_URL, CLIENT_ID, CLIENT_SECRET } from '@api/constants'
import fetch from 'node-fetch'
import { resolve } from 'url'

export default async function subscribeHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) {
  logger.info(`subscribeHandler has been called`)

  const createToken = await fetch(resolve(AUTH_URL, 'authenticateSystem'), {
    method: 'POST',
    body: JSON.stringify({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET
    }),
    headers: {
      'Content-Type': 'application/json'
    }
  })
    .then(response => {
      return response.json()
    })
    .catch(error => {
      return Promise.reject(new Error(` request failed: ${error.message}`))
    })
  if (!createToken) {
    throw new Error('Cannot create token')
  }
  try {
    const webhookSubscriptionResponse = await fetch(WEBHOOK_URL, {
      method: 'POST',
      body: JSON.stringify({
        address: 'https://api.mosip.yumeteki.io/webhooks',
        trigger: 'BIRTH_REGISTERED'
      }),
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${createToken.token}`
      }
    })
      .then(response => {
        return response.json()
      })
      .catch(error => {
        return Promise.reject(new Error(` request failed: ${error.message}`))
      })
    return h.response(webhookSubscriptionResponse).code(200)
  } catch (err) {
    throw Error(err.statusText)
  }
}
