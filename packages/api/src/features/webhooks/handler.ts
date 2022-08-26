import * as Hapi from '@hapi/hapi'
import fetch from 'node-fetch'
import {
  MOSIP_BIRTH_PROXY_CALLBACK_URL,
  MOSIP_DEATH_PROXY_CALLBACK_URL
} from '@api/constants'
import { logger } from '@api/logger'
import { encryptAndSign } from '@api/crypto/encrypt'
import { getMosipAuthToken } from '@api/authToken/mosipAuthToken'
import { generateMosipAid } from '@api/features/generateMosipAid'
import { putDataToOpenHIMMediatorWithToken } from '@api/util/openHIMMediatorUtil'

interface IRequestParams {
  [key: string]: string
}

export async function webhooksHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) {
  logger.info(`webhooksHandler has been called with some payload`)

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
    let isAIDSet: boolean = false
    const mosipAid: string = await generateMosipAid()
    let BRN: string = ''
    try {
      const entries = pay.event.context[0].entry
      for (const entry of entries) {
        if (
          entry.resource.resourceType.toUpperCase() === 'Task'.toUpperCase()
        ) {
          payId = entry.resource.focus.reference.split('/')[1]
        } else if (
          entry.resource.resourceType.toUpperCase() === 'Patient'.toUpperCase()
        ) {
          for (const id of entry.resource.identifier) {
            if (id.type === 'BIRTH_REGISTRATION_NUMBER') {
              BRN = id.value
              break
            }
          }
          entry.resource.identifier.push({ type: 'MOSIP_AID', value: mosipAid })
          isAIDSet = true
        }
        if (payId && isAIDSet) {
          break
        }
      }
      if (!payId) {
        return h.response().code(500)
      }
    } catch (e) {
      return h.response().code(500)
    }
    await putDataToOpenHIMMediatorWithToken(
      JSON.stringify({
        BRN,
        MOSIP_AID: mosipAid
      })
    )
    logger.info(`ID - ${payId}. Able to get txnId`)
    proxyCallback(payId, JSON.stringify(pay), sendingUrl)
  }

  return h.response().code(200)
}

async function proxyCallback(id: string, payload: string, sendingUrl: string) {
  let proxyRequest: string
  try {
    const encryptionResponse = encryptAndSign(payload)
    proxyRequest = JSON.stringify({
      id,
      requestTime: new Date().toISOString(),
      data: encryptionResponse.data,
      signature: encryptionResponse.signature
    })
  } catch (e) {
    logger.error(`Error encrypting and signing data: ${e.stack}`)
    return
  }

  logger.info(`Encryting Payload Complete. Here is the payload id : ${id}`)

  const authToken = await getMosipAuthToken()
  if (!authToken) {
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
      cookie: `Authorization=${authToken}`
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
