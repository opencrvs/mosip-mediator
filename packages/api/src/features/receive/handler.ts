import * as Hapi from '@hapi/hapi'
// import * as crypto from 'crypto'
import fetch from 'node-fetch'
import { resolve } from 'url'
import { logger } from '@api/logger'
import { AUTH_URL } from '@api/constants'

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
  // const payload = JSON.parse(JSON.stringify(request.payload))
  // const birthRegNo = payload.event.data.opencrvsId
  // const encryptedData = payload.event.data.credential
  // const signature = payload.event.data.proof.signature
  //
  // // crypto.veri
  //
  // logger.info(`here received encryted data: ${encryptedData}`)
}
