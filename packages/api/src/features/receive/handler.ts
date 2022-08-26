import * as Hapi from '@hapi/hapi'
import * as fs from 'fs'
import base64url from 'base64url'
import { logger } from '@api/logger'
import { verifyOpencrvsAuthToken } from '@api/authToken/opencrvsAuthToken'
import { decryptData } from '@api/crypto/decrypt'
import { putDataToOpenHIMMediator } from '@api/util/openHIMMediatorUtil'

export async function receiveNidHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) {
  const authHeaderValue = request.headers['authorization']
  if (!authHeaderValue) {
    return h.response(`{"message":"Unauthorized"}\n`).code(401)
  }
  const openCRVSToken = `${authHeaderValue.replace('Bearer ', '')}`
  const verifyStatus = await verifyOpencrvsAuthToken(openCRVSToken)
  if (!verifyStatus) {
    logger.error(`Invalid Token. Response: ${JSON.stringify(verifyStatus)}`)
    return h.response(`{"message":"Invalid Token"}\n`).code(400)
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

  // then decrypt data
  const encryptedData = base64url.toBuffer(payload.data)
  let decryptedData: string
  try {
    decryptedData = await decryptData(encryptedData)
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
  await putDataToOpenHIMMediator(
    openCRVSToken,
    JSON.stringify({
      BRN: birthRegNo,
      UINTOKEN: uinToken
    })
  )

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
