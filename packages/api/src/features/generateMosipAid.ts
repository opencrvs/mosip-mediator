import * as Hapi from '@hapi/hapi'
import fetch from 'node-fetch'
import { logger } from '@api/logger'
import { MOSIP_GENERATE_AID_URL } from '@api/constants'
import { getMosipAuthToken } from '@api/authToken/mosipAuthToken'

export async function generateMosipAidReqHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
): Promise<string> {
  return await generateMosipAid()
}

export async function generateMosipAid(): Promise<string> {
  const authToken: string = await getMosipAuthToken()
  if (!authToken) {
    logger.error(
      `failed getting mosip auth token. response: ${JSON.stringify(authToken)}`
    )
    return ''
  }
  const res = (await fetch(MOSIP_GENERATE_AID_URL, {
    method: 'GET',
    headers: {
      cookie: `Authorization=${authToken}`
    }
  })
    .then(response => {
      return response.json()
    })
    .catch(error => {
      logger.error(`failed receiving Aid from mosip: ${error.message}`)
      return undefined
    })) as string
  return res
}
