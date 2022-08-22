import * as Hapi from '@hapi/hapi'
import fetch from 'node-fetch'
import { logger } from '@api/logger'
import { MOSIP_GENERATE_RID_URL } from '@api/constants'
import { getMosipAuthToken } from '@api/authToken/mosipAuthToken'

export async function generateMosipRid(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
): Promise<string> {
  const authToken: string = await getMosipAuthToken()
  if (!authToken) {
    logger.error(
      `failed getting mosip auth token. response: ${JSON.stringify(authToken)}`
    )
    return ''
  }
  const res = (await fetch(MOSIP_GENERATE_RID_URL, {
    method: 'GET',
    headers: {
      cookie: `Authorization=${authToken}`
    }
  })
    .then(response => {
      return response.json()
    })
    .catch(error => {
      logger.error(`failed receiving rid from mosip: ${error.message}`)
      return undefined
    })) as string
  return res
}
