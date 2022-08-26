import fetch from 'node-fetch'
import { logger } from '@api/logger'
import {
  MOSIP_AUTH_URL,
  MOSIP_AUTH_CLIENT_ID,
  MOSIP_AUTH_CLIENT_SECRET,
  MOSIP_AUTH_USER,
  MOSIP_AUTH_PASS
} from '@api/constants'

export async function getMosipAuthToken(): Promise<string> {
  if (!MOSIP_AUTH_URL) {
    return 'Authorization'
  }
  const token = await fetch(MOSIP_AUTH_URL, {
    method: 'POST',
    body: `client_id=${MOSIP_AUTH_CLIENT_ID}&client_secret=${MOSIP_AUTH_CLIENT_SECRET}&username=${MOSIP_AUTH_USER}&password=${MOSIP_AUTH_PASS}&grant_type=password`,
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
  if (!token || !token['access_token']) {
    return ''
  } else {
    return token['access_token']
  }
}
