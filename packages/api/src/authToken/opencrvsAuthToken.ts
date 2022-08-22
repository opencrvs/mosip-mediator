import { resolve } from 'url'
import fetch from 'node-fetch'
import { logger } from '@api/logger'
import { AUTH_URL } from '@api/constants'

export async function verifyOpencrvsAuthToken(token: string): Promise<boolean> {
  if (!AUTH_URL) {
    return true
  }
  const valid = await fetch(resolve(AUTH_URL, 'verifyToken'), {
    method: 'POST',
    body: `token=${token}`,
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
  if (!valid && !valid['valid']) {
    return false
  } else {
    return valid['valid']
  }
}
