import fetch from 'node-fetch'
import { OPENHIM_MEDIATOR_URL } from '@api/constants'
import { logger } from '@api/logger'
import { getOpencrvsAuthToken } from '@api/authToken/opencrvsAuthToken'

export async function putDataToOpenHIMMediator(
  authToken: string,
  data: string
) {
  try {
    const openHIMMediatorResponse = await fetch(OPENHIM_MEDIATOR_URL, {
      method: 'POST',
      body: data,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`
      }
    })
      .then(response => {
        return response
      })
      .catch(error => {
        return Promise.reject(new Error(` request failed: ${error.message}`))
      })
    if (!openHIMMediatorResponse) {
      throw new Error('Cannot get response from OpenHIM Mediator')
    }
  } catch (error) {
    logger.error(error)
  }
}

export async function putDataToOpenHIMMediatorWithToken(data: string) {
  const authToken = await getOpencrvsAuthToken()
  if (!authToken) {
    throw new Error('Cannot create token')
  }
  return await putDataToOpenHIMMediator(authToken, data)
}
