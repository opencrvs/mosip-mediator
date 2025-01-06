import * as Hapi from '@hapi/hapi'
import { logger } from '@api/logger'

interface IRequestParams {
  [key: string]: string
}

export async function webhooksHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) {
  logger.info(`webhooksHandler has been called with some payload`)

  if (request.payload) {
    console.log(JSON.stringify(request.payload))
  }

  return h.response().code(200)
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
