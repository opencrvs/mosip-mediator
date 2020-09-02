import * as Hapi from 'hapi'
import { logger } from '@api/logger'
// import * as Joi from 'joi'

interface IRequestParams {
  [key: string]: string
}

export async function webhooksHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) {
  logger.info(
    `webhooksHandler has been called with payload: ${request.payload}`
  )
  return h.response().code(200)
}

export async function subscriptionConfirmationHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) {
  const params = request.query as IRequestParams

  const mode = params['mode']
  const challenge = decodeURIComponent(params['challenge'])
  const topic = params['topic']

  logger.info(
    `subscriptionConfirmationHandler has been called with params: ${JSON.stringify(
      params
    )}`
  )
  if (
    !mode ||
    mode !== 'subscribe' ||
    !challenge ||
    !topic ||
    topic !== 'BIRTH_REGISTERED'
  ) {
    throw new Error('Params incorrect')
  } else {
    return h.response({ challenge }).code(200)
  }
}
