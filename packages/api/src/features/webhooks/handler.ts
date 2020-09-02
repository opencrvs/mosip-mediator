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
  const challenge = params['challenge']
  // TODO: verifyToken to be implemented
  // const verifyToken = request.params.verifyToken
  logger.info(
    `subscriptionConfirmationHandler has been called with params: ${JSON.stringify(
      params
    )}`
  )
  if (!mode || mode !== 'subscribe' || !challenge) {
    throw new Error('Params incorrect')
  } else {
    return h.response({ challenge }).code(200)
  }
}
