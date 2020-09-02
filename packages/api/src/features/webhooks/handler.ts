import * as Hapi from 'hapi'
import { logger } from '@api/logger'
// import * as Joi from 'joi'

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
  const mode = request.params.mode
  const challenge = request.params.challenge
  // TODO: verifyToken to be implemented
  // const verifyToken = request.params.verifyToken
  logger.info(
    `subscriptionConfirmationHandler has been called with params: ${JSON.stringify(
      request.params
    )}`
  )
  if (!mode || mode !== 'subscribe' || !challenge) {
    throw new Error('Params incorrect')
  } else {
    return h.response({ challenge }).code(200)
  }
}
