import * as Hapi from 'hapi'
import { logger } from '@api/logger'
// import * as Joi from 'joi'

export default async function webhooksHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) {
  logger.info(
    `webhooksHandler has been called with payload: ${request.payload}`
  )
}
