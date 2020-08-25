import * as Hapi from 'hapi'
import { logger } from '@api/logger'
/*import * as Joi from 'joi'

import fetch from 'node-fetch'
import { resolve } from 'url'*/

export default async function subscribeHandler(
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) {
  logger.info(`subscribeHandler has been called`)
  return h.response().code(200)
}
