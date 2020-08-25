import * as pino from 'pino'
export const logger = pino()
if (process.env.NODE_ENV === 'test') {
  logger.level = 'silent'
}
