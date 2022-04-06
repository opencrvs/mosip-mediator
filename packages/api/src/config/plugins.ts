import * as Pino from 'hapi-pino'
import * as Inert from '@hapi/inert'
import { logger } from '@api/logger'

export default function getPlugins() {
  const plugins: any[] = [
    {
      plugin: Pino,
      options: {
        prettyPrint: false,
        logPayload: false,
        instance: logger
      }
    },
    {
      plugin: Inert
    }
  ]

  return plugins
}
