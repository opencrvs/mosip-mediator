import * as Pino from 'hapi-pino'
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
    }
  ]

  return plugins
}
