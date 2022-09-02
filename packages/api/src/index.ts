// tslint:disable-next-line no-var-requires
require('app-module-path').addPath(require('path').join(__dirname, '../'))

import * as Hapi from '@hapi/hapi'
import { HOST, PORT, DEFAULT_TIMEOUT } from '@api/constants'
import getPlugins from '@api/config/plugins'
import { getRoutes } from '@api/config/routes'

export async function createServer() {
  const server = new Hapi.Server({
    host: HOST,
    port: PORT,
    routes: {
      cors: { origin: ['*'] },
      payload: { maxBytes: 52428800, timeout: DEFAULT_TIMEOUT }
    }
  })

  await server.register(getPlugins())

  const routes = getRoutes()
  server.route(routes)

  async function start() {
    await server.start()
    server.log('info', `server started on ${HOST}:${PORT}`)
  }

  async function stop() {
    await server.stop()
    server.log('info', 'server stopped')
  }

  return { server, start, stop }
}

if (require.main === module) {
  createServer().then(server => server.start())
}
