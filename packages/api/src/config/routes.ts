import subscribeHandler from '@api/features/subscribe/handler'
import {
  webhooksHandler,
  subscriptionConfirmationHandler
} from '@api/features/webhooks/handler'

export const getRoutes = () => {
  const routes = [
    // add ping route by default for health check
    {
      method: 'GET',
      path: '/ping',
      handler: (request: any, h: any) => {
        // Perform any health checks and return true or false for success prop
        return {
          success: true
        }
      },
      config: {
        auth: false,
        tags: ['api'],
        description: 'Health check endpoint'
      }
    },
    {
      method: 'POST',
      path: '/subscribe',
      handler: subscribeHandler,
      config: {
        auth: false,
        tags: ['api']
      }
    },
    {
      method: 'POST',
      path: '/webhooks',
      handler: webhooksHandler,
      config: {
        auth: false,
        tags: ['api']
      }
    },
    {
      method: 'GET',
      path: '/webhooks',
      handler: subscriptionConfirmationHandler,
      config: {
        auth: false,
        tags: ['api']
      }
    }
  ]
  return routes
}
