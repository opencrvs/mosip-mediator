import * as fs from 'fs'
import * as util from 'util'

const get = (secret: string) => {
  try {
    // Swarm secret are accessible within tmpfs /run/secrets dir
    return fs
      .readFileSync(util.format('/run/secrets/%s', secret), 'utf8')
      .trim()
  } catch (e) {
    return false
  }
}

export const HOST = process.env.HOST || 'localhost'
export const PORT = process.env.PORT || 4545
export const CERT_PUBLIC_KEY_PATH =
  (process.env.CERT_PUBLIC_KEY_PATH as string) ||
  '../../.secrets/public-key.pem'
export const WEBHOOK_URL =
  process.env.WEBHOOK_URL ||
  'https://webhooks.opencrvs-staging.jembi.org/webhooks'
export const AUTH_URL =
  process.env.AUTH_URL || 'https://auth.opencrvs-staging.jembi.org/'

export const CLIENT_ID = get('CLIENT_ID') || (process.env.CLIENT_ID as string)
export const CLIENT_SECRET =
  get('CLIENT_SECRET') || (process.env.CLIENT_SECRET as string)
export const SHA_SECRET =
  get('SHA_SECRET') || (process.env.SHA_SECRET as string)
