import * as fs from 'fs'
import * as util from 'util'
import { logger } from '@api/logger'

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

export const HOST = process.env.HOST || '0.0.0.0'
export const PORT = process.env.PORT || 4545

export const WEBHOOK_URL = process.env.WEBHOOK_URL || '' // Insert your webhook URL
export const AUTH_URL = process.env.AUTH_URL || '' // Insert the URL to your OpenCRVS auth service installation
export const CALLBACK_URL = process.env.CALLBACK_URL || '' // Insert your webhooks URL here for Verification Request and Event Notification
export const CLIENT_ID = get('CLIENT_ID') || (process.env.CLIENT_ID as string)
export const CLIENT_SECRET =
  get('CLIENT_SECRET') || (process.env.CLIENT_SECRET as string)
export const SHA_SECRET =
  get('SHA_SECRET') || (process.env.SHA_SECRET as string)
export const PROXY_CALLBACK_URL = process.env.PROXY_CALLBACK_URL || '' // Insert your URL here to which the event has to be proxied to
export const MOSIP_AUTH_URL = process.env.MOSIP_AUTH_URL || ''
export const MOSIP_AUTH_CLIENT = process.env.MOSIP_AUTH_CLIENT || ''
export const MOSIP_AUTH_USER = process.env.MOSIP_AUTH_USER || ''
export const MOSIP_AUTH_PASS = process.env.MOSIP_AUTH_PASS || ''

export const SIGN_ALGORITHM = process.env.SIGN_ALGORITHM || 'RSA-SHA256'
const MOSIP_PUBLIC_KEY_PATH =
  process.env.MOSIP_PUBLIC_KEY_PATH || '/certs/mnt/mosip-public.key'
const OPENCRVS_PRIV_KEY_PATH =
  process.env.OPENCRVS_PRIV_KEY_PATH || '/certs/mnt/opencrvs-priv.key'
if (!fs.existsSync(MOSIP_PUBLIC_KEY_PATH)) {
  logger.error(`Cannot find mosip public key at: ${MOSIP_PUBLIC_KEY_PATH}`)
  process.exit(1)
}
if (!fs.existsSync(OPENCRVS_PRIV_KEY_PATH)) {
  logger.error(`Cannot find opencrvs priv key at: ${OPENCRVS_PRIV_KEY_PATH}`)
  process.exit(1)
}
export const MOSIP_PUBLIC_KEY = fs.readFileSync(MOSIP_PUBLIC_KEY_PATH)
export const OPENCRVS_PRIV_KEY = fs.readFileSync(OPENCRVS_PRIV_KEY_PATH)
