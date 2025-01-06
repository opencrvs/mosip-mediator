import * as fs from 'fs'
import { logger } from '@api/logger'

export const HOST = process.env.HOST || '0.0.0.0'
export const PORT = process.env.PORT || 4545
export const WEBHOOK_URL = process.env.WEBHOOK_URL || 'http://localhost:2525/webhooks' // Insert your webhook URL
export const AUTH_URL = process.env.AUTH_URL || 'http://localhost:4040' // Insert the URL to your OpenCRVS auth service installation
export const CALLBACK_URL = process.env.CALLBACK_URL || 'http://localhost:4545/webhooks' // Insert your webhooks URL here for Verification Request and Event Notification
export const OPENHIM_MEDIATOR_URL = process.env.OPENHIM_MEDIATOR_URL || '' // Insert your OpenCRVS Country Configuration OpenHIM Mediator URL
export const CLIENT_ID = process.env.CLIENT_ID as string || 'a87be4c6-9fc3-40a7-8ef5-c6033f8116af'
export const CLIENT_SECRET = process.env.CLIENT_SECRET as string || 'a1c755e9-2165-4898-9248-d72cf82ffb5d'
export const SHA_SECRET = process.env.SHA_SECRET as string || '25eac0f5-03f8-4e07-ba25-a6fd0b7012f8'
export const MOSIP_BIRTH_PROXY_CALLBACK_URL =
  process.env.MOSIP_BIRTH_PROXY_CALLBACK_URL || '' // Insert your URL here to which the birth event has to be proxied to
export const MOSIP_DEATH_PROXY_CALLBACK_URL =
  process.env.MOSIP_DEATH_PROXY_CALLBACK_URL || '' // Insert your URL here to which the death event has to be proxied to
export const MOSIP_GENERATE_AID_URL = process.env.MOSIP_GENERATE_AID_URL || ''
export const MOSIP_AUTH_URL = process.env.MOSIP_AUTH_URL || ''
export const MOSIP_AUTH_CLIENT_ID = process.env.MOSIP_AUTH_CLIENT_ID || ''
export const MOSIP_AUTH_CLIENT_SECRET =
  process.env.MOSIP_AUTH_CLIENT_SECRET || ''
export const MOSIP_AUTH_USER = process.env.MOSIP_AUTH_USER || ''
export const MOSIP_AUTH_PASS = process.env.MOSIP_AUTH_PASS || ''

export const KEY_SPLITTER = '#KEY_SPLITTER#'
export const VERSION_RSA_2048 = 'VER_R2'
// export const SIGN_ALGORITHM = 'RSA-SHA256'
export const SYMMETRIC_ALGORITHM = 'AES-GCM'
export const ASYMMETRIC_ALGORITHM = 'RSA-OAEP'
export const SYMMETRIC_KEY_SIZE: number = 32
export const NONCE_SIZE: number = 12
export const AAD_SIZE: number = 32
export const GCM_TAG_LENGTH: number = 16

export const IS_THUMBRPINT: boolean =
  process.env.IS_THUMBRPINT === 'false' ? false : true
export const THUMBPRINT_LENGTH: number = 32

// export const ASYMMETRIC_ENCRYPT_ALGORITHM = 'RSA/ECB/PKCS1Padding'
const MOSIP_PUBLIC_KEY_PATH =
  process.env.MOSIP_PUBLIC_KEY_PATH || '/certs/mnt/mosip-public.key'
const OPENCRVS_PRIV_KEY_PATH =
  process.env.OPENCRVS_PRIV_KEY_PATH || '/certs/mnt/opencrvs-priv.key'
if (!fs.existsSync(MOSIP_PUBLIC_KEY_PATH)) {
  logger.error(`Cannot find mosip public key at: ${MOSIP_PUBLIC_KEY_PATH}`)
  // process.exit(1)
}
if (!fs.existsSync(OPENCRVS_PRIV_KEY_PATH)) {
  logger.error(`Cannot find opencrvs priv key at: ${OPENCRVS_PRIV_KEY_PATH}`)
  // process.exit(1)
}
/*export const MOSIP_PUBLIC_KEY: string = fs
  .readFileSync(MOSIP_PUBLIC_KEY_PATH)
  .toString('utf8')
export const OPENCRVS_PRIV_KEY: string = fs
  .readFileSync(OPENCRVS_PRIV_KEY_PATH)
  .toString('utf8')
*/
export const CARDS_PATH_PREFIX = process.env.CARDS_PATH_PREFIX || '' // trailing slash must not be present. example: "/mosip-mediator"
export const DEFAULT_TIMEOUT = 600000
