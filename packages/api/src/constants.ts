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
export const CLIENT_ID = process.env.CLIENT_ID || ''
export const CLIENT_SECRET = process.env.CLIENT_SECRET || ''
