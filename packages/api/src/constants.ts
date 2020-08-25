export const HOST = process.env.HOST || 'localhost'
export const PORT = process.env.PORT || 4545
export const CERT_PUBLIC_KEY_PATH =
  (process.env.CERT_PUBLIC_KEY_PATH as string) ||
  '../../.secrets/public-key.pem'
