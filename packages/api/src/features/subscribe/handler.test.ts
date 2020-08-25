import { createServer } from '@api/index'
// import * as fetchAny from 'jest-fetch-mock'

// tslint:disable-next-line
// const fetch = fetchAny as any

describe('subscribe handler with valid payload', () => {
  let server: any

  beforeEach(async () => {
    server = await createServer()
  })

  it('subscribe handler should return 200', async () => {
    const res = await server.server.inject({
      method: 'POST',
      url: '/subscribe'
    })
    expect(res.statusCode).toBe(200)
  })
})
