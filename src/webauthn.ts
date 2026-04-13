import { Hono } from 'hono'
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server'
import type { Env, WebAuthnRegistration } from './types'
import { base64urlEncode } from './crypto'

type HonoEnv = { Bindings: Env }

export function webauthnRoutes() {
  const routes = new Hono<HonoEnv>()

  // Generate registration options
  routes.post('/webauthn/register/options', async (c) => {
    const origin = c.env.ORIGIN
    const rpID = new URL(origin).hostname
    const rpName = c.env.AGENT_NAME

    const body = await c.req.json<{ username: string }>()
    if (!body.username) {
      return c.json({ error: 'missing username' }, 400)
    }

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userName: body.username,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'discouraged',
      },
    })

    // Store challenge for verification
    const challengeKey = `challenge:${options.challenge}`
    await c.env.WEBAUTHN_KV.put(challengeKey, JSON.stringify({
      username: body.username,
      type: 'registration',
    }), { expirationTtl: 300 })

    return c.json(options)
  })

  // Verify registration
  routes.post('/webauthn/register/verify', async (c) => {
    const origin = c.env.ORIGIN
    const rpID = new URL(origin).hostname

    const body = await c.req.json<{ response: any; challenge: string }>()

    const challengeData = await c.env.WEBAUTHN_KV.get(`challenge:${body.challenge}`, 'json') as any
    if (!challengeData || challengeData.type !== 'registration') {
      return c.json({ error: 'invalid challenge' }, 400)
    }

    try {
      const verification = await verifyRegistrationResponse({
        response: body.response,
        expectedChallenge: body.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: false,
      })

      if (!verification.verified || !verification.registrationInfo) {
        return c.json({ error: 'verification failed' }, 400)
      }

      const { credential } = verification.registrationInfo
      const registration: WebAuthnRegistration = {
        credentialID: credential.id,
        credentialPublicKey: base64urlEncode(credential.publicKey),
        counter: credential.counter,
        transports: body.response.response?.transports,
      }

      // Store credential indexed by credential ID for discoverable login
      const username = challengeData.username
      await c.env.WEBAUTHN_KV.put(`cred:${credential.id}`, JSON.stringify({
        ...registration,
        username,
      }))

      // Also store by username for listing user's credentials
      const existingCreds = await c.env.WEBAUTHN_KV.get(`creds:${username}`, 'json') as WebAuthnRegistration[] || []
      existingCreds.push(registration)
      await c.env.WEBAUTHN_KV.put(`creds:${username}`, JSON.stringify(existingCreds))

      // Clean up challenge
      await c.env.WEBAUTHN_KV.delete(`challenge:${body.challenge}`)

      // Create session
      const sessionId = generateSessionId()
      await c.env.WEBAUTHN_KV.put(`session:${sessionId}`, JSON.stringify({
        username,
        credentialID: registration.credentialID,
        createdAt: Date.now(),
      }), { expirationTtl: 3600 })

      return c.json({ verified: true, sessionId })
    } catch (err) {
      return c.json({ error: (err as Error).message }, 400)
    }
  })

  // Generate authentication options (discoverable — no username needed)
  routes.post('/webauthn/login/options', async (c) => {
    const rpID = new URL(c.env.ORIGIN).hostname

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: [],
      userVerification: 'discouraged',
    })

    await c.env.WEBAUTHN_KV.put(`challenge:${options.challenge}`, JSON.stringify({
      type: 'authentication',
    }), { expirationTtl: 300 })

    return c.json(options)
  })

  // Verify authentication (discoverable — look up credential by ID)
  routes.post('/webauthn/login/verify', async (c) => {
    const origin = c.env.ORIGIN
    const rpID = new URL(origin).hostname

    const body = await c.req.json<{ response: any; challenge: string }>()

    const challengeData = await c.env.WEBAUTHN_KV.get(`challenge:${body.challenge}`, 'json') as any
    if (!challengeData || challengeData.type !== 'authentication') {
      return c.json({ error: 'invalid challenge' }, 400)
    }

    // Look up credential by ID (stored during registration)
    const credData = await c.env.WEBAUTHN_KV.get(`cred:${body.response.id}`, 'json') as (WebAuthnRegistration & { username: string }) | null
    if (!credData) {
      return c.json({ error: 'credential not found' }, 400)
    }

    const { username, ...credential } = credData

    try {
      const verification = await verifyAuthenticationResponse({
        response: body.response,
        expectedChallenge: body.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: false,
        credential: {
          id: credential.credentialID,
          publicKey: base64urlDecode(credential.credentialPublicKey) as Uint8Array<ArrayBuffer>,
          counter: credential.counter,
          transports: credential.transports as any | undefined,
        },
      })

      if (!verification.verified) {
        return c.json({ error: 'verification failed' }, 400)
      }

      // Update counter
      credential.counter = verification.authenticationInfo.newCounter
      await c.env.WEBAUTHN_KV.put(`cred:${body.response.id}`, JSON.stringify({ ...credential, username }))

      // Clean up challenge
      await c.env.WEBAUTHN_KV.delete(`challenge:${body.challenge}`)

      // Create session
      const sessionId = generateSessionId()
      await c.env.WEBAUTHN_KV.put(`session:${sessionId}`, JSON.stringify({
        username,
        credentialID: credential.credentialID,
        createdAt: Date.now(),
      }), { expirationTtl: 3600 })

      return c.json({ verified: true, sessionId, username })
    } catch (err) {
      return c.json({ error: (err as Error).message }, 400)
    }
  })

  return routes
}

function generateSessionId(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return base64urlEncode(bytes)
}

function base64urlDecode(str: string): Uint8Array {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4)
  const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}
