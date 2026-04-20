import { describe, it, expect, beforeAll, vi } from 'vitest'
import { webcrypto } from 'node:crypto'
import { fetch as sigFetch } from '@hellocoop/httpsig'
import { decodeJWTPayload } from '../src/crypto'

beforeAll(() => {
  if (!(globalThis as any).crypto) {
    ;(globalThis as any).crypto = webcrypto
  }
})

// ── Test fixtures ──

async function makeSigningKeyJson(): Promise<string> {
  const kp = await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair
  const jwk = await webcrypto.subtle.exportKey('jwk', kp.privateKey)
  return JSON.stringify(jwk)
}

async function makeEphemeralPublicJwk(): Promise<JsonWebKey> {
  const kp = await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair
  return await webcrypto.subtle.exportKey('jwk', kp.publicKey)
}

class InMemoryKV {
  private store = new Map<string, string>()
  async get(key: string, type?: 'json'): Promise<unknown> {
    const v = this.store.get(key)
    if (!v) return null
    return type === 'json' ? JSON.parse(v) : v
  }
  async put(key: string, value: string): Promise<void> {
    this.store.set(key, value)
  }
  async delete(key: string): Promise<void> {
    this.store.delete(key)
  }
}

async function makeEnv(): Promise<{ env: any; kv: InMemoryKV }> {
  const kv = new InMemoryKV()
  const env = {
    ORIGIN: 'https://playground.test',
    AGENT_NAME: 'test-agent',
    SIGNING_KEY: await makeSigningKeyJson(),
    WEBAUTHN_KV: kv,
  }
  return { env, kv }
}

// Import the app fresh; webauthn routes pull in @simplewebauthn/server which
// is fine in Node.
async function loadApp() {
  const mod = await import('../src/index')
  return mod.default
}

// ── Well-known endpoints ──

describe('GET /.well-known/aauth-agent.json', () => {
  it('returns issuer and endpoints derived from ORIGIN', async () => {
    const app = await loadApp()
    const { env } = await makeEnv()
    const res = await app.request('/.well-known/aauth-agent.json', {}, env)
    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.issuer).toBe('https://playground.test')
    expect(body.jwks_uri).toBe('https://playground.test/.well-known/jwks.json')
    expect(body.callback_endpoint).toBe('https://playground.test/callback')
    expect(body.login_endpoint).toBe('https://playground.test/login')
    expect(body.client_name).toBe('test-agent')
    expect(body.localhost_callback_allowed).toBe(true)
  })
})

describe('GET /.well-known/aauth-resource.json', () => {
  it('returns authorization_endpoint and scope descriptions', async () => {
    const app = await loadApp()
    const { env } = await makeEnv()
    const res = await app.request('/.well-known/aauth-resource.json', {}, env)
    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.issuer).toBe('https://playground.test')
    expect(body.authorization_endpoint).toBe('https://playground.test/authorize')
    expect(body.scope_descriptions).toMatchObject({
      openid: expect.any(String),
      profile: expect.any(String),
      email: expect.any(String),
      phone: expect.any(String),
    })
  })
})

describe('GET /.well-known/jwks.json', () => {
  it('returns a JWKS with the signing public key (no private material)', async () => {
    const app = await loadApp()
    const { env } = await makeEnv()
    const res = await app.request('/.well-known/jwks.json', {}, env)
    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.keys).toHaveLength(1)
    const key = body.keys[0]
    expect(key.kty).toBe('OKP')
    expect(key.crv).toBe('Ed25519')
    expect(key.x).toBeDefined()
    expect(key.kid).toBeDefined()
    expect(key.d).toBeUndefined()
    // Must declare verify (not sign) so strict verifiers like jose.importJWK accept it
    expect(key.key_ops).toEqual(['verify'])
    expect(key.ext).toBeUndefined()
  })
})

// ── Session check ──

describe('GET /session', () => {
  it('returns 401 when no session header', async () => {
    const app = await loadApp()
    const { env } = await makeEnv()
    const res = await app.request('/session', {}, env)
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ valid: false })
  })

  it('returns 401 when session not in KV', async () => {
    const app = await loadApp()
    const { env } = await makeEnv()
    const res = await app.request('/session', {
      headers: { 'X-Session-Id': 'missing' },
    }, env)
    expect(res.status).toBe(401)
  })

  it('returns valid + username when session exists', async () => {
    const app = await loadApp()
    const { env, kv } = await makeEnv()
    await kv.put('session:abc', JSON.stringify({ username: 'alice' }))
    const res = await app.request('/session', {
      headers: { 'X-Session-Id': 'abc' },
    }, env)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ valid: true, username: 'alice' })
  })
})

// ── Token issuance ──

describe('POST /token', () => {
  it('rejects without session', async () => {
    const app = await loadApp()
    const { env } = await makeEnv()
    const res = await app.request('/token', { method: 'POST' }, env)
    expect(res.status).toBe(401)
  })

  it('rejects without ephemeral_jwk', async () => {
    const app = await loadApp()
    const { env, kv } = await makeEnv()
    await kv.put('session:s1', JSON.stringify({ username: 'alice' }))
    const res = await app.request('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': 's1' },
      body: JSON.stringify({}),
    }, env)
    expect(res.status).toBe(400)
  })

  it('issues an aa-agent+jwt with cnf.jwk and 1h expiry', async () => {
    const app = await loadApp()
    const { env, kv } = await makeEnv()
    await kv.put('session:s1', JSON.stringify({ username: 'alice' }))
    const ephemeral = await makeEphemeralPublicJwk()

    const res = await app.request('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': 's1' },
      body: JSON.stringify({ ephemeral_jwk: ephemeral }),
    }, env)

    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.expires_in).toBe(3600)
    expect(body.agent_id).toBe('aauth:playground@playground.test')
    expect(body.agent_token).toBeDefined()

    const payload = decodeJWTPayload(body.agent_token)
    expect(payload.iss).toBe('https://playground.test')
    expect(payload.sub).toBe('aauth:playground@playground.test')
    expect(payload.dwk).toBe('aauth-agent.json')
    // cnf.jwk is sanitized to RFC 7638 required members (kty, crv, x for OKP).
    // WebCrypto-inserted fields like key_ops, ext, alg are stripped.
    expect((payload.cnf as any).jwk).toEqual({
      kty: ephemeral.kty,
      crv: ephemeral.crv,
      x: ephemeral.x,
    })
    expect(payload.exp as number).toBe((payload.iat as number) + 3600)
  })

  it('honors agent_local override in subject', async () => {
    const app = await loadApp()
    const { env, kv } = await makeEnv()
    await kv.put('session:s1', JSON.stringify({ username: 'alice' }))
    const ephemeral = await makeEphemeralPublicJwk()
    const res = await app.request('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': 's1' },
      body: JSON.stringify({ ephemeral_jwk: ephemeral, agent_local: 'custom' }),
    }, env)
    const body = await res.json() as any
    expect(body.agent_id).toBe('aauth:custom@playground.test')
  })
})

// ── Authorize ──

describe('POST /authorize', () => {
  // The authority that app.request() constructs for the Request URL. Signing
  // must match so the server's httpsig verify sees the same value on the
  // @authority component.
  const TEST_URL = 'http://localhost/authorize'

  // Mint an agent_token + keep the full ephemeral keypair (private + public)
  // so we can sign RFC 9421 requests against /authorize.
  async function mintAgentTokenWithKey(app: any, env: any, kv: InMemoryKV) {
    await kv.put('session:s1', JSON.stringify({ username: 'alice' }))
    const kp = await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair
    const publicJwk = await webcrypto.subtle.exportKey('jwk', kp.publicKey)
    const privateJwk = await webcrypto.subtle.exportKey('jwk', kp.privateKey)
    const res = await app.request('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': 's1' },
      body: JSON.stringify({ ephemeral_jwk: publicJwk }),
    }, env)
    const body = await res.json() as any
    return { agentToken: body.agent_token, publicJwk, privateJwk }
  }

  // Produce the header map a signed POST /authorize request carries.
  async function signedHeaders(bodyJSON: string, agentToken: string, privateJwk: JsonWebKey): Promise<Record<string, string>> {
    const dry = await sigFetch(TEST_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: bodyJSON,
      signingKey: privateJwk,
      signatureKey: { type: 'jwt', jwt: agentToken },
      components: ['@method', '@authority', '@path', 'content-type', 'signature-key'],
      dryRun: true,
    }) as { headers: Headers }
    const out: Record<string, string> = {}
    dry.headers.forEach((v, k) => { out[k] = v })
    return out
  }

  it('rejects missing required fields', async () => {
    const app = await loadApp()
    const { env, kv } = await makeEnv()
    const { agentToken, privateJwk } = await mintAgentTokenWithKey(app, env, kv)
    const body = JSON.stringify({ ps: 'https://ps.test' })
    const headers = await signedHeaders(body, agentToken, privateJwk)
    const res = await app.request('/authorize', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(400)
  })

  it('rejects when Signature-Key header is missing', async () => {
    const app = await loadApp()
    const { env } = await makeEnv()
    const res = await app.request('/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ps: 'https://ps.test', scope: 'openid' }),
    }, env)
    expect(res.status).toBe(401)
    expect((await res.json() as any).error).toMatch(/signature verification failed/i)
  })

  it('rejects invalid agent_token', async () => {
    const app = await loadApp()
    const { env } = await makeEnv()
    const res = await app.request('/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Signature-Key': 'sig=jwt;jwt="not.a.jwt"' },
      body: JSON.stringify({ ps: 'https://ps.test', scope: 'openid' }),
    }, env)
    expect(res.status).toBe(401)
  })

  it('rejects when the httpsig is signed by a key other than the one in cnf.jwk', async () => {
    const app = await loadApp()
    const { env, kv } = await makeEnv()
    const { agentToken } = await mintAgentTokenWithKey(app, env, kv)
    // Sign with a DIFFERENT private key so the cnf.jwk → public key doesn't
    // verify the signature. This is the key guarantee full httpsig gives us
    // over the old JWT-only check.
    const attackerKp = await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair
    const attackerPriv = await webcrypto.subtle.exportKey('jwk', attackerKp.privateKey)
    const body = JSON.stringify({ ps: 'https://ps.test', scope: 'openid' })
    const headers = await signedHeaders(body, agentToken, attackerPriv)
    const res = await app.request('/authorize', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(401)
    expect((await res.json() as any).error).toMatch(/signature verification failed/i)
  })

  it('rejects non-HTTPS PS URL', async () => {
    const app = await loadApp()
    const { env, kv } = await makeEnv()
    const { agentToken, privateJwk } = await mintAgentTokenWithKey(app, env, kv)
    const body = JSON.stringify({ ps: 'http://ps.test', scope: 'openid' })
    const headers = await signedHeaders(body, agentToken, privateJwk)
    const res = await app.request('/authorize', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(400)
    expect((await res.json() as any).error).toMatch(/HTTPS/)
  })

  it('returns 502 when PS metadata fetch fails', async () => {
    const app = await loadApp()
    const { env, kv } = await makeEnv()
    const { agentToken, privateJwk } = await mintAgentTokenWithKey(app, env, kv)
    const body = JSON.stringify({ ps: 'https://ps.test', scope: 'openid' })
    const headers = await signedHeaders(body, agentToken, privateJwk)
    vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 404 })))
    const res = await app.request('/authorize', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(502)
    vi.unstubAllGlobals()
  })

  it('returns 502 when PS metadata is missing required fields', async () => {
    const app = await loadApp()
    const { env, kv } = await makeEnv()
    const { agentToken, privateJwk } = await mintAgentTokenWithKey(app, env, kv)
    const body = JSON.stringify({ ps: 'https://ps.test', scope: 'openid' })
    const headers = await signedHeaders(body, agentToken, privateJwk)
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ issuer: 'https://ps.test' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })))
    const res = await app.request('/authorize', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(502)
    expect((await res.json() as any).error).toMatch(/missing required/)
    vi.unstubAllGlobals()
  })

  it('issues an aa-resource+jwt with correct claims when PS metadata is valid', async () => {
    const app = await loadApp()
    const { env, kv } = await makeEnv()
    const { agentToken, publicJwk, privateJwk } = await mintAgentTokenWithKey(app, env, kv)

    const psMetadata = {
      issuer: 'https://ps.test',
      token_endpoint: 'https://ps.test/token',
      jwks_uri: 'https://ps.test/.well-known/jwks.json',
    }
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      expect(url).toBe('https://ps.test/.well-known/aauth-person.json')
      return new Response(JSON.stringify(psMetadata), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }))

    const body = JSON.stringify({ ps: 'https://ps.test', scope: 'openid profile' })
    const headers = await signedHeaders(body, agentToken, privateJwk)
    const res = await app.request('/authorize', { method: 'POST', headers, body }, env)

    expect(res.status).toBe(200)
    const resBody = await res.json() as any
    expect(resBody.ps_metadata).toEqual(psMetadata)
    expect(resBody.ps_metadata_url).toBe('https://ps.test/.well-known/aauth-person.json')
    expect(resBody.resource_token).toBeDefined()

    const payload = decodeJWTPayload(resBody.resource_token)
    expect(payload.iss).toBe('https://playground.test')
    expect(payload.dwk).toBe('aauth-resource.json')
    expect(payload.aud).toBe('https://ps.test')
    expect(payload.scope).toBe('openid profile')
    expect(payload.agent).toBe('aauth:playground@playground.test')
    expect(payload.agent_jkt).toBeDefined()
    expect(payload.exp as number).toBe((payload.iat as number) + 300)

    // agent_jkt must be the RFC 7638 thumbprint of the ephemeral JWK
    const { computeJwkThumbprint } = await import('../src/crypto')
    expect(payload.agent_jkt).toBe(await computeJwkThumbprint(publicJwk))

    vi.unstubAllGlobals()
  })

  it('rejects unknown scopes with 400 invalid_scope', async () => {
    const app = await loadApp()
    const { env, kv } = await makeEnv()
    const { agentToken, privateJwk } = await mintAgentTokenWithKey(app, env, kv)
    const body = JSON.stringify({ ps: 'https://ps.test', scope: 'openid notascope' })
    const headers = await signedHeaders(body, agentToken, privateJwk)
    const res = await app.request('/authorize', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(400)
    const resBody = await res.json() as any
    expect(resBody.error).toBe('invalid_scope')
    expect(resBody.unknown).toEqual(['notascope'])
  })

  it('accepts multi-scope requests with all advertised values', async () => {
    const app = await loadApp()
    const { env, kv } = await makeEnv()
    const { agentToken, privateJwk } = await mintAgentTokenWithKey(app, env, kv)
    const psMetadata = {
      issuer: 'https://ps.test',
      token_endpoint: 'https://ps.test/token',
      jwks_uri: 'https://ps.test/.well-known/jwks.json',
    }
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(psMetadata), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })))
    const body = JSON.stringify({ ps: 'https://ps.test', scope: 'openid discord github' })
    const headers = await signedHeaders(body, agentToken, privateJwk)
    const res = await app.request('/authorize', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(200)
    const payload = decodeJWTPayload(((await res.json()) as any).resource_token)
    expect(payload.scope).toBe('openid discord github')
    vi.unstubAllGlobals()
  })
})
