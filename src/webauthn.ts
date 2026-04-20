import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server'
import type { Env, WebAuthnRegistration, Binding } from './types'
import { base64urlEncode, base64urlDecode } from './crypto'

// ── Binding + WebAuthn helpers used by /bootstrap and /refresh ──

// Hash (ps_url, user_sub) into an opaque 43-char binding key used as the
// WebAuthn userHandle and as the KV prefix for this (PS, user) pair.
export async function deriveBindingKey(psUrl: string, userSub: string): Promise<string> {
  const data = new TextEncoder().encode(`${psUrl}|${userSub}`)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return base64urlEncode(new Uint8Array(hash))
}

export async function getBinding(env: Env, bindingKey: string): Promise<Binding | null> {
  return (await env.WEBAUTHN_KV.get(`binding:${bindingKey}`, 'json')) as Binding | null
}

export async function putBinding(env: Env, bindingKey: string, binding: Binding): Promise<void> {
  await env.WEBAUTHN_KV.put(`binding:${bindingKey}`, JSON.stringify(binding))
}

export async function createRegistrationOptionsForBinding(
  env: Env,
  bindingKey: string,
  displayName: string,
  rpName: string,
  rpID: string,
  extraChallengeData: Record<string, unknown> = {}
) {
  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userID: new TextEncoder().encode(bindingKey) as Uint8Array<ArrayBuffer>,
    userName: displayName,
    userDisplayName: displayName,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  })

  await env.WEBAUTHN_KV.put(
    `challenge:${options.challenge}`,
    JSON.stringify({
      binding_key: bindingKey,
      type: 'registration',
      ...extraChallengeData,
    }),
    { expirationTtl: 300 }
  )

  return options
}

export async function createAuthenticationOptionsForBinding(
  env: Env,
  binding: Binding,
  rpID: string,
  extraChallengeData: Record<string, unknown> = {}
) {
  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: binding.credentials.map((c) => ({
      id: c.credentialID,
      transports: c.transports as any | undefined,
    })),
    userVerification: 'preferred',
  })

  const bindingKey = await deriveBindingKey(binding.ps_url, binding.user_sub)
  await env.WEBAUTHN_KV.put(
    `challenge:${options.challenge}`,
    JSON.stringify({
      binding_key: bindingKey,
      type: 'authentication',
      ...extraChallengeData,
    }),
    { expirationTtl: 300 }
  )

  return options
}

// Verifies a registration response for a bootstrap-bound challenge and
// appends the credential to the binding. Caller has already built the
// binding skeleton; this mutates `binding.credentials` and persists it.
export async function verifyAndStoreRegistration(
  env: Env,
  origin: string,
  rpID: string,
  expectedChallenge: string,
  response: any,
  binding: Binding
): Promise<WebAuthnRegistration> {
  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    requireUserVerification: false,
  })

  if (!verification.verified || !verification.registrationInfo) {
    throw new Error('verification failed')
  }

  const { credential } = verification.registrationInfo
  const registration: WebAuthnRegistration = {
    credentialID: credential.id,
    credentialPublicKey: base64urlEncode(credential.publicKey),
    counter: credential.counter,
    transports: response.response?.transports,
  }
  binding.credentials.push(registration)
  const bindingKey = await deriveBindingKey(binding.ps_url, binding.user_sub)
  await putBinding(env, bindingKey, binding)
  return registration
}

export async function verifyAssertion(
  origin: string,
  rpID: string,
  expectedChallenge: string,
  response: any,
  binding: Binding
): Promise<{ credential: WebAuthnRegistration; newCounter: number }> {
  const match = binding.credentials.find((c) => c.credentialID === response.id)
  if (!match) throw new Error('credential not found in binding')

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    requireUserVerification: false,
    credential: {
      id: match.credentialID,
      publicKey: base64urlDecode(match.credentialPublicKey) as Uint8Array<ArrayBuffer>,
      counter: match.counter,
      transports: match.transports as any | undefined,
    },
  })

  if (!verification.verified) throw new Error('verification failed')
  return { credential: match, newCounter: verification.authenticationInfo.newCounter }
}

