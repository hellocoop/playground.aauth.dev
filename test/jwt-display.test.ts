import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// app.js is a browser script; extract pure helpers (no DOM dependency) for
// Node-side unit testing.
function extract(...names: string[]): Record<string, Function> {
  const source = readFileSync(resolve(__dirname, '../public/app.js'), 'utf-8')
  const fragments: string[] = []
  for (const n of names) {
    const re = new RegExp(`function ${n}\\b[\\s\\S]*?\\n\\}\\n`, 'm')
    const m = source.match(re)
    if (!m) throw new Error(`Could not extract function ${n}`)
    fragments.push(m[0])
  }
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(`${fragments.join('\n')}\nreturn { ${names.join(', ')} };`)() as Record<string, Function>
}

const { escapeHtml, renderEncodedJWT, renderJSON } = extract(
  'escapeHtml', 'renderEncodedJWT', 'renderJSON'
) as {
  escapeHtml: (s: unknown) => string
  renderEncodedJWT: (jwt: string) => string
  renderJSON: (obj: unknown) => string
}

describe('escapeHtml', () => {
  it('escapes the five HTML special characters', () => {
    expect(escapeHtml(`<a href="x" class='y'>&</a>`))
      .toBe('&lt;a href=&quot;x&quot; class=&#39;y&#39;&gt;&amp;&lt;/a&gt;')
  })
  it('coerces non-strings to strings', () => {
    expect(escapeHtml(42)).toBe('42')
    expect(escapeHtml(null)).toBe('null')
  })
})

describe('renderEncodedJWT', () => {
  it('wraps each segment in colored spans separated by dots', () => {
    const html = renderEncodedJWT('aaa.bbb.ccc')
    expect(html).toBe(
      '<span class="jwt-header">aaa</span>' +
      '<span class="jwt-dot">.</span>' +
      '<span class="jwt-payload">bbb</span>' +
      '<span class="jwt-dot">.</span>' +
      '<span class="jwt-signature">ccc</span>'
    )
  })

  it('handles JWTs with empty signature segment', () => {
    const html = renderEncodedJWT('h.p.')
    expect(html).toContain('<span class="jwt-signature"></span>')
  })

  it('escapes HTML in segments', () => {
    const html = renderEncodedJWT('<script>.x.y')
    expect(html).toContain('&lt;script&gt;')
    expect(html).not.toContain('<script>')
  })

  it('falls back to escaped text for non-JWT input', () => {
    expect(renderEncodedJWT('not-a-jwt')).toBe('not-a-jwt')
  })
})

describe('renderJSON', () => {
  it('color-codes keys, string values, numbers, and booleans', () => {
    const html = renderJSON({ s: 'x', n: 1, b: true, nul: null })
    expect(html).toContain('<span class="json-key">&quot;s&quot;</span>:')
    expect(html).toContain('<span class="json-string">&quot;x&quot;</span>')
    expect(html).toContain('<span class="json-num">1</span>')
    expect(html).toContain('<span class="json-bool">true</span>')
    expect(html).toContain('<span class="json-bool">null</span>')
  })

  it('escapes HTML inside string values', () => {
    const html = renderJSON({ x: '<script>alert(1)</script>' })
    expect(html).not.toContain('<script>')
    expect(html).toContain('&lt;script&gt;')
  })

  it('produces parseable structure when stripped of spans', () => {
    const obj = { iss: 'https://x', iat: 123, ok: true }
    const html = renderJSON(obj)
    const stripped = html.replace(/<[^>]+>/g, '')
      .replace(/&quot;/g, '"').replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#39;/g, "'")
    expect(JSON.parse(stripped)).toEqual(obj)
  })

  it('does NOT mistake a colon inside a string value for a key separator', () => {
    // String value contains a colon; should still be highlighted as json-string.
    const html = renderJSON({ a: 'x: y' })
    expect(html).toContain('<span class="json-string">&quot;x: y&quot;</span>')
  })
})
