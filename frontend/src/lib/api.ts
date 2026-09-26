import type {
  Health, IncidentRow, Investigation, Sample, Stats, StreamEvent, Technique,
} from './types'

const BASE = '/api'

class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message)
    this.name = 'ApiError'
  }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(`${BASE}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...init,
    })
  } catch {
    throw new ApiError('Cannot reach the AEGIS API. Is the backend running on :8000?', 0)
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      if (body?.detail) detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(detail, res.status)
  }
  return res.json() as Promise<T>
}

export const api = {
  health: () => req<Health>('/health'),

  samples: () => req<{ samples: Sample[] }>('/samples').then((r) => r.samples),

  techniques: () =>
    req<{ tactics: string[]; techniques: Technique[] }>('/techniques'),
  technique: (id: string) => req<{ technique: Technique }>(`/techniques/${id}`).then((r) => r.technique),

  kbSearch: (query: string, limit = 6) =>
    req<{ results: { id: string; kind: string; title: string; tactic: string; score: number; excerpt: string; doc: Record<string, unknown> }[] }>(
      '/kb/search',
      { method: 'POST', body: JSON.stringify({ query, limit }) },
    ).then((r) => r.results),

  extract: (text: string) =>
    req<{ iocs: Record<string, string[]>; total: number; priority: { type: string; value: string }[] }>(
      '/iocs/extract',
      { method: 'POST', body: JSON.stringify({ text }) },
    ),

  investigate: (alert: Record<string, unknown>, useLlm = true) =>
    req<{ investigation: Investigation }>(
      `/investigate?use_llm=${useLlm}`,
      { method: 'POST', body: JSON.stringify(alert) },
    ).then((r) => r.investigation),

  incidents: (limit = 50) =>
    req<{ incidents: IncidentRow[]; stats: Stats }>(`/incidents?limit=${limit}`),

  incident: (id: string) =>
    req<{ investigation: Investigation }>(`/incidents/${id}`).then((r) => r.investigation),

  clearIncidents: () => req<{ removed: number }>('/incidents', { method: 'DELETE' }),

  ingest: (alert: Record<string, unknown>) =>
    req<{ count: number; alerts: { alert_id: string }[] }>('/alerts/ingest', {
      method: 'POST',
      body: JSON.stringify(alert),
    }),
}

/**
 * Streams the investigation pipeline over SSE.
 * `onEvent` receives every step; resolves with the final investigation.
 */
export function investigateStream(
  alert: Record<string, unknown>,
  useLlm: boolean,
  onEvent: (e: StreamEvent) => void,
  signal?: AbortSignal,
): Promise<Investigation | null> {
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = (v: Investigation | null) => {
      if (!settled) { settled = true; resolve(v) }
    }

    fetch(`${BASE}/investigate/stream?use_llm=${useLlm}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(alert),
      signal,
    })
      .then(async (res) => {
        if (!res.ok) {
          throw new ApiError(`Stream failed: ${res.status} ${res.statusText}`, res.status)
        }
        if (!res.body) throw new ApiError('Streaming is not supported by this browser.', 0)

        const reader = res.body.getReader()
        const decoder = new TextDecoder()
        let buffer = ''

        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          buffer += decoder.decode(value, { stream: true })

          // SSE frames are separated by a blank line.
          const frames = buffer.split('\n\n')
          buffer = frames.pop() ?? ''

          for (const frame of frames) {
            const line = frame.split('\n').find((l) => l.startsWith('data:'))
            if (!line) continue
            try {
              const event = JSON.parse(line.slice(5).trim()) as StreamEvent
              onEvent(event)
              if (event.type === 'result') finish(event.investigation)
              if (event.type === 'error') {
                settled = true
                reject(new ApiError(event.error, 500))
              }
              if (event.type === 'done') return
            } catch (err) {
              if (err instanceof ApiError) return
              /* ignore malformed frame */
            }
          }
        }
        finish(null)
      })
      .catch((err) => {
        if (settled) return
        settled = true
        reject(err as Error)
      })
  })
}

export { ApiError }
