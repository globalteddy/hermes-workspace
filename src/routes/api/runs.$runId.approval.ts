/**
 * Approval-resolution proxy (#641).
 *
 * The browser cannot hold the Hermes Agent API key, so it POSTs the user's
 * approval decision here and this server route injects the Bearer token and
 * forwards it to the agent's POST /v1/runs/{run_id}/approval. Body: { choice }
 * where choice ∈ once | session | always | deny (the backend also aliases
 * approve→once). Optional { all: true } resolves every pending approval in the
 * run's session at once.
 */
import { createFileRoute } from '@tanstack/react-router'
import { isAuthenticated } from '../../server/auth-middleware'
import { requireJsonContentType } from '../../server/rate-limit'
import {
  BEARER_TOKEN,
  CLAUDE_API,
} from '../../server/gateway-capabilities'

function authHeaders(): Record<string, string> {
  return BEARER_TOKEN ? { Authorization: `Bearer ${BEARER_TOKEN}` } : {}
}

const VALID_CHOICES = new Set(['once', 'session', 'always', 'deny'])
const CHOICE_ALIASES: Record<string, string> = {
  approve: 'once',
  approved: 'once',
  allow: 'once',
  denied: 'deny',
  reject: 'deny',
}

export const Route = createFileRoute('/api/runs/$runId/approval')({
  server: {
    handlers: {
      POST: async ({ request, params }) => {
        if (!isAuthenticated(request)) {
          return new Response(JSON.stringify({ ok: false, error: 'Unauthorized' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
          })
        }
        const csrfCheck = requireJsonContentType(request)
        if (csrfCheck) return csrfCheck

        const runId = params.runId
        if (!runId) {
          return new Response(
            JSON.stringify({ ok: false, error: 'run id required' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } },
          )
        }

        let body: Record<string, unknown> = {}
        try {
          body = JSON.parse(await request.text()) as Record<string, unknown>
        } catch {
          // empty body falls through to validation below
        }

        const rawChoice =
          typeof body.choice === 'string' ? body.choice.trim().toLowerCase() : ''
        const choice = CHOICE_ALIASES[rawChoice] ?? rawChoice
        if (!VALID_CHOICES.has(choice)) {
          return new Response(
            JSON.stringify({
              ok: false,
              error:
                'invalid approval choice; expected one of: once, session, always, deny',
            }),
            { status: 400, headers: { 'Content-Type': 'application/json' } },
          )
        }

        const forwardBody: Record<string, unknown> = { choice }
        if (body.all === true) forwardBody.all = true

        try {
          const res = await fetch(
            `${CLAUDE_API}/v1/runs/${encodeURIComponent(runId)}/approval`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', ...authHeaders() },
              body: JSON.stringify(forwardBody),
            },
          )
          const text = await res.text()
          return new Response(text || JSON.stringify({ ok: res.ok }), {
            status: res.status,
            headers: { 'Content-Type': 'application/json' },
          })
        } catch (err) {
          return new Response(
            JSON.stringify({
              ok: false,
              error: err instanceof Error ? err.message : String(err),
            }),
            { status: 502, headers: { 'Content-Type': 'application/json' } },
          )
        }
      },
    },
  },
})
