# SentinelGrid Frontend

React + TypeScript SOC console for the Cyber Threat Detection and Incident Response Dashboard.

**Status: Module 1 complete** — project scaffolding, core infrastructure, authentication, and the app
shell are built, typechecked, linted, and build-verified. Every other page (Dashboard, Live Monitoring,
Upload Logs, Threat Detection, AI Anomaly Detection, Incidents, Analytics, Detection Rules, User
Management, Settings) exists as a real routed page file with a placeholder body, ready to be filled in
module by module without any routing/import changes.

## Stack

React 18 · TypeScript · Vite · Tailwind CSS · React Router 6 · TanStack Query 5 · Axios · React Hook Form
+ Zod · Recharts · lucide-react

## Quick start

```bash
npm install
cp .env.example .env.local   # defaults work as-is against a locally running backend
npm run dev                   # http://localhost:5173, proxies /api to http://localhost:8000
```

Log in with the backend's seeded admin (`admin` / `ChangeMe123!` by default — see
`backend/scripts/seed_admin.py`).

```bash
npm run build       # tsc -b && vite build -> dist/
npm run typecheck   # tsc --noEmit
npm run lint        # eslint
npm run preview     # serve the production build locally
```

## Architecture

**Feature-based structure** — `src/features/<domain>/{pages,components,hooks,services}` — not
type-based folders. Each feature owns its full vertical slice.

```
src/
├── api/              # axios client (JWT + auto-refresh), endpoint path constants, token storage
├── types/             # TypeScript interfaces mirroring backend Pydantic schemas EXACTLY
├── services/           # API-calling functions; real backend calls or mock fallback (see below)
├── features/
│   ├── auth/             # fully real: login, JWT, RBAC-aware routing
│   ├── dashboard/         # placeholder -> Module 2
│   ├── monitoring/         # placeholder -> Module 3
│   ├── logs/                # placeholder -> Module 4
│   ├── detections/           # placeholder -> Module 5
│   ├── anomalies/              # placeholder -> Module 6
│   ├── incidents/                # placeholder -> Module 7
│   ├── analytics/                  # placeholder -> Module 8
│   ├── rules/                        # placeholder -> Module 9
│   ├── users/ , settings/              # placeholder -> Module 10
├── components/
│   ├── ui/            # Button, Input, Card, Badge, Spinner, EmptyState, Skeleton
│   ├── layout/          # AppShell, Sidebar, Topbar, navConfig (single source of nav truth)
│   └── common/            # ErrorBoundary, ComingSoonPage
├── routes/             # AppRouter, ProtectedRoute, AdminRoute, NotFoundPage
└── lib/                  # cn() classname helper, queryClient
```

## The mock-data pattern (important — read before building later modules)

Several backend endpoints aren't implemented yet: `incidents` (Phase 7), `analytics` (Phase 7+), rule
*write* operations (Phase 5), and user list/role management. Per the project requirement, every service
function that would call one of these follows one pattern:

```ts
// src/services/incidentService.ts (illustrative — built in Module 7)
export async function listIncidents(params: IncidentListParams): Promise<IncidentRecord[]> {
  if (!env.useMocksForUnimplemented) {
    const { data } = await apiClient.get(ENDPOINTS.incidents.list, { params });
    return data.items;
  }
  await simulateNetworkDelay();
  return mockIncidents(params);
}
```

Flipping `VITE_USE_MOCKS_FOR_UNIMPLEMENTED=false` in `.env.local` once a backend phase lands switches
every such function to the real call. **No component or hook ever branches on mock-vs-real** — they only
ever import the service function, so this is a one-line env change, not a refactor.

Already-implemented backend endpoints (`auth`, `logs` upload/search, `detections`, `ml`) have **no** mock
branch — `authService.ts` is a good example of what a "real" service looks like once its backend phase is
done.

## Design system

Dark navy base (`base-900` `#0A0E17`, not pure black) with a cyan/blue duotone accent, plus the brief's
semantic severity palette (red/orange/green). Inter for UI chrome, JetBrains Mono for data-dense content
(IDs, IPs, timestamps) — see `tailwind.config.ts` for the full token rationale and `src/index.css`'s
`.font-data` utility. Full token/rationale documentation lives as comments directly in
`tailwind.config.ts`, not a separate style guide, so it can't drift from the code.

## Known dependency notes

- `@types/node` was added to satisfy `vite.config.ts`'s use of `path`/`__dirname`/`process` — not in the
  original dependency list but required for `tsc -b` to pass on the Vite config itself.
- `recharts@2.15.4` prints an npm deprecation notice (2.x is in maintenance mode, 3.x exists) — pinned to
  2.x deliberately since Recharts 3 changes several chart APIs the later analytics modules will use; worth
  revisiting once those modules are built if bundle size becomes a concern.
