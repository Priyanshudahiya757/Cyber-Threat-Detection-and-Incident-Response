/**
 * Dashboard — live summary cards, charts, and recent events.
 * Auto-refreshes every 15s via React Query.
 */
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Brain,
  FileWarning,
  ShieldAlert,
  Siren,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { analyticsService } from "@/services/analyticsService";
import { formatDateTime, formatHour, humanize } from "@/lib/format";
import { Badge, Card, CardBody, CardHeader, CardTitle, Spinner } from "@/components/ui";

const SEVERITY_COLORS: Record<string, string> = {
  low: "#3B82F6",
  medium: "#FDB022",
  high: "#F97066",
  critical: "#F04438",
};

function StatCard({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: number | string;
  icon: typeof Activity;
  accent: string;
}) {
  return (
    <Card>
      <CardBody className="flex items-center gap-4">
        <div className={`rounded-lg p-3 ${accent}`}>
          <Icon className="h-5 w-5" />
        </div>
        <div>
          <p className="text-2xs uppercase tracking-wide text-text-muted">{label}</p>
          <p className="font-data text-2xl font-semibold text-text-primary">{value}</p>
        </div>
      </CardBody>
    </Card>
  );
}

export function DashboardPage() {
  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ["analytics", "summary"],
    queryFn: () => analyticsService.summary(24),
    refetchInterval: 15_000,
  });

  const { data: timeline } = useQuery({
    queryKey: ["analytics", "timeline"],
    queryFn: () => analyticsService.threatTimeline(24),
    refetchInterval: 15_000,
  });

  const { data: severity } = useQuery({
    queryKey: ["analytics", "severity"],
    queryFn: () => analyticsService.severityDistribution(24),
    refetchInterval: 15_000,
  });

  const { data: attackTypes } = useQuery({
    queryKey: ["analytics", "attacks"],
    queryFn: () => analyticsService.attackTypes(8),
    refetchInterval: 15_000,
  });

  const { data: topIps } = useQuery({
    queryKey: ["analytics", "topIps"],
    queryFn: () => analyticsService.topIps(24, 8),
    refetchInterval: 15_000,
  });

  const { data: recent } = useQuery({
    queryKey: ["analytics", "recent"],
    queryFn: () => analyticsService.recentEvents(12),
    refetchInterval: 15_000,
  });

  const severityPie = severity
    ? Object.entries(severity).map(([name, value]) => ({ name, value }))
    : [];

  if (summaryLoading && !summary) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Spinner />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Security Operations Dashboard</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Live telemetry from ingestion, rule detection, and AI anomaly scoring.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <StatCard
          label="Logs (24h)"
          value={summary?.total_logs ?? 0}
          icon={Activity}
          accent="bg-accent-cyan/10 text-accent-cyan"
        />
        <StatCard
          label="Detections"
          value={summary?.threats_detected ?? 0}
          icon={ShieldAlert}
          accent="bg-severity-warning-dim text-severity-warning"
        />
        <StatCard
          label="Active Incidents"
          value={summary?.active_incidents ?? 0}
          icon={FileWarning}
          accent="bg-accent-blue/10 text-accent-blue"
        />
        <StatCard
          label="Critical Alerts"
          value={summary?.critical_alerts ?? 0}
          icon={Siren}
          accent="bg-severity-critical-dim text-severity-critical"
        />
        <StatCard
          label="AI Anomalies"
          value={summary?.ai_anomalies ?? 0}
          icon={Brain}
          accent="bg-accent-cyan/10 text-accent-cyan"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Threat Timeline (24h)</CardTitle>
          </CardHeader>
          <CardBody className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline?.items ?? []}>
                <defs>
                  <linearGradient id="threatFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#22D3EE" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#22D3EE" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#232C3F" strokeDasharray="3 3" />
                <XAxis
                  dataKey="timestamp"
                  tickFormatter={formatHour}
                  stroke="#5B6478"
                  fontSize={11}
                />
                <YAxis stroke="#5B6478" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ background: "#111827", border: "1px solid #232C3F" }}
                  labelFormatter={(value) => formatDateTime(String(value))}
                />
                <Area type="monotone" dataKey="count" stroke="#22D3EE" fill="url(#threatFill)" />
              </AreaChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Log Severity (24h)</CardTitle>
          </CardHeader>
          <CardBody className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={severityPie} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90}>
                  {severityPie.map((entry) => (
                    <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] ?? "#8D96AC"} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "#111827", border: "1px solid #232C3F" }} />
                <Legend formatter={(value) => humanize(String(value))} />
              </PieChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Detections by Type</CardTitle>
          </CardHeader>
          <CardBody className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={attackTypes?.items ?? []} layout="vertical" margin={{ left: 20 }}>
                <CartesianGrid stroke="#232C3F" strokeDasharray="3 3" />
                <XAxis type="number" stroke="#5B6478" fontSize={11} allowDecimals={false} />
                <YAxis
                  type="category"
                  dataKey="threat_type"
                  width={120}
                  stroke="#5B6478"
                  fontSize={10}
                />
                <Tooltip contentStyle={{ background: "#111827", border: "1px solid #232C3F" }} />
                <Bar dataKey="count" fill="#3B82F6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Most Active Source IPs (24h)</CardTitle>
          </CardHeader>
          <CardBody>
            <ul className="space-y-2">
              {(topIps?.items ?? []).length === 0 && (
                <li className="text-sm text-text-muted">No source IP activity yet.</li>
              )}
              {(topIps?.items ?? []).map((row) => (
                <li
                  key={row.ip}
                  className="flex items-center justify-between rounded-md bg-base-700/50 px-3 py-2"
                >
                  <span className="font-data text-sm text-text-primary">{row.ip}</span>
                  <span className="font-data text-sm text-accent-cyan">{row.count}</span>
                </li>
              ))}
            </ul>
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-severity-warning" />
            Recent Events
          </CardTitle>
        </CardHeader>
        <CardBody className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead className="text-2xs uppercase text-text-muted">
              <tr>
                <th className="pb-3 pr-4">Detected</th>
                <th className="pb-3 pr-4">Engine</th>
                <th className="pb-3 pr-4">Threat</th>
                <th className="pb-3 pr-4">Entity</th>
                <th className="pb-3 pr-4">Severity</th>
                <th className="pb-3">Explanation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {(recent?.events ?? []).map((ev) => (
                <tr key={ev.detection_id}>
                  <td className="whitespace-nowrap py-3 pr-4 font-data text-text-secondary">
                    {formatDateTime(ev.timestamp)}
                  </td>
                  <td className="py-3 pr-4 uppercase text-text-secondary">{ev.engine}</td>
                  <td className="py-3 pr-4 text-text-primary">
                    {ev.rule_name ? humanize(ev.rule_name) : "AI Anomaly"}
                  </td>
                  <td className="py-3 pr-4 font-data text-accent-cyan">{ev.entity?.value}</td>
                  <td className="py-3 pr-4">
                    <Badge tone={ev.severity} />
                  </td>
                  <td className="max-w-xs truncate py-3 text-text-secondary" title={ev.explanation}>
                    {ev.explanation}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {(recent?.events ?? []).length === 0 && (
            <p className="py-6 text-center text-sm text-text-muted">
              No detections yet — upload sample logs to populate the dashboard.
            </p>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
