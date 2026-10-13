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
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { format, parseISO } from "date-fns";
import { analyticsService } from "@/services/analyticsService";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { severityToTone } from "@/components/ui/badgeUtils";
import { Spinner } from "@/components/ui/Spinner";
import type { Severity } from "@/types";

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
          label="Total Logs"
          value={summary?.total_logs ?? 0}
          icon={Activity}
          accent="bg-accent-cyan/10 text-accent-cyan"
        />
        <StatCard
          label="Threats"
          value={summary?.threats_detected ?? 0}
          icon={ShieldAlert}
          accent="bg-severity-warning-dim text-severity-warning"
        />
        <StatCard
          label="Incidents"
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
                  tickFormatter={(v) => {
                    try {
                      return format(parseISO(v), "HH:mm");
                    } catch {
                      return v;
                    }
                  }}
                  stroke="#5B6478"
                  fontSize={11}
                />
                <YAxis stroke="#5B6478" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ background: "#111827", border: "1px solid #232C3F" }}
                  labelFormatter={(v) => String(v)}
                />
                <Area type="monotone" dataKey="count" stroke="#22D3EE" fill="url(#threatFill)" />
              </AreaChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Severity Distribution</CardTitle>
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
              </PieChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Attack Types</CardTitle>
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
            <CardTitle>Top Source IPs</CardTitle>
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
                <th className="pb-3 pr-4">Time</th>
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
                  <td className="py-3 pr-4 font-data text-text-secondary">
                    {ev.timestamp ? format(parseISO(ev.timestamp), "HH:mm:ss") : "—"}
                  </td>
                  <td className="py-3 pr-4 uppercase text-text-secondary">{ev.engine}</td>
                  <td className="py-3 pr-4 text-text-primary">
                    {ev.rule_name?.replace(/_/g, " ") ?? "AI Anomaly"}
                  </td>
                  <td className="py-3 pr-4 font-data text-accent-cyan">{ev.entity?.value}</td>
                  <td className="py-3 pr-4">
                    <Badge tone={severityToTone(ev.severity as Severity)} />
                  </td>
                  <td className="max-w-xs truncate py-3 text-text-secondary">{ev.explanation}</td>
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
