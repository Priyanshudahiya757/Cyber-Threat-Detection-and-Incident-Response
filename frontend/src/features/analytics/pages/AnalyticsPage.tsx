/**
 * Analytics — deeper charts over the same backend aggregations.
 */
import { useQuery } from "@tanstack/react-query";
import {
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
import { Card, CardBody, CardHeader, CardTitle, Spinner } from "@/components/ui";

const SEVERITY_COLORS: Record<string, string> = {
  low: "#3B82F6",
  medium: "#FDB022",
  high: "#F97066",
  critical: "#F04438",
};

export function AnalyticsPage() {
  const summary = useQuery({
    queryKey: ["analytics", "summary", "page"],
    queryFn: () => analyticsService.summary(24),
  });
  const severity = useQuery({
    queryKey: ["analytics", "severity", "page"],
    queryFn: () => analyticsService.severityDistribution(24),
  });
  const attacks = useQuery({
    queryKey: ["analytics", "attacks", "page"],
    queryFn: () => analyticsService.attackTypes(12),
  });
  const ips = useQuery({
    queryKey: ["analytics", "topIps", "page"],
    queryFn: () => analyticsService.topIps(24, 12),
  });

  const severityPie = severity.data
    ? Object.entries(severity.data).map(([name, value]) => ({ name, value }))
    : [];

  if (summary.isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Spinner />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Threat Analytics</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Attack patterns across all logs ingested in the last 24 hours and every detection on record.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          ["Logs (24h)", summary.data?.total_logs],
          ["Detections", summary.data?.threats_detected],
          ["Active incidents", summary.data?.active_incidents],
          ["Log sources", summary.data?.log_sources],
        ].map(([label, value]) => (
          <Card key={String(label)}>
            <CardBody>
              <p className="text-2xs uppercase text-text-muted">{label}</p>
              <p className="font-data text-2xl font-semibold">{value ?? 0}</p>
            </CardBody>
          </Card>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Log severity (24h)</CardTitle>
          </CardHeader>
          <CardBody className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={severityPie} dataKey="value" nameKey="name" label outerRadius={100}>
                  {severityPie.map((e) => (
                    <Cell key={e.name} fill={SEVERITY_COLORS[e.name] ?? "#8D96AC"} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "#111827", border: "1px solid #232C3F" }} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Detections by type</CardTitle>
          </CardHeader>
          <CardBody className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={attacks.data?.items ?? []}>
                <CartesianGrid stroke="#232C3F" strokeDasharray="3 3" />
                <XAxis dataKey="threat_type" stroke="#5B6478" fontSize={10} interval={0} angle={-20} textAnchor="end" height={60} />
                <YAxis stroke="#5B6478" fontSize={11} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#111827", border: "1px solid #232C3F" }} />
                <Bar dataKey="count" fill="#22D3EE" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Most active source IPs (24h)</CardTitle>
          </CardHeader>
          <CardBody className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={ips.data?.items ?? []}>
                <CartesianGrid stroke="#232C3F" strokeDasharray="3 3" />
                <XAxis dataKey="ip" stroke="#5B6478" fontSize={10} />
                <YAxis stroke="#5B6478" fontSize={11} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#111827", border: "1px solid #232C3F" }} />
                <Bar dataKey="count" fill="#3B82F6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
