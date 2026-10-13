/**
 * Live Monitoring — searchable Elasticsearch log stream with auto-refresh.
 */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { format, parseISO } from "date-fns";
import { RefreshCw, Search } from "lucide-react";
import { logService } from "@/services/logService";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge, severityToTone } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Spinner } from "@/components/ui/Spinner";
import type { Severity, SourceType } from "@/types";

export function LiveMonitoringPage() {
  const [query, setQuery] = useState("");
  const [sourceType, setSourceType] = useState<SourceType | "">("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [applied, setApplied] = useState({ query: "", sourceType: "", severity: "" });

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["logs", "search", applied],
    queryFn: () =>
      logService.search({
        query: applied.query || undefined,
        source_type: (applied.sourceType as SourceType) || undefined,
        severity: (applied.severity as Severity) || undefined,
        size: 50,
      }),
    refetchInterval: 10_000,
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-text-primary">Live Monitoring</h1>
          <p className="mt-1 text-sm text-text-secondary">
            Real-time view of normalized security logs in Elasticsearch.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()} isLoading={isFetching}>
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
      </div>

      <Card>
        <CardBody className="flex flex-wrap items-end gap-3">
          <div className="min-w-[200px] flex-1">
            <label className="mb-1 block text-2xs uppercase text-text-muted">Search</label>
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search raw_log…"
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  setApplied({ query, sourceType, severity });
                }
              }}
            />
          </div>
          <div>
            <label className="mb-1 block text-2xs uppercase text-text-muted">Source</label>
            <select
              className="h-10 rounded-md border border-border bg-base-800 px-3 text-sm text-text-primary"
              value={sourceType}
              onChange={(e) => setSourceType(e.target.value as SourceType | "")}
            >
              <option value="">All</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="firewall">Firewall</option>
              <option value="web_server">Web Server</option>
            </select>
          </div>
          <div>
            <label className="mb-1 block text-2xs uppercase text-text-muted">Severity</label>
            <select
              className="h-10 rounded-md border border-border bg-base-800 px-3 text-sm text-text-primary"
              value={severity}
              onChange={(e) => setSeverity(e.target.value as Severity | "")}
            >
              <option value="">All</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
          <Button
            onClick={() => setApplied({ query, sourceType, severity })}
            size="md"
          >
            <Search className="h-4 w-4" />
            Apply
          </Button>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>
            Logs {data ? `(${data.total})` : ""}
          </CardTitle>
        </CardHeader>
        <CardBody className="overflow-x-auto">
          {isLoading ? (
            <div className="flex h-40 items-center justify-center">
              <Spinner />
            </div>
          ) : (
            <table className="w-full min-w-[800px] text-left text-sm">
              <thead className="text-2xs uppercase text-text-muted">
                <tr>
                  <th className="pb-3 pr-3">Time</th>
                  <th className="pb-3 pr-3">Source</th>
                  <th className="pb-3 pr-3">Event</th>
                  <th className="pb-3 pr-3">IP</th>
                  <th className="pb-3 pr-3">Severity</th>
                  <th className="pb-3">Raw</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {(data?.results ?? []).map((log) => (
                  <tr key={log.log_id}>
                    <td className="py-2.5 pr-3 font-data text-text-secondary">
                      {log.timestamp ? format(parseISO(log.timestamp), "HH:mm:ss") : "—"}
                    </td>
                    <td className="py-2.5 pr-3 text-text-secondary">{log.source_type}</td>
                    <td className="py-2.5 pr-3 text-text-primary">{log.event_type}</td>
                    <td className="py-2.5 pr-3 font-data text-accent-cyan">{log.source_ip ?? "—"}</td>
                    <td className="py-2.5 pr-3">
                      <Badge tone={severityToTone(log.severity)} />
                    </td>
                    <td className="max-w-md truncate py-2.5 font-data text-xs text-text-muted">
                      {log.raw_log}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {!isLoading && (data?.results?.length ?? 0) === 0 && (
            <p className="py-8 text-center text-sm text-text-muted">No logs matched your filters.</p>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
