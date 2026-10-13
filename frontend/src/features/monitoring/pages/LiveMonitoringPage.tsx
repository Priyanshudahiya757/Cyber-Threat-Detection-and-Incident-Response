/**
 * Live Monitoring — searchable view of the normalized logs in
 * Elasticsearch, refreshed automatically. The search text lives in the
 * URL (?q=...) so the top-bar search and shared links land here directly.
 */
import { useEffect, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { RefreshCw, Search } from "lucide-react";
import { logService } from "@/services/logService";
import { getErrorMessage } from "@/lib/apiError";
import { formatDateTime, humanize } from "@/lib/format";
import { Badge, Button, Card, CardBody, CardHeader, CardTitle, Input, Notice, Select, Spinner } from "@/components/ui";
import { SEVERITIES, SOURCE_TYPE_LABELS, type Severity, type SourceType } from "@/types";

const PAGE_SIZE = 100;

export function LiveMonitoringPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const appliedQuery = searchParams.get("q") ?? "";

  const [queryText, setQueryText] = useState(appliedQuery);
  const [sourceType, setSourceType] = useState<SourceType | "">("");
  const [severity, setSeverity] = useState<Severity | "">("");

  // The top-bar search changes ?q= while this page is already open.
  useEffect(() => setQueryText(appliedQuery), [appliedQuery]);

  const { data, error, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ["logs", "search", appliedQuery, sourceType, severity],
    queryFn: () =>
      logService.search({
        query: appliedQuery || undefined,
        source_type: sourceType || undefined,
        severity: severity || undefined,
        size: PAGE_SIZE,
      }),
    refetchInterval: 10_000,
  });

  const handleSearch = (event: FormEvent) => {
    event.preventDefault();
    const query = queryText.trim();
    setSearchParams(query ? { q: query } : {});
  };

  const logs = data?.results ?? [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-text-primary">Live Monitoring</h1>
          <p className="mt-1 text-sm text-text-secondary">
            Normalized security logs from every source, newest events first.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()} isLoading={isFetching}>
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
      </div>

      <Card>
        <CardBody>
          <form onSubmit={handleSearch} className="flex flex-wrap items-end gap-3">
            <div className="min-w-[220px] flex-1">
              <Input
                label="Search"
                name="log-search"
                value={queryText}
                onChange={(event) => setQueryText(event.target.value)}
                placeholder='Words to find, or an "exact phrase"'
              />
            </div>
            <Select
              label="Source"
              name="source-type"
              value={sourceType}
              onChange={(event) => setSourceType(event.target.value as SourceType | "")}
            >
              <option value="">All sources</option>
              {Object.entries(SOURCE_TYPE_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </Select>
            <Select
              label="Severity"
              name="severity"
              value={severity}
              onChange={(event) => setSeverity(event.target.value as Severity | "")}
            >
              <option value="">All severities</option>
              {SEVERITIES.map((level) => (
                <option key={level} value={level}>
                  {humanize(level)}
                </option>
              ))}
            </Select>
            <Button type="submit">
              <Search className="h-4 w-4" />
              Search
            </Button>
          </form>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>
            Logs
            {data && (
              <span className="ml-2 font-normal text-text-muted">
                {data.total > logs.length ? `showing ${logs.length} of ${data.total}` : `${data.total} matching`}
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardBody className="overflow-x-auto">
          {isLoading ? (
            <div className="flex h-40 items-center justify-center">
              <Spinner />
            </div>
          ) : isError ? (
            <Notice tone="error">{getErrorMessage(error, "Could not load logs.")}</Notice>
          ) : logs.length === 0 ? (
            <p className="py-8 text-center text-sm text-text-muted">No logs matched your filters.</p>
          ) : (
            <table className="w-full min-w-[900px] text-left text-sm">
              <thead className="text-2xs uppercase text-text-muted">
                <tr>
                  <th className="pb-3 pr-3">Event time</th>
                  <th className="pb-3 pr-3">Source</th>
                  <th className="pb-3 pr-3">Event</th>
                  <th className="pb-3 pr-3">Source IP</th>
                  <th className="pb-3 pr-3">User</th>
                  <th className="pb-3 pr-3">Severity</th>
                  <th className="pb-3">Raw log</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {logs.map((log) => (
                  <tr key={log.log_id}>
                    <td className="whitespace-nowrap py-2.5 pr-3 font-data text-text-secondary">
                      {formatDateTime(log.timestamp)}
                    </td>
                    <td className="py-2.5 pr-3 text-text-secondary">{SOURCE_TYPE_LABELS[log.source_type]}</td>
                    <td className="py-2.5 pr-3 text-text-primary">{humanize(log.event_type)}</td>
                    <td className="py-2.5 pr-3 font-data text-accent-cyan">{log.source_ip ?? "—"}</td>
                    <td className="py-2.5 pr-3 font-data text-text-secondary">{log.user ?? "—"}</td>
                    <td className="py-2.5 pr-3">
                      <Badge tone={log.severity} />
                    </td>
                    <td className="max-w-md truncate py-2.5 font-data text-xs text-text-muted" title={log.raw_log}>
                      {log.raw_log}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
