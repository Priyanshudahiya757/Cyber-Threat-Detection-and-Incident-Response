/**
 * Threat Detection — rule-engine findings, the alerts raised from them,
 * and a manual re-scan of recently ingested logs.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Play, Shield } from "lucide-react";
import { alertService } from "@/services/alertService";
import { detectionService } from "@/services/detectionService";
import { getErrorMessage } from "@/lib/apiError";
import { formatDateTime, humanize } from "@/lib/format";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Notice,
  Select,
  Spinner,
  type NoticeMessage,
} from "@/components/ui";
import { SEVERITIES, type Severity } from "@/types";

/** How far back "Re-run rules" looks, in minutes of ingestion time. */
const RESCAN_WINDOW_MINUTES = 24 * 60;

export function ThreatDetectionPage() {
  const queryClient = useQueryClient();
  const [severity, setSeverity] = useState<Severity | "">("");
  const [showAcknowledged, setShowAcknowledged] = useState(false);
  const [notice, setNotice] = useState<NoticeMessage | null>(null);

  const detectionsQuery = useQuery({
    queryKey: ["detections", "rule", severity],
    queryFn: () => detectionService.list({ engine: "rule", severity: severity || undefined, limit: 100 }),
    refetchInterval: 15_000,
  });

  const alertsQuery = useQuery({
    queryKey: ["alerts", "list", showAcknowledged],
    queryFn: () => alertService.list({ acknowledged: showAcknowledged ? undefined : false, limit: 50 }),
    refetchInterval: 15_000,
  });

  const runMutation = useMutation({
    mutationFn: () => detectionService.runRules(RESCAN_WINDOW_MINUTES),
    onSuccess: (result) => {
      setNotice({
        tone: "info",
        text:
          `Scanned ${result.logs_scanned} logs from the last 24 hours: ` +
          `${result.detections_found} new detection(s), ${result.alerts_generated} new alert(s).`,
      });
      for (const key of ["detections", "alerts", "analytics", "incidents"]) {
        queryClient.invalidateQueries({ queryKey: [key] });
      }
    },
    onError: (error) => setNotice({ tone: "error", text: getErrorMessage(error) }),
  });

  const acknowledgeMutation = useMutation({
    mutationFn: (id: string) => alertService.acknowledge(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alerts"] }),
    onError: (error) => setNotice({ tone: "error", text: getErrorMessage(error) }),
  });

  const detections = detectionsQuery.data?.detections ?? [];
  const alerts = alertsQuery.data?.alerts ?? [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-text-primary">Threat Detection</h1>
          <p className="mt-1 text-sm text-text-secondary">
            Rule-engine findings with MITRE ATT&amp;CK mapping, and the alerts raised from them.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Select
            aria-label="Filter by severity"
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
          <Button onClick={() => runMutation.mutate()} isLoading={runMutation.isPending}>
            <Play className="h-4 w-4" />
            Re-run rules
          </Button>
        </div>
      </div>

      {notice && <Notice tone={notice.tone}>{notice.text}</Notice>}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-accent-cyan" />
              Detections ({detections.length})
            </CardTitle>
          </CardHeader>
          <CardBody className="overflow-x-auto">
            {detectionsQuery.isLoading ? (
              <div className="flex h-40 items-center justify-center">
                <Spinner />
              </div>
            ) : detectionsQuery.isError ? (
              <Notice tone="error">{getErrorMessage(detectionsQuery.error, "Could not load detections.")}</Notice>
            ) : detections.length === 0 ? (
              <p className="py-8 text-center text-sm text-text-muted">No rule detections match this filter.</p>
            ) : (
              <table className="w-full min-w-[720px] text-left text-sm">
                <thead className="text-2xs uppercase text-text-muted">
                  <tr>
                    <th className="pb-3 pr-3">Detected</th>
                    <th className="pb-3 pr-3">Rule</th>
                    <th className="pb-3 pr-3">Entity</th>
                    <th className="pb-3 pr-3">Severity</th>
                    <th className="pb-3 pr-3">Confidence</th>
                    <th className="pb-3">MITRE ATT&amp;CK</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {detections.map((detection) => (
                    <tr key={detection.detection_id} title={detection.explanation}>
                      <td className="py-2.5 pr-3 font-data text-text-secondary">
                        {formatDateTime(detection.timestamp)}
                      </td>
                      <td className="py-2.5 pr-3 text-text-primary">
                        {humanize(detection.rule_name ?? "unknown")}
                      </td>
                      <td className="py-2.5 pr-3 font-data text-accent-cyan">{detection.entity.value}</td>
                      <td className="py-2.5 pr-3">
                        <Badge tone={detection.severity} />
                      </td>
                      <td className="py-2.5 pr-3 font-data text-text-secondary">
                        {Math.round(detection.confidence * 100)}%
                      </td>
                      <td className="py-2.5 text-xs text-text-muted">{detection.mitre_technique ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>
              Alerts
              <span className="ml-2 font-normal text-text-muted">
                {alertsQuery.data?.unacknowledged_total ?? 0} unacknowledged
              </span>
            </CardTitle>
            <label className="flex items-center gap-2 text-xs text-text-secondary">
              <input
                type="checkbox"
                className="h-3.5 w-3.5 rounded border-border bg-base-800"
                checked={showAcknowledged}
                onChange={(event) => setShowAcknowledged(event.target.checked)}
              />
              Show acknowledged
            </label>
          </CardHeader>
          <CardBody className="max-h-[560px] space-y-3 overflow-y-auto">
            {alertsQuery.isLoading && <Spinner />}
            {alertsQuery.isError && (
              <Notice tone="error">{getErrorMessage(alertsQuery.error, "Could not load alerts.")}</Notice>
            )}
            {alerts.map((alert) => (
              <div key={alert._id} className="rounded-md border border-border bg-base-700/40 p-3">
                <div className="mb-1 flex items-start justify-between gap-2">
                  <span className="text-sm font-medium text-text-primary">{alert.title}</span>
                  <Badge tone={alert.severity} />
                </div>
                <p className="text-xs text-text-secondary">{alert.description}</p>
                <div className="mt-2 flex items-center justify-between gap-2">
                  <span className="font-data text-2xs text-text-muted">
                    {formatDateTime(alert.created_at)}
                    {(alert.dispatched_channels ?? []).length > 0 &&
                      ` · sent via ${alert.dispatched_channels!.join(", ")}`}
                  </span>
                  {alert.acknowledged ? (
                    <span className="text-2xs text-text-muted">Acknowledged by {alert.acknowledged_by}</span>
                  ) : (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={acknowledgeMutation.isPending}
                      onClick={() => acknowledgeMutation.mutate(alert._id)}
                    >
                      <Check className="h-3.5 w-3.5" />
                      Acknowledge
                    </Button>
                  )}
                </div>
              </div>
            ))}
            {alertsQuery.isSuccess && alerts.length === 0 && (
              <p className="py-6 text-center text-sm text-text-muted">
                {showAcknowledged ? "No alerts yet." : "No alerts waiting for acknowledgement."}
              </p>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
