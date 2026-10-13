/**
 * Threat Detection — rule detections, alerts, and manual re-scan.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { format, parseISO } from "date-fns";
import { Play, Shield } from "lucide-react";
import { detectionService } from "@/services/detectionService";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge, severityToTone } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import type { Severity } from "@/types";

export function ThreatDetectionPage() {
  const queryClient = useQueryClient();
  const [severity, setSeverity] = useState("");
  const [runMsg, setRunMsg] = useState<string | null>(null);

  const detectionsQuery = useQuery({
    queryKey: ["detections", "list", severity],
    queryFn: () =>
      detectionService.list({
        engine: "rule",
        severity: severity || undefined,
        limit: 100,
      }),
    refetchInterval: 15_000,
  });

  const alertsQuery = useQuery({
    queryKey: ["detections", "alerts"],
    queryFn: () => detectionService.listAlerts(50),
    refetchInterval: 15_000,
  });

  const runMutation = useMutation({
    mutationFn: () => detectionService.runDetection(120),
    onSuccess: (result) => {
      setRunMsg(
        `Scanned ${result.logs_scanned} logs → ${result.detections_found} detections, ${result.alerts_generated} alerts.`
      );
      queryClient.invalidateQueries({ queryKey: ["detections"] });
      queryClient.invalidateQueries({ queryKey: ["analytics"] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-text-primary">Threat Detection</h1>
          <p className="mt-1 text-sm text-text-secondary">
            Rule-engine hits with MITRE mapping and generated alerts.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select
            className="h-10 rounded-md border border-border bg-base-800 px-3 text-sm"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
          >
            <option value="">All severities</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
          <Button onClick={() => runMutation.mutate()} isLoading={runMutation.isPending}>
            <Play className="h-4 w-4" />
            Re-run rules
          </Button>
        </div>
      </div>

      {runMsg && (
        <p className="rounded-md border border-accent-cyan/30 bg-accent-cyan/10 px-3 py-2 text-sm text-accent-cyan">
          {runMsg}
        </p>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-accent-cyan" />
              Detections ({detectionsQuery.data?.count ?? 0})
            </CardTitle>
          </CardHeader>
          <CardBody className="overflow-x-auto">
            {detectionsQuery.isLoading ? (
              <div className="flex h-40 items-center justify-center">
                <Spinner />
              </div>
            ) : (
              <table className="w-full min-w-[640px] text-left text-sm">
                <thead className="text-2xs uppercase text-text-muted">
                  <tr>
                    <th className="pb-3 pr-3">Time</th>
                    <th className="pb-3 pr-3">Rule</th>
                    <th className="pb-3 pr-3">Entity</th>
                    <th className="pb-3 pr-3">Severity</th>
                    <th className="pb-3">MITRE</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {(detectionsQuery.data?.detections ?? []).map((d) => (
                    <tr key={d.detection_id}>
                      <td className="py-2.5 pr-3 font-data text-text-secondary">
                        {d.timestamp ? format(parseISO(d.timestamp), "HH:mm:ss") : "—"}
                      </td>
                      <td className="py-2.5 pr-3">{d.rule_name?.replace(/_/g, " ")}</td>
                      <td className="py-2.5 pr-3 font-data text-accent-cyan">{d.entity.value}</td>
                      <td className="py-2.5 pr-3">
                        <Badge tone={severityToTone(d.severity as Severity)} />
                      </td>
                      <td className="py-2.5 text-xs text-text-muted">{d.mitre_technique ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Alerts ({alertsQuery.data?.count ?? 0})</CardTitle>
          </CardHeader>
          <CardBody className="max-h-[480px] space-y-3 overflow-y-auto">
            {(alertsQuery.data?.alerts ?? []).map((a) => (
              <div key={a._id} className="rounded-md border border-border bg-base-700/40 p-3">
                <div className="mb-1 flex items-center justify-between gap-2">
                  <span className="text-sm font-medium text-text-primary">{a.title}</span>
                  <Badge tone={severityToTone(a.severity)} />
                </div>
                <p className="text-xs text-text-secondary">{a.description}</p>
                <p className="mt-1 font-data text-2xs text-text-muted">
                  {a.created_at ? format(parseISO(a.created_at), "MMM d HH:mm") : ""}
                </p>
              </div>
            ))}
            {(alertsQuery.data?.alerts?.length ?? 0) === 0 && (
              <p className="text-sm text-text-muted">No alerts yet.</p>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
