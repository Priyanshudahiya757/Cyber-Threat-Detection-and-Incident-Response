/**
 * Anomaly Detection — ML train / predict / evaluate console.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { format, parseISO } from "date-fns";
import { Brain, FlaskConical, Sparkles } from "lucide-react";
import { detectionService } from "@/services/detectionService";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { severityToTone } from "@/components/ui/badgeUtils";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import type { Severity } from "@/types";

export function AnomalyDetectionPage() {
  const queryClient = useQueryClient();
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [evalMsg, setEvalMsg] = useState<string | null>(null);

  const anomaliesQuery = useQuery({
    queryKey: ["detections", "ml"],
    queryFn: () => detectionService.list({ engine: "ml", limit: 100 }),
    refetchInterval: 20_000,
  });

  const modelsQuery = useQuery({
    queryKey: ["ml", "models"],
    queryFn: () => detectionService.listModels(),
    retry: false,
  });

  const trainMutation = useMutation({
    mutationFn: () => detectionService.trainModel(7),
    onSuccess: (r) => {
      setStatusMsg(
        `Trained ${r.version}: ${r.n_samples} samples, anomaly ratio ${(r.anomaly_ratio * 100).toFixed(1)}%.`
      );
      queryClient.invalidateQueries({ queryKey: ["ml"] });
    },
    onError: (err: unknown) => {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        "Training failed — ingest more logs first.";
      setStatusMsg(String(detail));
    },
  });

  const predictMutation = useMutation({
    mutationFn: () => detectionService.predict(120),
    onSuccess: (r) => {
      setStatusMsg(`Scored ${r.logs_scanned} logs → ${r.anomalies_found} anomalies.`);
      queryClient.invalidateQueries({ queryKey: ["detections"] });
      queryClient.invalidateQueries({ queryKey: ["analytics"] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
    onError: (err: unknown) => {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        "Prediction failed — train a model first.";
      setStatusMsg(String(detail));
    },
  });

  const evalMutation = useMutation({
    mutationFn: () => detectionService.evaluate(),
    onSuccess: (m) => {
      setEvalMsg(
        `Precision ${(m.precision * 100).toFixed(0)}% · Recall ${(m.recall * 100).toFixed(0)}% · F1 ${(m.f1_score * 100).toFixed(0)}% (${m.n_samples} samples)`
      );
    },
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">AI Anomaly Detection</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Isolation Forest scoring with versioned model registry and labeled evaluation.
        </p>
      </div>

      <div className="flex flex-wrap gap-3">
        <Button onClick={() => trainMutation.mutate()} isLoading={trainMutation.isPending}>
          <Brain className="h-4 w-4" />
          Train model
        </Button>
        <Button variant="outline" onClick={() => predictMutation.mutate()} isLoading={predictMutation.isPending}>
          <Sparkles className="h-4 w-4" />
          Score window
        </Button>
        <Button variant="ghost" onClick={() => evalMutation.mutate()} isLoading={evalMutation.isPending}>
          <FlaskConical className="h-4 w-4" />
          Evaluate (labeled set)
        </Button>
      </div>

      {statusMsg && (
        <p className="rounded-md border border-accent-cyan/30 bg-accent-cyan/10 px-3 py-2 text-sm text-accent-cyan">
          {statusMsg}
        </p>
      )}
      {evalMsg && (
        <p className="rounded-md border border-severity-success/30 bg-severity-success-dim/30 px-3 py-2 text-sm text-severity-success">
          {evalMsg}
        </p>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Model registry</CardTitle>
          </CardHeader>
          <CardBody className="space-y-2">
            {(modelsQuery.data?.models ?? []).length === 0 && (
              <p className="text-sm text-text-muted">No trained models yet.</p>
            )}
            {(modelsQuery.data?.models ?? []).map((m) => (
              <div key={m.version} className="rounded-md bg-base-700/50 px-3 py-2 text-sm">
                <p className="font-data text-accent-cyan">{m.version}</p>
                <p className="text-xs text-text-muted">
                  {m.n_samples} samples · {m.trained_at ? format(parseISO(m.trained_at), "MMM d HH:mm") : ""}
                </p>
              </div>
            ))}
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>ML anomalies ({anomaliesQuery.data?.count ?? 0})</CardTitle>
          </CardHeader>
          <CardBody className="overflow-x-auto">
            {anomaliesQuery.isLoading ? (
              <div className="flex h-40 items-center justify-center">
                <Spinner />
              </div>
            ) : (
              <table className="w-full min-w-[560px] text-left text-sm">
                <thead className="text-2xs uppercase text-text-muted">
                  <tr>
                    <th className="pb-3 pr-3">Time</th>
                    <th className="pb-3 pr-3">Entity</th>
                    <th className="pb-3 pr-3">Risk %</th>
                    <th className="pb-3 pr-3">Severity</th>
                    <th className="pb-3">Explanation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {(anomaliesQuery.data?.detections ?? []).map((d) => (
                    <tr key={d.detection_id}>
                      <td className="py-2.5 pr-3 font-data text-text-secondary">
                        {d.timestamp ? format(parseISO(d.timestamp), "HH:mm:ss") : "—"}
                      </td>
                      <td className="py-2.5 pr-3 font-data text-accent-cyan">{d.entity.value}</td>
                      <td className="py-2.5 pr-3 font-data">
                        {d.risk_percentage != null ? d.risk_percentage.toFixed(1) : "—"}
                      </td>
                      <td className="py-2.5 pr-3">
                        <Badge tone={severityToTone(d.severity as Severity)} />
                      </td>
                      <td className="max-w-xs truncate py-2.5 text-text-secondary">{d.explanation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
