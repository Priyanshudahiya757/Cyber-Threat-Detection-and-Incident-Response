/**
 * AI Anomaly Detection — train the Isolation Forest, score recent logs,
 * evaluate against the labeled dataset, and review flagged entities.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Brain, FlaskConical, Sparkles } from "lucide-react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { detectionService } from "@/services/detectionService";
import { getErrorMessage } from "@/lib/apiError";
import { formatDateTime } from "@/lib/format";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Notice,
  Spinner,
  type NoticeMessage,
} from "@/components/ui";
import type { EvaluationMetrics } from "@/types";

/** Train on logs ingested in the last week; score those from the last day. */
const TRAINING_WINDOW_DAYS = 7;
const SCORING_WINDOW_MINUTES = 24 * 60;

function percent(value: number): string {
  return `${(value * 100).toFixed(0)}%`;
}

function EvaluationCard({ metrics }: { metrics: EvaluationMetrics }) {
  const [[trueNegatives, falsePositives], [falseNegatives, truePositives]] = metrics.confusion_matrix;
  const scores = [
    ["Precision", metrics.precision],
    ["Recall", metrics.recall],
    ["F1 score", metrics.f1_score],
    ["Accuracy", metrics.accuracy],
  ] as const;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Evaluation on labeled dataset ({metrics.n_samples} samples)</CardTitle>
      </CardHeader>
      <CardBody className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-4">
          {scores.map(([label, value]) => (
            <div key={label} className="rounded-md bg-base-700/50 px-4 py-3">
              <p className="text-2xs uppercase text-text-muted">{label}</p>
              <p className="font-data text-xl font-semibold text-text-primary">{percent(value)}</p>
            </div>
          ))}
        </div>
        <p className="text-sm text-text-secondary">
          Of {metrics.n_true_anomalies} known attacks, the model caught{" "}
          <span className="text-severity-success">{truePositives}</span> and missed{" "}
          <span className="text-severity-critical">{falseNegatives}</span>. Of{" "}
          {metrics.n_samples - metrics.n_true_anomalies} normal entities, it wrongly flagged{" "}
          <span className="text-severity-warning">{falsePositives}</span> and correctly passed{" "}
          {trueNegatives}.
        </p>
      </CardBody>
    </Card>
  );
}

export function AnomalyDetectionPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const queryClient = useQueryClient();
  const [notice, setNotice] = useState<NoticeMessage | null>(null);

  const anomaliesQuery = useQuery({
    queryKey: ["detections", "ml"],
    queryFn: () => detectionService.list({ engine: "ml", limit: 100 }),
    refetchInterval: 20_000,
  });

  const modelsQuery = useQuery({ queryKey: ["ml", "models"], queryFn: detectionService.listModels });

  const fail = (error: unknown) => setNotice({ tone: "error", text: getErrorMessage(error) });

  const trainMutation = useMutation({
    mutationFn: () => detectionService.trainModel(TRAINING_WINDOW_DAYS),
    onSuccess: (result) => {
      setNotice({
        tone: "success",
        text:
          `Trained model ${result.version} on ${result.n_samples} source IPs; ` +
          `${result.entities_flagged_anomalous.length} looked anomalous in the training data.`,
      });
      queryClient.invalidateQueries({ queryKey: ["ml"] });
    },
    onError: fail,
  });

  const scoreMutation = useMutation({
    mutationFn: () => detectionService.runAnomalyScoring(SCORING_WINDOW_MINUTES),
    onSuccess: (result) => {
      setNotice({
        tone: "info",
        text:
          `Scored ${result.logs_scanned} logs from the last 24 hours: ` +
          `${result.detections_found} new anomaly detection(s).`,
      });
      for (const key of ["detections", "alerts", "analytics", "incidents"]) {
        queryClient.invalidateQueries({ queryKey: [key] });
      }
    },
    onError: fail,
  });

  const evaluateMutation = useMutation({ mutationFn: detectionService.evaluate, onError: fail });

  const models = [...(modelsQuery.data ?? [])].reverse();
  const anomalies = anomaliesQuery.data?.detections ?? [];
  const hasModel = models.length > 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">AI Anomaly Detection</h1>
        <p className="mt-1 text-sm text-text-secondary">
          An Isolation Forest learns what normal activity per source IP looks like and flags the
          outliers. New uploads are scored automatically once a model has been trained.
        </p>
      </div>

      <div className="flex flex-wrap gap-3">
        {isAdmin && (
          <Button onClick={() => trainMutation.mutate()} isLoading={trainMutation.isPending}>
            <Brain className="h-4 w-4" />
            {hasModel ? "Retrain model" : "Train model"}
          </Button>
        )}
        <Button
          variant="outline"
          onClick={() => scoreMutation.mutate()}
          isLoading={scoreMutation.isPending}
          disabled={!hasModel}
          title={hasModel ? undefined : "Train a model first"}
        >
          <Sparkles className="h-4 w-4" />
          Score recent logs
        </Button>
        <Button variant="ghost" onClick={() => evaluateMutation.mutate()} isLoading={evaluateMutation.isPending}>
          <FlaskConical className="h-4 w-4" />
          Evaluate on labeled dataset
        </Button>
      </div>

      {!isAdmin && !hasModel && modelsQuery.isSuccess && (
        <Notice tone="info">No model has been trained yet. Ask an administrator to train one.</Notice>
      )}
      {notice && <Notice tone={notice.tone}>{notice.text}</Notice>}
      {evaluateMutation.data && <EvaluationCard metrics={evaluateMutation.data} />}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Model registry</CardTitle>
          </CardHeader>
          <CardBody className="space-y-2">
            {modelsQuery.isLoading && <Spinner />}
            {modelsQuery.isSuccess && !hasModel && (
              <p className="text-sm text-text-muted">No trained models yet.</p>
            )}
            {models.map((model, index) => (
              <div key={model.version} className="rounded-md bg-base-700/50 px-3 py-2 text-sm">
                <div className="flex items-center justify-between">
                  <span className="font-data text-accent-cyan">{model.version}</span>
                  {index === 0 && <Badge tone="success">In use</Badge>}
                </div>
                <p className="text-xs text-text-muted">
                  {model.n_samples} source IPs · {formatDateTime(model.trained_at)}
                </p>
              </div>
            ))}
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Anomalous entities ({anomalies.length})</CardTitle>
          </CardHeader>
          <CardBody className="overflow-x-auto">
            {anomaliesQuery.isLoading ? (
              <div className="flex h-40 items-center justify-center">
                <Spinner />
              </div>
            ) : anomaliesQuery.isError ? (
              <Notice tone="error">{getErrorMessage(anomaliesQuery.error, "Could not load anomalies.")}</Notice>
            ) : anomalies.length === 0 ? (
              <p className="py-8 text-center text-sm text-text-muted">No anomalies detected yet.</p>
            ) : (
              <table className="w-full min-w-[640px] text-left text-sm">
                <thead className="text-2xs uppercase text-text-muted">
                  <tr>
                    <th className="pb-3 pr-3">Detected</th>
                    <th className="pb-3 pr-3">Entity</th>
                    <th className="pb-3 pr-3">Risk</th>
                    <th className="pb-3 pr-3">Severity</th>
                    <th className="pb-3">Why it was flagged</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {anomalies.map((detection) => (
                    <tr key={detection.detection_id} className="align-top">
                      <td className="py-2.5 pr-3 font-data text-text-secondary">
                        {formatDateTime(detection.timestamp)}
                      </td>
                      <td className="py-2.5 pr-3 font-data text-accent-cyan">{detection.entity.value}</td>
                      <td className="py-2.5 pr-3 font-data text-text-primary">
                        {detection.risk_percentage != null ? `${detection.risk_percentage.toFixed(0)}%` : "—"}
                      </td>
                      <td className="py-2.5 pr-3">
                        <Badge tone={detection.severity} />
                      </td>
                      <td className="py-2.5 text-xs text-text-secondary">{detection.explanation}</td>
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
