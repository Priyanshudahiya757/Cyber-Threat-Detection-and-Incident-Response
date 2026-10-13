/**
 * Upload Logs — file upload into the ingestion → detection pipeline.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { format, parseISO } from "date-fns";
import { Upload } from "lucide-react";
import { logService } from "@/services/logService";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import type { SourceType } from "@/types";

export function UploadLogsPage() {
  const queryClient = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [sourceType, setSourceType] = useState<SourceType>("linux");
  const [sourceHost, setSourceHost] = useState("demo-host");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const batchesQuery = useQuery({
    queryKey: ["logs", "batches"],
    queryFn: () => logService.listBatches(),
  });

  const uploadMutation = useMutation({
    mutationFn: () => {
      if (!file) throw new Error("Select a file first");
      return logService.upload(file, sourceType, sourceHost || undefined);
    },
    onSuccess: (result) => {
      setError(null);
      setMessage(
        `Accepted ${result.accepted}, rejected ${result.rejected}, duplicates ${result.duplicates}. ` +
          `Batch ${result.batch_id ?? "n/a"} — detection engine runs automatically.`
      );
      setFile(null);
      queryClient.invalidateQueries({ queryKey: ["logs"] });
      queryClient.invalidateQueries({ queryKey: ["analytics"] });
      queryClient.invalidateQueries({ queryKey: ["detections"] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
    onError: (err: unknown) => {
      setMessage(null);
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        (err as Error).message ??
        "Upload failed";
      setError(String(detail));
    },
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Upload Logs</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Ingest Windows, Linux, firewall, or web logs. Parsing, detection, and incident
          correlation run automatically after upload.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Ingest file</CardTitle>
        </CardHeader>
        <CardBody className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-3">
            <div>
              <label className="mb-1 block text-2xs uppercase text-text-muted">Source type</label>
              <select
                className="h-10 w-full rounded-md border border-border bg-base-800 px-3 text-sm"
                value={sourceType}
                onChange={(e) => setSourceType(e.target.value as SourceType)}
              >
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
                <option value="firewall">Firewall</option>
                <option value="web_server">Web Server</option>
              </select>
            </div>
            <div>
              <label className="mb-1 block text-2xs uppercase text-text-muted">Source host</label>
              <Input value={sourceHost} onChange={(e) => setSourceHost(e.target.value)} />
            </div>
            <div>
              <label className="mb-1 block text-2xs uppercase text-text-muted">File (.log / .txt / .json)</label>
              <input
                type="file"
                accept=".log,.txt,.json"
                className="block w-full text-sm text-text-secondary file:mr-3 file:rounded-md file:border-0 file:bg-accent-blue file:px-3 file:py-2 file:text-sm file:text-white"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            </div>
          </div>

          {message && (
            <p className="rounded-md border border-severity-success/30 bg-severity-success-dim/40 px-3 py-2 text-sm text-severity-success">
              {message}
            </p>
          )}
          {error && (
            <p className="rounded-md border border-severity-critical/30 bg-severity-critical-dim/40 px-3 py-2 text-sm text-severity-critical">
              {error}
            </p>
          )}

          <Button
            onClick={() => uploadMutation.mutate()}
            isLoading={uploadMutation.isPending}
            disabled={!file}
          >
            <Upload className="h-4 w-4" />
            Upload &amp; Detect
          </Button>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recent ingestion batches</CardTitle>
        </CardHeader>
        <CardBody className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead className="text-2xs uppercase text-text-muted">
              <tr>
                <th className="pb-3 pr-3">When</th>
                <th className="pb-3 pr-3">Source</th>
                <th className="pb-3 pr-3">File</th>
                <th className="pb-3 pr-3">Accepted</th>
                <th className="pb-3 pr-3">Rejected</th>
                <th className="pb-3">By</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {(batchesQuery.data?.batches ?? []).map((b) => (
                <tr key={b.batch_id}>
                  <td className="py-2.5 pr-3 font-data text-text-secondary">
                    {b.created_at ? format(parseISO(b.created_at), "MMM d HH:mm") : "—"}
                  </td>
                  <td className="py-2.5 pr-3">{b.source_type}</td>
                  <td className="py-2.5 pr-3 font-data text-xs">{b.filename ?? "—"}</td>
                  <td className="py-2.5 pr-3 text-severity-success">{b.accepted}</td>
                  <td className="py-2.5 pr-3 text-severity-critical">{b.rejected}</td>
                  <td className="py-2.5">{b.uploaded_by}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardBody>
      </Card>
    </div>
  );
}
