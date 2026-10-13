/**
 * Upload Logs — send a log file through ingestion and detection, and
 * review the audit trail of previous uploads.
 */
import { useRef, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Upload } from "lucide-react";
import { logService } from "@/services/logService";
import { getErrorMessage } from "@/lib/apiError";
import { formatDateTime } from "@/lib/format";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Input,
  Notice,
  Select,
  Spinner,
  type NoticeMessage,
} from "@/components/ui";
import { SOURCE_TYPE_LABELS, type SourceType } from "@/types";

const FORMAT_HINTS: Record<SourceType, string> = {
  linux: "auth.log / syslog lines from sshd and sudo",
  windows: "Security events exported as a JSON array or one JSON object per line",
  firewall: "Lines like: 2026-07-19 10:02:11 DENY TCP 1.2.3.4:4431 -> 10.0.0.5:22 SYN",
  web_server: "Apache / Nginx access logs in Combined Log Format",
};

export function UploadLogsPage() {
  const queryClient = useQueryClient();
  const fileInput = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [sourceType, setSourceType] = useState<SourceType>("linux");
  const [sourceHost, setSourceHost] = useState("");
  const [notice, setNotice] = useState<NoticeMessage | null>(null);

  const batchesQuery = useQuery({ queryKey: ["logs", "batches"], queryFn: logService.listBatches });

  const uploadMutation = useMutation({
    mutationFn: () => logService.upload(file!, sourceType, sourceHost.trim() || undefined),
    onSuccess: (result) => {
      const recognised = result.accepted + result.duplicates;
      setNotice(
        recognised === 0
          ? {
              tone: "error",
              text: `No ${SOURCE_TYPE_LABELS[sourceType]} log records were recognised in this file. Check the source type.`,
            }
          : {
              tone: "success",
              text:
                `Stored ${result.accepted} new log(s); skipped ${result.duplicates} already ingested` +
                (result.rejected ? ` and ${result.rejected} invalid` : "") +
                ". Detection has run on the new logs.",
            }
      );
      setFile(null);
      if (fileInput.current) fileInput.current.value = "";
      for (const key of ["logs", "analytics", "detections", "alerts", "incidents"]) {
        queryClient.invalidateQueries({ queryKey: [key] });
      }
    },
    onError: (error) => setNotice({ tone: "error", text: getErrorMessage(error, "Upload failed.") }),
  });

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (file) uploadMutation.mutate();
  };

  const batches = batchesQuery.data?.batches ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Upload Logs</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Ingest Windows, Linux, firewall, or web server logs. Parsing, threat detection, and incident
          correlation run automatically after upload.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Ingest a file</CardTitle>
        </CardHeader>
        <CardBody>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-3">
              <Select
                label="Source type"
                name="source-type"
                value={sourceType}
                onChange={(event) => setSourceType(event.target.value as SourceType)}
              >
                {Object.entries(SOURCE_TYPE_LABELS).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </Select>
              <Input
                label="Source host (optional)"
                name="source-host"
                placeholder="e.g. web01"
                value={sourceHost}
                onChange={(event) => setSourceHost(event.target.value)}
              />
              <div className="flex flex-col gap-1.5">
                <label htmlFor="log-file" className="text-sm font-medium text-text-secondary">
                  File (.log, .txt, .json — up to 25 MB)
                </label>
                <input
                  id="log-file"
                  ref={fileInput}
                  type="file"
                  accept=".log,.txt,.json"
                  className="block w-full text-sm text-text-secondary file:mr-3 file:rounded-md file:border-0 file:bg-accent-blue file:px-3 file:py-2 file:text-sm file:text-white"
                  onChange={(event) => setFile(event.target.files?.[0] ?? null)}
                />
              </div>
            </div>
            <p className="text-xs text-text-muted">Expected format: {FORMAT_HINTS[sourceType]}.</p>

            {notice && <Notice tone={notice.tone}>{notice.text}</Notice>}

            <Button type="submit" isLoading={uploadMutation.isPending} disabled={!file}>
              <Upload className="h-4 w-4" />
              Upload and detect
            </Button>
          </form>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recent uploads</CardTitle>
        </CardHeader>
        <CardBody className="overflow-x-auto">
          {batchesQuery.isLoading ? (
            <Spinner />
          ) : batchesQuery.isError ? (
            <Notice tone="error">{getErrorMessage(batchesQuery.error, "Could not load upload history.")}</Notice>
          ) : batches.length === 0 ? (
            <p className="py-6 text-center text-sm text-text-muted">Nothing has been uploaded yet.</p>
          ) : (
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead className="text-2xs uppercase text-text-muted">
                <tr>
                  <th className="pb-3 pr-3">Uploaded</th>
                  <th className="pb-3 pr-3">Source</th>
                  <th className="pb-3 pr-3">File</th>
                  <th className="pb-3 pr-3">New</th>
                  <th className="pb-3 pr-3">Duplicates</th>
                  <th className="pb-3 pr-3">Rejected</th>
                  <th className="pb-3">By</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {batches.map((batch) => (
                  <tr key={batch.batch_id}>
                    <td className="py-2.5 pr-3 font-data text-text-secondary">{formatDateTime(batch.created_at)}</td>
                    <td className="py-2.5 pr-3">{SOURCE_TYPE_LABELS[batch.source_type]}</td>
                    <td className="py-2.5 pr-3 font-data text-xs">{batch.filename ?? "—"}</td>
                    <td className="py-2.5 pr-3 font-data text-severity-success">{batch.accepted}</td>
                    <td className="py-2.5 pr-3 font-data text-text-secondary">{batch.duplicates}</td>
                    <td className="py-2.5 pr-3 font-data text-severity-critical">{batch.rejected}</td>
                    <td className="py-2.5">{batch.uploaded_by}</td>
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
