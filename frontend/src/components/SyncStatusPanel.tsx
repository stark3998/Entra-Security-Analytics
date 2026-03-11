import { useEffect, useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { syncLogs, fetchSyncStatus, type SyncStatus } from "../api";

interface Props {
  /** Query keys to invalidate when sync completes (e.g. ["signin-logs"]) */
  invalidateKeys: string[][];
}

const LEVEL_CLASS: Record<string, string> = {
  ERROR: "sync-log-error",
  WARNING: "sync-log-warn",
  INFO: "sync-log-info",
  DEBUG: "sync-log-debug",
};

export default function SyncStatusPanel({ invalidateKeys }: Props) {
  const queryClient = useQueryClient();
  const [showPanel, setShowPanel] = useState(false);
  const logEndRef = useRef<HTMLDivElement>(null);

  // Poll sync status — enabled when panel is open
  const { data: status } = useQuery<SyncStatus>({
    queryKey: ["sync-status"],
    queryFn: fetchSyncStatus,
    refetchInterval: showPanel ? 1500 : false,
    enabled: showPanel,
  });

  const syncMutation = useMutation({
    mutationFn: syncLogs,
    onSuccess: () => setShowPanel(true),
  });

  // Auto-scroll log viewer to bottom
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [status?.entries.length]);

  // When sync completes, invalidate queries so the log table refreshes
  useEffect(() => {
    if (status?.state === "completed" || status?.state === "failed") {
      const timer = setTimeout(() => {
        for (const key of invalidateKeys) {
          queryClient.invalidateQueries({ queryKey: key });
        }
      }, 1000);
      return () => clearTimeout(timer);
    }
  }, [status?.state, invalidateKeys, queryClient]);

  const isRunning = status?.state === "running";
  const isBusy = syncMutation.isPending || isRunning;

  return (
    <div className="sync-panel-wrapper">
      <div className="page-header-row">
        <div className="sync-header-actions">
          <button
            className="btn btn-primary"
            disabled={isBusy}
            onClick={() => syncMutation.mutate()}
          >
            {isBusy ? "Syncing…" : "Sync Logs"}
          </button>
          {(status?.state === "running" || status?.state === "completed" || status?.state === "failed") && (
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setShowPanel((v) => !v)}
            >
              {showPanel ? "Hide Logs" : "View Sync Logs"}
            </button>
          )}
          {status?.state === "running" && (
            <span className="sync-status-badge sync-badge-running">Running</span>
          )}
          {status?.state === "completed" && (
            <span className="sync-status-badge sync-badge-completed">Completed</span>
          )}
          {status?.state === "failed" && (
            <span className="sync-status-badge sync-badge-failed">Failed</span>
          )}
        </div>
      </div>

      {syncMutation.isError && (
        <div className="error-box">Sync failed: {String(syncMutation.error)}</div>
      )}

      {showPanel && status && status.entries.length > 0 && (
        <div className="sync-log-panel">
          <div className="sync-log-header">
            <span className="sync-log-title">
              Sync Log
              {status.started_at && (
                <span className="sync-log-time">
                  {" "}— started {new Date(status.started_at).toLocaleTimeString()}
                </span>
              )}
            </span>
            <button
              className="sync-log-close"
              onClick={() => setShowPanel(false)}
              title="Close"
            >
              ✕
            </button>
          </div>
          <div className="sync-log-body">
            {status.entries.map((entry, i) => (
              <div key={i} className={`sync-log-line ${LEVEL_CLASS[entry.level] ?? ""}`}>
                <span className="sync-log-ts">
                  {new Date(entry.timestamp).toLocaleTimeString()}
                </span>
                <span className={`sync-log-level sync-level-${entry.level.toLowerCase()}`}>
                  {entry.level}
                </span>
                <span className="sync-log-msg">{entry.message}</span>
              </div>
            ))}
            <div ref={logEndRef} />
          </div>
        </div>
      )}
    </div>
  );
}
