# Broker Liveness Process Drill Results

Generated: 2026-06-21T03:47:47.287Z
Overall: PASS

## Configuration

```json
{
  "fortress_id": "fortress:broker-liveness-process-drill",
  "heartbeat_interval_seconds": 1,
  "min_beats_required": 3,
  "runs_per_leg_required": 3,
  "production_default_reader_freshness_window_ms": 600000,
  "production_default_digest_window_ms": 86400000,
  "drill_reader_freshness_window_ms": 2500,
  "drill_digest_window_ms": 60000,
  "dead_detection_wait_ms": 3250,
  "temp_root_cleaned_after_capture": true
}
```

## Acceptance Criteria

| # | Criterion | Result | Evidence |
|---|---|---|---|
| 1 | Alive -> real beats | PASS | {"min_beats_required":3,"observed_counts":[{"phase":"silent_death","run":1,"beats":3},{"phase":"silent_death","run":2,"beats":3},{"phase":"silent_death","run":3,"beats":3},{"phase":"silent_death","run":4,"beats":3},{"phase":"clean_stop","run":1,"beats":3},{"phase":"clean_stop","run":2,"beats":3},{"phase":"clean_stop","run":3,"beats":3}]} |
| 2 | Silent death -> fault / dead_no_heartbeat | PASS | {"required_runs":3,"verdicts":[{"run":1,"status":"fault","basis":"dead_no_heartbeat"},{"run":2,"status":"fault","basis":"dead_no_heartbeat"},{"run":3,"status":"fault","basis":"dead_no_heartbeat"}]} |
| 3 | Clean stop -> no dead_no_heartbeat false alarm | PASS | {"required_runs":3,"verdicts":[{"run":1,"status":"unknown","basis":"intentionally_stopped","stand_down_count":1},{"run":2,"status":"unknown","basis":"intentionally_stopped","stand_down_count":1},{"run":3,"status":"unknown","basis":"intentionally_stopped","stand_down_count":1}]} |
| 4 | Honesty / un-greenable | PASS | {"source_phase_run":"honesty-forged-beat","assertions":{"real_beats_never_made_row_green":true,"real_silent_death_was_fault_before_forgery":true,"forged_in_process_beat_relabels_fault_to_non_green_unknown":true,"forged_in_process_beat_did_not_make_green":true,"daemon_invocation_count_remained_zero":true},"before_forgery":{"status":"fault","basis":"dead_no_heartbeat"},"after_forgery":{"status":"unknown","basis":"alive_no_recent_enforcement","invocation_count":0}} |
| 5 | Evidence capture | PASS | {"evidence_path":"/private/tmp/wt-broker-drill/docs/audit/broker-liveness-process-drill-2026-06-20.md","raw_entries_captured":28} |

## Phase A: Silent Death

### Run 1: PASS
```json
{
  "phase": "silent_death",
  "run": 1,
  "storage_label": "silent_death-1",
  "signal_sent": "SIGKILL",
  "child_pid": 38965,
  "child_exit": {
    "code": null,
    "signal": "SIGKILL"
  },
  "beat_count_before_signal": 3,
  "stand_down_count_after_exit": 0,
  "alive_verdict_before_signal": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "unknown",
    "basis": "alive_no_recent_enforcement",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "final_verdict_after_dead_window": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "fault",
    "basis": "dead_no_heartbeat",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "timings_ms": {
    "heartbeat_interval": 1000,
    "reader_freshness_window": 2500,
    "dead_detection_wait": 3250,
    "elapsed_to_min_beats": 2125,
    "elapsed_after_signal_to_verdict": 3273
  },
  "raw_broker_lifecycle_entries": [
    {
      "timestamp": "2026-06-21T03:47:08.908Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:09.910Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:10.911Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    }
  ],
  "child_stdout": "[audit-log] cross-process file locking enabled: /var/folders/tf/2m3v8md13vv8zm3hpxbfr6nw0000gn/T/broker-liveness-drill-B8fxR0/silent_death-1/state/_audit/.audit-write.lock\n{\"worker\":\"broker-liveness-process-drill\",\"pid\":38965,\"interval_seconds\":1}\n",
  "child_stderr": "",
  "assertions": {
    "observed_at_least_three_marked_beats": true,
    "alive_verdict_is_not_green": true,
    "alive_verdict_is_alive_idle_unknown": true,
    "final_verdict_is_fault_dead_no_heartbeat": true,
    "no_stand_down_marker_was_written": true
  },
  "pass": true
}
```

### Run 2: PASS
```json
{
  "phase": "silent_death",
  "run": 2,
  "storage_label": "silent_death-2",
  "signal_sent": "SIGKILL",
  "child_pid": 38978,
  "child_exit": {
    "code": null,
    "signal": "SIGKILL"
  },
  "beat_count_before_signal": 3,
  "stand_down_count_after_exit": 0,
  "alive_verdict_before_signal": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "unknown",
    "basis": "alive_no_recent_enforcement",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "final_verdict_after_dead_window": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "fault",
    "basis": "dead_no_heartbeat",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "timings_ms": {
    "heartbeat_interval": 1000,
    "reader_freshness_window": 2500,
    "dead_detection_wait": 3250,
    "elapsed_to_min_beats": 2204,
    "elapsed_after_signal_to_verdict": 3266
  },
  "raw_broker_lifecycle_entries": [
    {
      "timestamp": "2026-06-21T03:47:14.343Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:15.344Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:16.346Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    }
  ],
  "child_stdout": "[audit-log] cross-process file locking enabled: /var/folders/tf/2m3v8md13vv8zm3hpxbfr6nw0000gn/T/broker-liveness-drill-B8fxR0/silent_death-2/state/_audit/.audit-write.lock\n{\"worker\":\"broker-liveness-process-drill\",\"pid\":38978,\"interval_seconds\":1}\n",
  "child_stderr": "",
  "assertions": {
    "observed_at_least_three_marked_beats": true,
    "alive_verdict_is_not_green": true,
    "alive_verdict_is_alive_idle_unknown": true,
    "final_verdict_is_fault_dead_no_heartbeat": true,
    "no_stand_down_marker_was_written": true
  },
  "pass": true
}
```

### Run 3: PASS
```json
{
  "phase": "silent_death",
  "run": 3,
  "storage_label": "silent_death-3",
  "signal_sent": "SIGKILL",
  "child_pid": 38993,
  "child_exit": {
    "code": null,
    "signal": "SIGKILL"
  },
  "beat_count_before_signal": 3,
  "stand_down_count_after_exit": 0,
  "alive_verdict_before_signal": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "unknown",
    "basis": "alive_no_recent_enforcement",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "final_verdict_after_dead_window": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "fault",
    "basis": "dead_no_heartbeat",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "timings_ms": {
    "heartbeat_interval": 1000,
    "reader_freshness_window": 2500,
    "dead_detection_wait": 3250,
    "elapsed_to_min_beats": 2208,
    "elapsed_after_signal_to_verdict": 3267
  },
  "raw_broker_lifecycle_entries": [
    {
      "timestamp": "2026-06-21T03:47:19.822Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:20.824Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:21.826Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    }
  ],
  "child_stdout": "[audit-log] cross-process file locking enabled: /var/folders/tf/2m3v8md13vv8zm3hpxbfr6nw0000gn/T/broker-liveness-drill-B8fxR0/silent_death-3/state/_audit/.audit-write.lock\n{\"worker\":\"broker-liveness-process-drill\",\"pid\":38993,\"interval_seconds\":1}\n",
  "child_stderr": "",
  "assertions": {
    "observed_at_least_three_marked_beats": true,
    "alive_verdict_is_not_green": true,
    "alive_verdict_is_alive_idle_unknown": true,
    "final_verdict_is_fault_dead_no_heartbeat": true,
    "no_stand_down_marker_was_written": true
  },
  "pass": true
}
```

### Run 4: PASS
```json
{
  "phase": "silent_death",
  "run": 4,
  "storage_label": "honesty-forged-beat",
  "signal_sent": "SIGKILL",
  "child_pid": 38995,
  "child_exit": {
    "code": null,
    "signal": "SIGKILL"
  },
  "beat_count_before_signal": 3,
  "stand_down_count_after_exit": 0,
  "alive_verdict_before_signal": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "unknown",
    "basis": "alive_no_recent_enforcement",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "final_verdict_after_dead_window": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "fault",
    "basis": "dead_no_heartbeat",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "timings_ms": {
    "heartbeat_interval": 1000,
    "reader_freshness_window": 2500,
    "dead_detection_wait": 3250,
    "elapsed_to_min_beats": 2199,
    "elapsed_after_signal_to_verdict": 3266
  },
  "raw_broker_lifecycle_entries": [
    {
      "timestamp": "2026-06-21T03:47:25.313Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:26.315Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:27.317Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    }
  ],
  "child_stdout": "[audit-log] cross-process file locking enabled: /var/folders/tf/2m3v8md13vv8zm3hpxbfr6nw0000gn/T/broker-liveness-drill-B8fxR0/honesty-forged-beat/state/_audit/.audit-write.lock\n{\"worker\":\"broker-liveness-process-drill\",\"pid\":38995,\"interval_seconds\":1}\n",
  "child_stderr": "",
  "assertions": {
    "observed_at_least_three_marked_beats": true,
    "alive_verdict_is_not_green": true,
    "alive_verdict_is_alive_idle_unknown": true,
    "final_verdict_is_fault_dead_no_heartbeat": true,
    "no_stand_down_marker_was_written": true
  },
  "pass": true
}
```

## Phase B: Clean Stop

### Run 1: PASS
```json
{
  "phase": "clean_stop",
  "run": 1,
  "storage_label": "clean_stop-1",
  "signal_sent": "SIGTERM",
  "child_pid": 38998,
  "child_exit": {
    "code": 0,
    "signal": null
  },
  "beat_count_before_signal": 3,
  "stand_down_count_after_exit": 1,
  "alive_verdict_before_signal": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "unknown",
    "basis": "alive_no_recent_enforcement",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "final_verdict_after_dead_window": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "unknown",
    "basis": "intentionally_stopped",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "timings_ms": {
    "heartbeat_interval": 1000,
    "reader_freshness_window": 2500,
    "dead_detection_wait": 3250,
    "elapsed_to_min_beats": 2208,
    "elapsed_after_signal_to_verdict": 3329
  },
  "raw_broker_lifecycle_entries": [
    {
      "timestamp": "2026-06-21T03:47:30.840Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:31.843Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:32.845Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:32.959Z",
      "layer": "l3",
      "operation": "broker_daemon_stopped",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    }
  ],
  "child_stdout": "[audit-log] cross-process file locking enabled: /var/folders/tf/2m3v8md13vv8zm3hpxbfr6nw0000gn/T/broker-liveness-drill-B8fxR0/clean_stop-1/state/_audit/.audit-write.lock\n{\"worker\":\"broker-liveness-process-drill\",\"pid\":38998,\"interval_seconds\":1}\n",
  "child_stderr": "",
  "assertions": {
    "observed_at_least_three_marked_beats": true,
    "alive_verdict_is_not_green": true,
    "alive_verdict_is_alive_idle_unknown": true,
    "final_verdict_is_unknown_intentionally_stopped": true,
    "final_verdict_is_not_dead_no_heartbeat": true,
    "final_verdict_is_not_fault": true,
    "exactly_one_stand_down_marker_was_written": true
  },
  "pass": true
}
```

### Run 2: PASS
```json
{
  "phase": "clean_stop",
  "run": 2,
  "storage_label": "clean_stop-2",
  "signal_sent": "SIGTERM",
  "child_pid": 39016,
  "child_exit": {
    "code": 0,
    "signal": null
  },
  "beat_count_before_signal": 3,
  "stand_down_count_after_exit": 1,
  "alive_verdict_before_signal": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "unknown",
    "basis": "alive_no_recent_enforcement",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "final_verdict_after_dead_window": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "unknown",
    "basis": "intentionally_stopped",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "timings_ms": {
    "heartbeat_interval": 1000,
    "reader_freshness_window": 2500,
    "dead_detection_wait": 3250,
    "elapsed_to_min_beats": 2114,
    "elapsed_after_signal_to_verdict": 3330
  },
  "raw_broker_lifecycle_entries": [
    {
      "timestamp": "2026-06-21T03:47:36.372Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:37.374Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:38.376Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:38.419Z",
      "layer": "l3",
      "operation": "broker_daemon_stopped",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    }
  ],
  "child_stdout": "[audit-log] cross-process file locking enabled: /var/folders/tf/2m3v8md13vv8zm3hpxbfr6nw0000gn/T/broker-liveness-drill-B8fxR0/clean_stop-2/state/_audit/.audit-write.lock\n{\"worker\":\"broker-liveness-process-drill\",\"pid\":39016,\"interval_seconds\":1}\n",
  "child_stderr": "",
  "assertions": {
    "observed_at_least_three_marked_beats": true,
    "alive_verdict_is_not_green": true,
    "alive_verdict_is_alive_idle_unknown": true,
    "final_verdict_is_unknown_intentionally_stopped": true,
    "final_verdict_is_not_dead_no_heartbeat": true,
    "final_verdict_is_not_fault": true,
    "exactly_one_stand_down_marker_was_written": true
  },
  "pass": true
}
```

### Run 3: PASS
```json
{
  "phase": "clean_stop",
  "run": 3,
  "storage_label": "clean_stop-3",
  "signal_sent": "SIGTERM",
  "child_pid": 39029,
  "child_exit": {
    "code": 0,
    "signal": null
  },
  "beat_count_before_signal": 3,
  "stand_down_count_after_exit": 1,
  "alive_verdict_before_signal": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "unknown",
    "basis": "alive_no_recent_enforcement",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "final_verdict_after_dead_window": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "unknown",
    "basis": "intentionally_stopped",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "timings_ms": {
    "heartbeat_interval": 1000,
    "reader_freshness_window": 2500,
    "dead_detection_wait": 3250,
    "elapsed_to_min_beats": 2202,
    "elapsed_after_signal_to_verdict": 3326
  },
  "raw_broker_lifecycle_entries": [
    {
      "timestamp": "2026-06-21T03:47:41.843Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:42.845Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:43.845Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:43.957Z",
      "layer": "l3",
      "operation": "broker_daemon_stopped",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    }
  ],
  "child_stdout": "[audit-log] cross-process file locking enabled: /var/folders/tf/2m3v8md13vv8zm3hpxbfr6nw0000gn/T/broker-liveness-drill-B8fxR0/clean_stop-3/state/_audit/.audit-write.lock\n{\"worker\":\"broker-liveness-process-drill\",\"pid\":39029,\"interval_seconds\":1}\n",
  "child_stderr": "",
  "assertions": {
    "observed_at_least_three_marked_beats": true,
    "alive_verdict_is_not_green": true,
    "alive_verdict_is_alive_idle_unknown": true,
    "final_verdict_is_unknown_intentionally_stopped": true,
    "final_verdict_is_not_dead_no_heartbeat": true,
    "final_verdict_is_not_fault": true,
    "exactly_one_stand_down_marker_was_written": true
  },
  "pass": true
}
```

## Honesty / Forged Beat

```json
{
  "source_phase_run": "honesty-forged-beat",
  "fault_verdict_before_forged_beat": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "fault",
    "basis": "dead_no_heartbeat",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "verdict_after_forged_in_process_beat": {
    "origin_machine": "fortress:broker-liveness-process-drill",
    "feature_id": "secret_broker_daemon",
    "label": "Secret broker daemon (process liveness)",
    "liveness": "self_reporting",
    "status": "unknown",
    "basis": "alive_no_recent_enforcement",
    "invocation_count": 0,
    "last_evidence_at": null,
    "broken_zero_detectable": true,
    "audit_integrity_ok": true,
    "freshness_window_ms": 2500
  },
  "forged_entry_details": {
    "source": "drill-forged-in-process",
    "broker_source": "broker_daemon"
  },
  "raw_broker_lifecycle_entries_after_forgery": [
    {
      "timestamp": "2026-06-21T03:47:25.313Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:26.315Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:27.317Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "broker-server",
        "broker_source": "broker_daemon"
      }
    },
    {
      "timestamp": "2026-06-21T03:47:30.691Z",
      "layer": "l3",
      "operation": "broker_daemon_heartbeat",
      "identity_id": "fortress:broker-liveness-process-drill",
      "result": "success",
      "details": {
        "source": "drill-forged-in-process",
        "broker_source": "broker_daemon"
      }
    }
  ],
  "assertions": {
    "real_beats_never_made_row_green": true,
    "real_silent_death_was_fault_before_forgery": true,
    "forged_in_process_beat_relabels_fault_to_non_green_unknown": true,
    "forged_in_process_beat_did_not_make_green": true,
    "daemon_invocation_count_remained_zero": true
  },
  "pass": true
}
```

