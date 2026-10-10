# Reviewer liveness shared by every review host: the Codex and Claude
# wrappers and the Grok adapter (docs/reviewer-liveness-design.md). One copy
# keeps the providers on the same stall rule; a per-provider copy drifted
# before. The review wait itself stays unbounded: this module makes a quiet
# reviewer VISIBLE and never times out, kills or retries one.
#
# Trusted review copies (the pre-commit hook's HEAD extraction, the merge
# gate's base extraction and LOCAL manifest snapshots) carry this module beside
# the wrappers, so a candidate cannot weaken the liveness code that watches its
# own review.

# ---------------------------------------------------------------------------
# Heartbeat helper: pure-.NET background thread that writes
# `[<label>-heartbeat] reviewing at HH:MM:SS` to stderr on a fixed interval
# while a silent reviewer CLI runs (the hosts redirect the child's stdout AND
# stderr away from the parent stream).
#
# Implementation uses Add-Type to compile inline C# so the thread body is
# a pure .NET method with no PowerShell runspace dependency. A previous
# attempt used a PowerShell scriptblock cast to ParameterizedThreadStart;
# Codex caught this BLOCKER because
# PS-scriptblock-to-delegate conversion requires a runspace on the
# executing thread and raw System.Threading.Thread has none, so the
# callback would fail silently and no heartbeat would ever fire.
#
# The class is guarded by a type-existence check so repeated invocations
# in the same AppDomain reuse the compiled type.
# ---------------------------------------------------------------------------
function Get-AdversarialReviewHeartbeat {
  # docs/reviewer-liveness-design.md: the beat samples EVIDENCE FILES
  # -- artifacts that grow only while the reviewer under it actually works
  # (codex per-pass events NDJSON; the claude stream file; the grok CLI
  # Messages stream) -- PER FILE,
  # never aggregate: codex passes run concurrently, and an aggregate delta
  # stays nonzero while any one pass works, hiding a stalled sibling. Each
  # watched file carries its own growth state; a quiet ACTIVE file past the
  # threshold escalates a self-clearing STALL-SUSPECT naming that file,
  # while a file whose OWNING PROCESS is no longer alive is exempt --
  # quiet with a dead owner is completion or a crash, both reported by the
  # parent's own exit handling, never a stall (marker files were measured
  # wrong: the pre-seeded crash sentinel survives a hard child crash).
  # Samples and escalation transitions are appended, timestamped, to a
  # run-owned LIVENESS LOG (best-effort, loud on failure) so the
  # post-run audit can
  # reconstruct quiet intervals the console alone cannot. Warn, never kill:
  # the review wait stays unbounded per the port contract. An empty
  # evidence dir runs the plain timer beat. The type
  # name is VERSIONED: a loaded type can never be redefined in-process, so
  # an older definition must never shadow this method set.
  if (-not ('AdversarialReviewHeartbeatV6' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;

// Timestamps format with InvariantCulture throughout: the ISO-8601 shape
// of the liveness log's ts field is a contract, and a non-Gregorian
// active culture would otherwise write its own calendar's year inside an
// ISO-looking string, corrupting audit chronology.
public class AdversarialReviewHeartbeatV6 {
    private Thread thread;
    private ManualResetEvent stopEvent;
    private string heartbeatLabel;
    private int heartbeatIntervalMs;
    private string evidenceDir;
    private string evidencePattern;
    private int stallWarnMs;
    private string logPath;
    private Dictionary<string, int> pidByName;
    private bool logWarned;
    private bool samplingWarned;
    private Dictionary<string, long> lastSize;
    // Quiet-time decisions run on THIS monotonic clock (elapsed ms since
    // Start): an adjustable wall clock stepped forward would fabricate a
    // stall and stepped backward would suppress one. Wall time appears
    // only inside emitted record timestamps.
    private System.Diagnostics.Stopwatch clock;
    private Dictionary<string, double> lastGrowthMs;
    private Dictionary<string, bool> escalated;
    private Dictionary<string, bool> probeWarned;

    public void Start(string label, int intervalMs, string dir, string pattern, int stallMs, string liveLog, string pidSpec) {
        heartbeatLabel = label;
        heartbeatIntervalMs = intervalMs;
        evidenceDir = dir;
        evidencePattern = pattern;
        stallWarnMs = stallMs;
        logPath = liveLog;
        pidByName = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrEmpty(pidSpec)) {
            string[] pairs = pidSpec.Split(';');
            for (int i = 0; i < pairs.Length; i++) {
                int eq = pairs[i].IndexOf('=');
                if (eq <= 0) { continue; }
                int pid;
                if (int.TryParse(pairs[i].Substring(eq + 1), out pid)) { pidByName[pairs[i].Substring(0, eq)] = pid; }
            }
        }
        logWarned = false;
        clock = System.Diagnostics.Stopwatch.StartNew();
        lastSize = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        lastGrowthMs = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        escalated = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        probeWarned = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        samplingWarned = false;
        // Every EXPECTED evidence file is watched from t=0 even before it
        // exists: absence is quiet evidence (a reviewer hung before ever
        // creating its output is exactly the blind-wait shape), so the
        // quiet clock for the whole expected set seeds at invocation. The
        // pid map names the per-pass files; a wildcard-free pattern names
        // its single expected file.
        foreach (string expected in pidByName.Keys) {
            lastGrowthMs[expected] = 0.0;
            lastSize[expected] = -1;
        }
        if (!string.IsNullOrEmpty(pattern) && pattern.IndexOf('*') < 0 && pattern.IndexOf('?') < 0 && !lastGrowthMs.ContainsKey(pattern)) {
            lastGrowthMs[pattern] = 0.0;
            lastSize[pattern] = -1;
        }
        // The start record is appended SYNCHRONOUSLY, before the sampling
        // thread exists: the run-owned liveness log is expected for every
        // run that launched (lazy creation on the first beat left a run
        // that ended inside the first interval with no artifact at all).
        // Appends stay best-effort -- a persistent failure warns loudly
        // rather than silently thinning the record.
        AppendLog("{\"ts\":\"" + DateTime.Now.ToString("yyyy-MM-dd'T'HH:mm:ss.fffK", CultureInfo.InvariantCulture) + "\",\"event\":\"start\",\"label\":\"" + label + "\",\"stallWarnMs\":" + stallMs + ",\"intervalMs\":" + intervalMs + "}");
        stopEvent = new ManualResetEvent(false);
        thread = new Thread(new ThreadStart(Run));
        thread.IsBackground = true;
        thread.Start();
    }

    private void AppendLog(string line) {
        if (string.IsNullOrEmpty(logPath)) { return; }
        // A concurrent reader that opened the log without write sharing
        // briefly denies the append. Transition records are emitted exactly
        // once, so a bounded retry keeps them from being lost to a
        // transient reader; only a persistent failure falls through to
        // the warn-once drop. Forensics only either way -- a log failure
        // must never break the review, but a SILENT loss would re-open
        // the audit gap.
        for (int attempt = 0; ; attempt++) {
            try {
                using (FileStream fs = new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.Read)) {
                    byte[] bytes = new UTF8Encoding(false).GetBytes(line + "\n");
                    fs.Write(bytes, 0, bytes.Length);
                }
                return;
            } catch (IOException ex) {
                if (attempt < 24) { Thread.Sleep(20); continue; }
                WarnLogOnce(ex);
                return;
            } catch (Exception ex) {
                WarnLogOnce(ex);
                return;
            }
        }
    }

    private void WarnLogOnce(Exception ex) {
        if (!logWarned) {
            logWarned = true;
            Console.Error.WriteLine("[" + heartbeatLabel + "-heartbeat] WARN: liveness log append failed (" + ex.Message + "); samples continue on the console only");
        }
    }

    private bool IsPassDone(string filePath) {
        // A file's pass is DONE (escalation-exempt) when its OWNING PROCESS
        // is no longer alive: quiet-with-dead-owner is completion or a
        // crash, both reported loudly by the parent's own exit handling --
        // never a stall for the beat to re-report. (Marker files were
        // measured wrong here: the pre-seeded crash sentinel survives a
        // hard child crash and would have escalated a dead pass forever.)
        // A file with NO mapping counts active (claude's single stream:
        // the CLI runs in the wrapper's pipeline, so its death ends the
        // beat). Pid reuse inside a run's window can delay an exemption
        // or, at worst, hold a completed pass's quiet file
        // escalation-eligible -- the warn-only false-STALL-SUSPECT
        // residual docs/reviewer-liveness-design.md records. Only the POSITIVE gone-process
        // shape exempts; any other probe failure keeps the file
        // stall-eligible and is reported once -- mapping an unknown owner
        // state to exempt would silently disable stall detection, the
        // exact blind-wait condition this class exists to close.
        string name = Path.GetFileName(filePath);
        int pid;
        if (pidByName == null || !pidByName.TryGetValue(name, out pid)) { return false; }
        try {
            using (System.Diagnostics.Process p = System.Diagnostics.Process.GetProcessById(pid)) {
                return p.HasExited;
            }
        } catch (ArgumentException) {
            return true;
        } catch (Exception ex) {
            bool warned; probeWarned.TryGetValue(name, out warned);
            if (!warned) {
                probeWarned[name] = true;
                Console.Error.WriteLine("[" + heartbeatLabel + "-heartbeat] WARN: owner-process probe failed for " + name + " (" + ex.Message + "); the file stays stall-eligible");
                AppendLog("{\"ts\":\"" + DateTime.Now.ToString("yyyy-MM-dd'T'HH:mm:ss.fffK", CultureInfo.InvariantCulture) + "\",\"event\":\"probe-error\",\"file\":\"" + name + "\"}");
            }
            return false;
        }
    }

    private void Run() {
        // The FIRST sample runs before any wait: observation clocks seed at
        // invocation time, so a file quiet from launch escalates once the
        // threshold passes -- waiting an interval before the first sample
        // pushed every escalation one full beat late.
        do { Beat(); } while (!stopEvent.WaitOne(heartbeatIntervalMs));
    }

    private void Beat() {
        string stamp = DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture);
        string iso = DateTime.Now.ToString("yyyy-MM-dd'T'HH:mm:ss.fffK", CultureInfo.InvariantCulture);
        string[] files;
        try {
            if (string.IsNullOrEmpty(evidenceDir)) {
                Console.Error.WriteLine("[" + heartbeatLabel + "-heartbeat] reviewing at " + stamp);
                return;
            }
            if (!Directory.Exists(evidenceDir)) {
                // A configured-but-vanished evidence dir is a sampling
                // failure, never a silent downgrade to a timer beat --
                // that downgrade would quietly disable stall detection.
                if (!samplingWarned) {
                    samplingWarned = true;
                    Console.Error.WriteLine("[" + heartbeatLabel + "-heartbeat] WARN: evidence dir '" + evidenceDir + "' is missing; stall detection is DEGRADED to timer beats until it returns");
                    AppendLog("{\"ts\":\"" + iso + "\",\"event\":\"sampling-error\",\"detail\":\"evidence dir missing\"}");
                }
                Console.Error.WriteLine("[" + heartbeatLabel + "-heartbeat] reviewing at " + stamp + " (evidence sampling DEGRADED)");
                return;
            }
            files = Directory.GetFiles(evidenceDir, evidencePattern, SearchOption.TopDirectoryOnly);
            samplingWarned = false;
        } catch (Exception ex) {
            if (!samplingWarned) {
                samplingWarned = true;
                Console.Error.WriteLine("[" + heartbeatLabel + "-heartbeat] WARN: evidence enumeration failed (" + ex.Message + "); stall detection is DEGRADED to timer beats until it recovers");
                AppendLog("{\"ts\":\"" + iso + "\",\"event\":\"sampling-error\",\"detail\":\"enumeration failed\"}");
            }
            Console.Error.WriteLine("[" + heartbeatLabel + "-heartbeat] reviewing at " + stamp + " (evidence sampling DEGRADED)");
            return;
        }
        // The walk covers the UNION of files on disk and files the clock
        // dictionaries already track (the Start-seeded expected set, plus
        // anything sampled earlier): a file that never appears -- or
        // vanishes -- must keep aging toward escalation, not fall out of
        // the walk with GetFiles.
        double nowMs = clock.Elapsed.TotalMilliseconds;
        Dictionary<string, string> presentPaths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < files.Length; i++) { presentPaths[Path.GetFileName(files[i])] = files[i]; }
        List<string> watchNames = new List<string>(presentPaths.Keys);
        foreach (string tracked in lastGrowthMs.Keys) { if (!presentPaths.ContainsKey(tracked)) { watchNames.Add(tracked); } }
        watchNames.Sort(StringComparer.Ordinal);
        StringBuilder summary = new StringBuilder();
        StringBuilder logBeat = new StringBuilder();
        logBeat.Append("{\"ts\":\"").Append(iso).Append("\",\"beat\":[");
        List<string> stallLines = new List<string>();
        List<string> transitions = new List<string>();
        bool first = true;
        for (int i = 0; i < watchNames.Count; i++) {
            string name = watchNames[i];
            string path; bool exists = presentPaths.TryGetValue(name, out path);
            bool missing = !exists;
            long size = -1;
            bool sizeError = false;
            if (exists) { try { size = new FileInfo(path).Length; } catch { sizeError = true; } }
            long prev; bool had = lastSize.TryGetValue(name, out prev);
            long delta = 0;
            // GROWTH means new reviewer output only: creation of an
            // expected file, or a positive size increase. Truncation and
            // shrink are recorded (negative delta) but never touch the
            // quiet clock -- resetting on ANY size change would let a
            // corrupting writer look like a working reviewer.
            bool grew = false;
            if (missing) {
                // An absent file is QUIET evidence, not an error: the
                // clock keeps aging from its seed so never-created output
                // escalates like never-grown output, and later creation
                // registers as growth.
                if (!had) { lastGrowthMs[name] = nowMs; lastSize[name] = -1; }
            } else if (sizeError) {
                // Unknown size proves neither growth nor quiet: the
                // growth clock is left untouched (the file keeps its
                // existing stall eligibility) and the failure is
                // recorded in the beat rather than silently read as a
                // fresh sample.
                if (!had) { lastGrowthMs[name] = nowMs; lastSize[name] = -1; }
            } else {
                if (!had) { lastGrowthMs[name] = nowMs; }
                else if (prev < 0 && size >= 0) { grew = true; }
                else if (size > prev) { grew = true; }
                delta = (had && prev >= 0) ? (size - prev) : 0;
                lastSize[name] = size;
                if (grew) { lastGrowthMs[name] = nowMs; }
            }
            bool done = IsPassDone(name);
            double quietSecs = (nowMs - lastGrowthMs[name]) / 1000.0;
            if (quietSecs < 0) { quietSecs = 0; }
            bool stalled = (!done) && stallWarnMs > 0 && (quietSecs * 1000.0) >= stallWarnMs;
            bool wasEscalated; escalated.TryGetValue(name, out wasEscalated);
            if (stalled && !wasEscalated) { transitions.Add("{\"ts\":\"" + iso + "\",\"event\":\"stall-suspect\",\"file\":\"" + name + "\",\"quietSecs\":" + ((int)quietSecs) + "}"); }
            if (!stalled && wasEscalated) {
                // stall-cleared is RESERVED for growth from a still-active
                // owner; a dead owner takes precedence even when final
                // output landed in the same interval -- a crash after a
                // last write must never read as recovery in the audit log.
                if (done) { transitions.Add("{\"ts\":\"" + iso + "\",\"event\":\"owner-exited\",\"file\":\"" + name + "\",\"quietSecs\":" + ((int)quietSecs) + "}"); }
                else { transitions.Add("{\"ts\":\"" + iso + "\",\"event\":\"stall-cleared\",\"file\":\"" + name + "\",\"quietSecs\":" + ((int)quietSecs) + "}"); }
            }
            escalated[name] = stalled;
            if (stalled) {
                // The console line names the FULL path: concurrent runs
                // (tagged panel children, parallel repos) interleave one
                // console, and a bare basename cannot be correlated back
                // to its run's announced evidence dir.
                if (missing) {
                    stallLines.Add("[" + heartbeatLabel + "-heartbeat] STALL-SUSPECT at " + stamp + ": '" + Path.Combine(evidenceDir, name) + "' has not been created after " + ((int)quietSecs) + "s and its pass is still active (the review is NOT killed - inspect the child process)");
                } else {
                    stallLines.Add("[" + heartbeatLabel + "-heartbeat] STALL-SUSPECT at " + stamp + ": '" + Path.Combine(evidenceDir, name) + "' has grown nothing for " + ((int)quietSecs) + "s and its pass is still active (" + size + " bytes; the review is NOT killed - inspect the file and the child process)");
                }
            }
            if (!first) { summary.Append(", "); logBeat.Append(","); }
            first = false;
            summary.Append(name).Append("=").Append(missing ? "absent" : size.ToString()).Append("(").Append(delta >= 0 ? "+" : "").Append(delta).Append(")");
            logBeat.Append("{\"name\":\"").Append(name).Append("\",\"size\":").Append(size).Append(",\"delta\":").Append(delta).Append(",\"active\":").Append(done ? "false" : "true").Append(",\"quietSecs\":").Append((int)quietSecs).Append(",\"stalled\":").Append(stalled ? "true" : "false").Append(",\"sizeError\":").Append(sizeError ? "true" : "false").Append(",\"missing\":").Append(missing ? "true" : "false").Append("}");
        }
        logBeat.Append("]}");
        if (watchNames.Count == 0) {
            Console.Error.WriteLine("[" + heartbeatLabel + "-heartbeat] reviewing at " + stamp + " (no evidence files yet)");
        } else {
            Console.Error.WriteLine("[" + heartbeatLabel + "-heartbeat] reviewing at " + stamp + " (evidence: " + summary.ToString() + ")");
        }
        for (int i = 0; i < stallLines.Count; i++) { Console.Error.WriteLine(stallLines[i]); }
        AppendLog(logBeat.ToString());
        for (int i = 0; i < transitions.Count; i++) { AppendLog(transitions[i]); }
    }

    public bool Stop() {
        if (stopEvent == null) { return true; }
        stopEvent.Set();
        bool joined = true;
        if (thread != null && thread.IsAlive) {
            // A beat's work is bounded (a handful of file samples, each
            // append's retry window brief and bounded), so an
            // extended-but-bounded join is decisive in practice while a
            // single short window could expire inside one slow beat.
            joined = thread.Join(2000);
            for (int extra = 0; !joined && extra < 26; extra++) { joined = thread.Join(500); }
        }
        if (joined) {
            stopEvent.Dispose();
            stopEvent = null;
        } else {
            // The beat thread did not confirm termination: disposing its
            // wait handle would throw on the still-running thread, and a
            // late beat could race the caller's artifact preservation.
            // The handle is RETAINED (released at process exit) and the
            // caller receives the false verdict so preservation can say
            // the log may not be final.
            Console.Error.WriteLine("[" + heartbeatLabel + "-heartbeat] WARN: the beat thread did not stop within its join window; final liveness records may still be arriving while artifacts are preserved");
            AppendLog("{\"ts\":\"" + DateTime.Now.ToString("yyyy-MM-dd'T'HH:mm:ss.fffK", CultureInfo.InvariantCulture) + "\",\"event\":\"stop-incomplete\"}");
        }
        return joined;
    }
}
'@
  }
  return New-Object AdversarialReviewHeartbeatV6
}

# The stall-warning threshold knob (docs/reviewer-liveness-design.md):
# CROSS_REVIEW_STALL_WARN_SECS, default 300, admitted only in 30..86400 --
# rejected outside it, never clamped. Same env-knob contract as the other
# gate vars: UNSET or blank takes the default; a SET-but-invalid value is an
# invocation/config error the caller fails closed on (Ok=$false), never a
# silent fallback that would hide a typo'd threshold.
function Resolve-StallWarnMs {
  param([string]$Raw)
  if ([string]::IsNullOrWhiteSpace($Raw)) { return @{ Ok = $true; Ms = 300000 } }
  $secs = 0
  if (-not [int]::TryParse($Raw.Trim(), [ref]$secs)) { return @{ Ok = $false; Ms = 0 } }
  if ($secs -lt 30 -or $secs -gt 86400) { return @{ Ok = $false; Ms = 0 } }
  return @{ Ok = $true; Ms = ($secs * 1000) }
}

# REVIEW-DURATION-SECS producer (docs/reviewer-liveness-design.md): the
# FLOOR of the elapsed wall seconds as a non-negative base-10 integer.
# PowerShell's [int] cast rounds to nearest ([int]1.9 -> 2), which would
# overstate a review by a second, and a negative elapsed input would
# violate the non-negative grammar -- so the floor and the zero clamp are
# explicit here.
function Get-ReviewDurationSecs {
  param([Parameter(Mandatory)][double]$ElapsedSeconds)
  if ($ElapsedSeconds -lt 0) { return 0 }
  return [int][Math]::Floor($ElapsedSeconds)
}

Export-ModuleMember -Function Get-AdversarialReviewHeartbeat, Resolve-StallWarnMs, Get-ReviewDurationSecs
