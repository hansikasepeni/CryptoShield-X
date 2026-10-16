import statistics,time,tracemalloc
from pathlib import Path
from .scanner import scan_path
def run_benchmark(root,runs=5):
    if runs<1: raise ValueError("runs must be >= 1")
    durations=[]; peaks=[]; counts=[]; file_count=0
    for _ in range(runs):
        tracemalloc.start(); start=time.perf_counter(); findings,meta=scan_path(root)
        durations.append(time.perf_counter()-start); _,peak=tracemalloc.get_traced_memory(); tracemalloc.stop()
        peaks.append(peak); counts.append(len(findings)); file_count=meta["files_scanned"]
    return {"benchmark_type":"local_baseline_not_organizer_platform_A_B","input_path":str(Path(root).resolve()),
      "runs":runs,"files_scanned":file_count,"findings_per_run":counts,"duration_seconds":durations,
      "duration_mean_seconds":statistics.mean(durations),"duration_median_seconds":statistics.median(durations),
      "python_tracemalloc_peak_bytes":max(peaks),"memory_method_note":"Python allocation peak via tracemalloc; excludes some native/process memory.",
      "limitations":"Use organizer-specified Platform A/B environment and memory method for official results."}
