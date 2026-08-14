/* eslint-disable @typescript-eslint/no-explicit-any */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  CheckSquare,
  ChevronLeft,
  ChevronRight,
  Database,
  Download,
  FileText,
  FolderOpen,
  HardDrive,
  Layers,
  Loader2,
  Lock,
  Play,
  RefreshCw,
  ScanSearch,
  Search,
  ShieldCheck,
  Square,
  Terminal,
  Unlock,
  X,
} from "lucide-react";
import { Reveal, SectionHeading } from "./Reveal";

/* ---------------------------------------------------------------- types */

type Health = {
  ok: boolean;
  version: string;
  is_root: boolean;
  output_root: string;
  writes_allowed: boolean;
  carvers: number;
  filesystems: number;
  can_elevate: boolean;
};

type Privileges = {
  ok: boolean;
  is_root: boolean;
  pkexec: boolean;
  sudo: boolean;
  sudo_nopasswd: boolean;
  has_display: boolean;
  preferred: string;
  note: string;
  inaccessible_disks: number;
};

type Disk = {
  name: string;
  display_name: string;
  device_path: string;
  type: string;
  type_label: string;
  size_bytes: number;
  size_human: string;
  removable: boolean;
  rotational: boolean;
  accessible: boolean;
  status_message: string;
  partition_count: number;
};

type Partition = {
  entry: number;
  label?: string;
  name?: string;
  filesystem?: string;
  fs_status?: string;
  size_bytes: number;
  start_byte: number;
  start_lba: number;
  type?: string;
};

type DeletedPartition = {
  start_byte: number;
  size_bytes: number;
  filesystem?: string;
  note?: string;
  recovered?: boolean;
};

type PartitionsResult = {
  partition_table?: string;
  count: number;
  deleted_count: number;
  image_size: number;
  partitions: Partition[];
  deleted_partitions: DeletedPartition[];
  gpt_primary_ok?: boolean;
  gpt_backup_ok?: boolean;
  error?: string;
  warnings?: string[];
};

type ResultFile = {
  index: number;
  name: string;
  path: string;
  ext: string;
  size: number;
  recoverable: number;
  deleted: boolean;
  dir: boolean;
  kind: string;
  method: string;
  confidence: number;
  mtime_iso: string;
  compressed: boolean;
  encrypted: boolean;
  ads: boolean;
};

type ResultsPage = {
  ok: boolean;
  total: number;
  matched: number;
  offset: number;
  limit: number;
  files: ResultFile[];
  by_ext: Record<string, number>;
};

type Job = {
  id: string;
  kind: string;
  state: string;
  phase?: string;
  percent: number;
  found?: number;
  error?: string;
  started_ms: number;
  finished_ms?: number;
  result?: Record<string, any>;
};

type BrowseEntry = { name: string; is_dir: boolean; size: number };

type Screen = "source" | "partitions" | "workspace";
type Modal = "elevate" | "attach" | "carve" | "extract" | null;

/* -------------------------------------------------------------- helpers */

function token() {
  return sessionStorage.getItem("ghostToken") || "";
}

async function apiGet(path: string) {
  const h: Record<string, string> = {};
  const t = token();
  if (t) h["X-Ghost-Token"] = t;
  const r = await fetch(path, { headers: h });
  return r.json();
}

async function apiPost(path: string, body: unknown) {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  const t = token();
  if (t) h["X-Ghost-Token"] = t;
  const r = await fetch(path, { method: "POST", headers: h, body: JSON.stringify(body || {}) });
  return r.json();
}

function fmtSize(b: number | undefined) {
  const n = Number(b) || 0;
  const u = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  const s = v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2);
  return s + " " + u[i];
}

function fmtNum(n: number | undefined) {
  return (Number(n) || 0).toLocaleString();
}

function fmtDuration(ms: number) {
  const s = Math.round(ms / 1000);
  if (s < 60) return s + "s";
  return Math.floor(s / 60) + "m " + (s % 60) + "s";
}

function contentUrl(job: string, index: number, max?: number) {
  const t = token();
  return (
    `/api/content?job=${encodeURIComponent(job)}&index=${index}` +
    (max ? `&max=${max}` : "") +
    (t ? `&tok=${t}` : "")
  );
}

const IMG = [
  "jpg",
  "jpeg",
  "png",
  "gif",
  "bmp",
  "webp",
  "tif",
  "tiff",
  "ico",
  "svg",
  "heic",
  "heif",
  "avif",
];
const VID = ["mp4", "m4v", "mkv", "webm", "avi", "mov", "flv", "3gp", "ts", "mpg", "mpeg", "wmv"];
const AUD = [
  "mp3",
  "wav",
  "flac",
  "ogg",
  "oga",
  "opus",
  "m4a",
  "aac",
  "aiff",
  "ac3",
  "amr",
  "mid",
  "wma",
  "au",
];
const TXT = [
  "txt",
  "md",
  "log",
  "json",
  "xml",
  "html",
  "htm",
  "csv",
  "yaml",
  "yml",
  "ini",
  "conf",
  "toml",
  "py",
  "sh",
  "js",
  "ts",
  "c",
  "cpp",
  "h",
  "hpp",
  "rs",
  "go",
  "java",
  "rb",
  "php",
  "sql",
  "pem",
  "service",
  "gitconfig",
  "tex",
  "dockerfile",
  "cmake",
  "env",
  "eml",
  "mbox",
];

const PART_COLOURS = [
  "bg-cyan-400",
  "bg-emerald-400",
  "bg-amber-400",
  "bg-purple-400",
  "bg-rose-500",
  "bg-orange-400",
  "bg-sky-400",
  "bg-lime-400",
  "bg-yellow-300",
  "bg-fuchsia-400",
];

const btn =
  "inline-flex items-center gap-1.5 rounded border border-border px-3 py-1.5 font-mono text-[11px] tracking-widest uppercase transition-colors hover:border-primary/60 hover:text-primary disabled:pointer-events-none disabled:opacity-40";
const btnPrimary = btn + " border-primary/60 bg-primary/10 text-primary";
const btnWarn =
  btn +
  " border-amber-500/40 bg-amber-500/10 text-amber-300 hover:border-amber-400/70 hover:text-amber-200";
const inputCls =
  "w-full rounded border border-border bg-surface/50 px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground/60 focus:border-primary/60 focus:outline-none";
const pillOk =
  "rounded border border-emerald-400/40 bg-emerald-400/10 px-1.5 py-0.5 font-mono text-[10px] tracking-wider text-emerald-300";
const pillWarn =
  "rounded border border-amber-400/40 bg-amber-400/10 px-1.5 py-0.5 font-mono text-[10px] tracking-wider text-amber-300";
const pillBad =
  "rounded border border-rose-400/40 bg-rose-400/10 px-1.5 py-0.5 font-mono text-[10px] tracking-wider text-rose-300";

/* ----------------------------------------------------------------- app */

export function Console() {
  const [health, setHealth] = useState<Health | null>(null);
  const [offline, setOffline] = useState(false);
  const [privileges, setPrivileges] = useState<Privileges | null>(null);
  const [carverCats, setCarverCats] = useState<string[]>([]);

  const [screen, setScreen] = useState<Screen>("source");
  const [disks, setDisks] = useState<Disk[]>([]);
  const [disksBusy, setDisksBusy] = useState(false);
  const [selDisk, setSelDisk] = useState<string | null>(null);
  const [source, setSource] = useState<{
    path: string;
    offset: number;
    length: number;
    size: number;
    fs?: string;
    label?: string;
    uuid?: string;
    title?: string;
  } | null>(null);
  const [parts, setParts] = useState<PartitionsResult | null>(null);
  const [partBusy, setPartBusy] = useState(false);
  const [deepPartScan, setDeepPartScan] = useState(false);

  const [job, setJob] = useState<Job | null>(null);
  const [summary, setSummary] = useState<Record<string, any> | null>(null);
  const [results, setResults] = useState<ResultsPage | null>(null);
  const [resultJob, setResultJob] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [filter, setFilter] = useState({ q: "", ext: "", only: "", sort: "" });
  const [selIndex, setSelIndex] = useState(-1);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [fileInfo, setFileInfo] = useState<Record<string, any> | null>(null);

  const [modal, setModal] = useState<Modal>(null);
  const [modalData, setModalData] = useState<Record<string, any>>({});
  const [browsePath, setBrowsePath] = useState("");
  const [browseEntries, setBrowseEntries] = useState<BrowseEntry[]>([]);

  const [elevating, setElevating] = useState<Record<string, any> | null>(null);
  const [logs, setLogs] = useState<{ t: string; msg: string; level: string }[]>([]);
  const [logOpen, setLogOpen] = useState(false);
  const [notice, setNotice] = useState<{ kind: string; msg: string } | null>(null);

  const pollRef = useRef<number | null>(null);
  const elevCancelRef = useRef(false);
  const jobIdRef = useRef<string | null>(null);

  const log = useCallback((msg: string, level = "ok") => {
    setLogs((l) => [...l.slice(-80), { t: new Date().toLocaleTimeString(), msg, level }]);
  }, []);

  const showNotice = (kind: string, msg: string) => {
    setNotice({ kind, msg });
    window.setTimeout(() => setNotice(null), 9000);
  };

  /* ------------------------------------------------------------- boot */

  const loadDisks = useCallback(async () => {
    setDisksBusy(true);
    try {
      const r = await apiGet("/api/disks");
      if (r && r.ok) setDisks(r.disks || []);
    } catch {
      /* offline */
    }
    setDisksBusy(false);
  }, []);

  const refresh = useCallback(async () => {
    try {
      const h = await apiGet("/api/health");
      if (!h || !h.ok) {
        setOffline(true);
        return;
      }
      setOffline(false);
      setHealth(h);
      if (!h.is_root) {
        try {
          const p = await apiGet("/api/privileges");
          setPrivileges(p);
        } catch {
          /* non-fatal */
        }
      }
      if (screen === "source") await loadDisks();
    } catch {
      setOffline(true);
    }
  }, [loadDisks, screen]);

  useEffect(() => {
    refresh();
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
      elevCancelRef.current = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* ------------------------------------------------------------- source */

  const openSource = useCallback(
    async (path: string) => {
      if (!path) return;
      log("identifying " + path);
      let det: any;
      try {
        det = await apiPost("/api/detect", { image_path: path });
      } catch (e: any) {
        log("detect failed: " + e.message, "err");
        return;
      }
      if (det.ok === false) {
        showNotice("err", det.error || "could not identify that source");
        return;
      }
      const r = det.result;
      const src = { path, offset: 0, length: 0, size: r.size_bytes || 0 };

      if (r.is_container && (r.container === "gpt" || r.container === "mbr")) {
        setSource({ ...src });
        setParts(null);
        setScreen("partitions");
        loadPartitions(path, false);
        return;
      }
      if (r.is_container) log(r.note || "", "warn");

      setSource({
        ...src,
        fs: r.filesystem,
        label: r.label,
        uuid: r.uuid,
        title: r.detected ? `${path}: ${r.filesystem}${r.label ? " " + r.label : ""}` : path,
      });
      log(
        r.detected
          ? `${path}: ${r.filesystem}${r.label ? " " + r.label : ""} (${fmtSize(r.size_bytes)})`
          : `${path}: no filesystem detected — carving only`,
        r.detected ? "ok" : "warn",
      );
      enterWorkspace({ path, offset: 0, length: 0, size: r.size_bytes || 0 });
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [log],
  );

  const loadPartitions = useCallback(
    async (path: string, deep: boolean) => {
      setPartBusy(true);
      try {
        const r = await apiPost("/api/partitions", {
          image_path: path,
          find_deleted: deep,
        });
        setParts(r.result || null);
        if (r.result) {
          const p = r.result;
          log(
            `${(p.partition_table || "unknown").toUpperCase()}: ${p.count} partition(s)` +
              (p.deleted_count ? `, ${p.deleted_count} other region(s)` : ""),
            p.count ? "ok" : "warn",
          );
          (p.warnings || []).forEach((w: string) => log(w, "warn"));
          if (p.error) log(p.error, "warn");
        }
      } catch (e: any) {
        log("partition scan failed: " + e.message, "err");
      }
      setPartBusy(false);
    },
    [log],
  );

  const pickDisk = (i: number) => {
    const d = disks[i];
    if (!d) return;
    setSelDisk(d.device_path);
    if (!d.accessible && health && !health.is_root) {
      setModal("elevate");
      return;
    }
  };

  const continueToSource = async () => {
    if (!selDisk) return;
    await openSource(selDisk);
  };

  const usePartition = (i: number) => {
    const p = parts?.partitions[i];
    if (!p || !source) return;
    log(`selected partition ${p.entry}: ${p.filesystem || p.type || ""}`, "ok");
    enterWorkspace({
      path: source.path,
      offset: p.start_byte,
      length: p.size_bytes,
      size: p.size_bytes,
      fs: p.filesystem,
      label: p.label || p.name,
      title: `Partition ${p.entry}${p.label ? " " + p.label : ""}`,
    });
  };

  const useRegion = (i: number) => {
    const p = parts?.deleted_partitions[i];
    if (!p || !source) return;
    log(`selected ${p.recovered ? "recovered volume" : "free space"}`, "warn");
    enterWorkspace({
      path: source.path,
      offset: p.start_byte,
      length: p.size_bytes,
      size: p.size_bytes,
      fs: p.filesystem || "",
      title: p.recovered ? "Recovered volume" : "Unallocated space",
    });
  };

  const useWholeDisk = () => {
    if (!source) return;
    log("working on the whole disk — carving only", "warn");
    enterWorkspace({ ...source, offset: 0, length: 0, fs: "", title: "Whole disk" });
  };

  /* ---------------------------------------------------------- workspace */

  const enterWorkspace = (src: typeof source) => {
    setSource(src);
    setScreen("workspace");
    setResults(null);
    setSummary(null);
    setResultJob(null);
    setSelIndex(-1);
    setSelected(new Set());
    setPage(0);
  };

  const backToVolumes = () => {
    setScreen(parts ? "partitions" : "source");
  };

  const loadResults = useCallback(
    async (p: number, f: typeof filter, jobId: string) => {
      const q = new URLSearchParams({
        job: jobId,
        offset: String(p * 200),
        limit: "200",
        q: f.q,
        ext: f.ext,
        only: f.only,
        sort: f.sort,
      });
      try {
        const r = await apiGet("/api/results?" + q.toString());
        if (!r.ok) throw new Error(r.error);
        setResults(r);
        if (p * 200 >= r.matched && r.matched > 0) {
          const np = Math.floor((r.matched - 1) / 200);
          setPage(np);
          loadResults(np, f, jobId);
        }
      } catch (e: any) {
        log("could not load results: " + e.message, "err");
      }
    },
    [log],
  );

  const pollJob = useCallback(
    (id: string) => {
      if (pollRef.current) window.clearInterval(pollRef.current);
      pollRef.current = window.setInterval(async () => {
        try {
          const r = await apiGet("/api/job?id=" + encodeURIComponent(id));
          if (!r.ok) throw new Error(r.error);
          const j: Job = r.job;
          setJob(j);
          if (["done", "failed", "cancelled"].includes(j.state)) {
            if (pollRef.current) window.clearInterval(pollRef.current);
            pollRef.current = null;
            onJobFinished(j);
          }
        } catch (e: any) {
          if (pollRef.current) window.clearInterval(pollRef.current);
          pollRef.current = null;
          log("lost track of the job: " + e.message, "err");
        }
      }, 400);
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [log],
  );

  const onJobFinished = (j: Job) => {
    const kind = j.kind;
    if (j.state === "failed") {
      log(`${kind} failed: ${j.error || "unknown error"}`, "err");
      showNotice("err", `${kind} failed: ${j.error || "unknown error"}`);
      return;
    }
    if (j.state === "cancelled") {
      log(`${kind} cancelled`, "warn");
      return;
    }
    const res = j.result || {};

    if (kind === "extract") {
      log(
        `recovered ${fmtNum(res.files_written)} file(s) → ${res.output_dir}`,
        res.ok ? "ok" : "err",
      );
      if (res.error) log(res.error, "err");
      showNotice(
        res.ok ? "ok" : "err",
        `Recovered ${fmtNum(res.files_written)} file(s) to ${res.output_dir}` +
          (res.files_failed ? `\n${res.files_failed} failed` : ""),
      );
      return;
    }
    if (kind === "image") {
      log(`clone finished: ${fmtSize(res.bytes_copied)} copied`, res.ok ? "ok" : "err");
      showNotice("ok", `Clone written to ${res.output_path}`);
      return;
    }
    if (kind === "raid") {
      log(
        `array assembled: ${fmtSize(res.bytes_written)} → ${res.output_path}`,
        res.ok ? "ok" : "err",
      );
      if (res.ok) showNotice("ok", `Array assembled to ${res.output_path}`);
      else if (res.error) showNotice("err", res.error);
      return;
    }

    setSummary(res);
    setResultJob(j.id);
    jobIdRef.current = j.id;
    setPage(0);
    setSelIndex(-1);
    setSelected(new Set());
    if (res.scan && !res.scan.ok && res.scan.error) log("scan: " + res.scan.error, "warn");
    if (res.carve && res.carve.error) log("carve: " + res.carve.error, "warn");
    log(
      `${kind} finished in ${fmtDuration((j.finished_ms || j.started_ms) - j.started_ms)}: ${fmtNum(res.file_count)} file(s)`,
      "ok",
    );
    loadResults(0, filter, j.id);
  };

  const startJob = async (kind: string, extra?: Record<string, any>) => {
    if (job && (job.state === "running" || job.state === "queued")) return;
    if (!source) return;
    const body: Record<string, any> = {
      image_path: source.path,
      offset: source.offset || 0,
      partition_size: source.length || 0,
      filesystem: kind === "carve" ? "" : source.fs || "",
      ...(extra || {}),
    };
    log(`starting ${kind}…`);
    try {
      const r = await apiPost("/api/" + kind, body);
      if (!r.ok) {
        log(r.error || "could not start", "err");
        showNotice("err", r.error || "could not start");
        return;
      }
      setJob({
        id: r.job,
        kind,
        state: "queued",
        phase: "starting",
        percent: 0,
        started_ms: Date.now(),
      });
      pollJob(r.job);
    } catch (e: any) {
      log("start failed: " + e.message, "err");
    }
  };

  const cancelJob = async () => {
    if (!job) return;
    await apiPost("/api/job/cancel", { id: job.id });
    log("cancelling…", "warn");
  };

  const setSort = (key: string) => {
    setFilter((f) => {
      const nf = { ...f, sort: f.sort === key ? "" : key };
      if (resultJob) loadResults(0, nf, resultJob);
      return nf;
    });
    setPage(0);
  };

  const applyFilter = (patch: Partial<typeof filter>) => {
    setFilter((f) => {
      const nf = { ...f, ...patch };
      if (resultJob) loadResults(0, nf, resultJob);
      return nf;
    });
    setPage(0);
  };

  const toggleSel = (i: number) => {
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(i)) n.delete(i);
      else n.add(i);
      return n;
    });
  };

  const selectAllShown = () => {
    setSelected((s) => {
      const n = new Set(s);
      (results?.files || []).forEach((f) => n.add(f.index));
      return n;
    });
  };

  const selectFile = async (f: ResultFile) => {
    setSelIndex(f.index);
    if (!resultJob) return;
    try {
      const r = await apiGet(`/api/fileinfo?job=${encodeURIComponent(resultJob)}&index=${f.index}`);
      if (r.ok) setFileInfo(r);
    } catch {
      /* non-fatal */
    }
  };

  /* ---------------------------------------------------------- elevation */

  const elevate = async (method: string) => {
    const body: Record<string, any> = { method };
    if (method === "sudo-password") {
      const pw = (document.getElementById("ghost-sudopw") as HTMLInputElement)?.value || "";
      if (!pw) return;
      body.password = pw;
      (document.getElementById("ghost-sudopw") as HTMLInputElement).value = "";
    }
    setElevating({
      phase: "authenticating",
      title: method === "pkexec" ? "Waiting for authentication" : "Restarting with disk access",
      message:
        method === "pkexec"
          ? "Complete the prompt your desktop just opened. If you cannot see it, check behind this window."
          : "Starting the privileged engine…",
    });
    elevCancelRef.current = false;

    let r: any;
    try {
      r = await apiPost("/api/elevate", body);
    } catch {
      log("elevation request lost at the network layer; polling…", "warn");
      waitForElevated(method);
      return;
    }
    if (!r.ok) {
      if ((r.error || "").indexOf("already in progress") >= 0) {
        log("an elevation is already running — waiting for it", "warn");
        waitForElevated(method);
        return;
      }
      setElevating({
        phase: "failed",
        title: "Could not start",
        message: (r.error || "") + (r.hint ? " — " + r.hint : ""),
      });
      log("elevation failed: " + r.error, "err");
      return;
    }
    log("elevation requested via " + method);
    if (r.token) sessionStorage.setItem("ghostToken", r.token);
    setElevating((e) => ({ ...e, message: r.message || (e && e.message) }));
    waitForElevated(method);
  };

  const waitForElevated = async (method: string) => {
    const deadline = Date.now() + 180000;
    let silence = 0;
    while (Date.now() < deadline) {
      await new Promise((r2) => setTimeout(r2, 600));
      if (elevCancelRef.current) return;
      let h: Health | null = null;
      try {
        h = await apiGet("/api/health");
      } catch {
        /* the handover moment */
      }
      if (h) silence = 0;
      else silence++;

      if (h && h.is_root) {
        setHealth(h);
        setPrivileges(null);
        setElevating(null);
        setModal(null);
        log("disk access unlocked — the engine is now running with full privileges", "ok");
        loadDisks();
        setScreen("source");
        return;
      }

      if (h) {
        try {
          const st = await apiGet("/api/elevate/status");
          if (st && st.failed) {
            setElevating({
              phase: "failed",
              title:
                method === "pkexec"
                  ? "Authentication was not completed"
                  : "Could not get administrator access",
              message: st.detail || "The privileged engine did not start.",
            });
            log("elevation failed: " + (st.detail || "unknown reason"), "err");
            return;
          }
        } catch {
          /* ignore */
        }
      }

      setElevating((e) =>
        e && e.phase !== "failed"
          ? {
              ...e,
              message:
                method === "pkexec"
                  ? silence > 20
                    ? "Waiting for the engine to come back after the switch…"
                    : "Waiting for the authentication dialog…"
                  : "Waiting for the privileged engine to take over…",
            }
          : e,
      );
    }
    setElevating({
      phase: "failed",
      title: "Timed out",
      message:
        "The authentication was not completed. Try again, or quit and run: sudo ghost_recover",
    });
  };

  /* ------------------------------------------------------------- modals */

  const openModal = (name: Exclude<Modal, null>) => {
    setModal(name);
    setModalData({});
    if (name === "attach") browseTo(browsePath || "~");
    if (name === "carve") loadCarvers();
    if (name === "elevate") refreshPrivileges();
  };

  const refreshPrivileges = async () => {
    try {
      setPrivileges(await apiGet("/api/privileges"));
    } catch {
      /* non-fatal */
    }
  };

  const loadCarvers = async () => {
    try {
      const r = await apiGet("/api/carvers");
      if (r.ok) setCarverCats(r.categories || []);
    } catch {
      /* non-fatal */
    }
  };

  const browseTo = async (path: string) => {
    try {
      const r = await apiGet("/api/browse?path=" + encodeURIComponent(path));
      if (!r.ok) throw new Error(r.error);
      setBrowsePath(r.path);
      setBrowseEntries(r.entries || []);
    } catch (e: any) {
      log("browse failed: " + e.message, "err");
    }
  };

  const joinPath = (a: string, b: string) => {
    if (b === "..") {
      const p = a.replace(/\/[^/]*$/, "");
      return p || "/";
    }
    return a.endsWith("/") ? a + b : a + "/" + b;
  };

  const pickBrowse = (e: BrowseEntry) => {
    if (e.is_dir) browseTo(joinPath(browsePath, e.name));
    else setModalData((d) => ({ ...d, path: joinPath(browsePath, e.name) }));
  };

  const attachConfirm = () => {
    const p = (modalData.path || "").trim();
    if (!p) return;
    setModal(null);
    openSource(p);
  };

  const runCarve = () => {
    const d = modalData;
    setModal(null);
    startJob("carve", {
      categories: d.cats || [],
      unallocated_only: !!d.unalloc,
      text_carving: !!d.text,
      validate: !d.novalidate,
      max_files: d.max || 20000,
    });
  };

  const runExtract = () => {
    const d = modalData;
    const dest = (d.dest || ((health && health.output_root) || "") + "/recovered").trim();
    const indices = Array.from(selected);
    setModal(null);
    log(`recovering ${indices.length || "all"} file(s) to ${dest}`);
    (async () => {
      try {
        const r = await apiPost("/api/extract", {
          job: resultJob,
          output_dir: dest,
          indices,
          preserve_paths: !d.flat,
          preserve_times: !d.notimes,
          write_manifest: !d.nohash,
          compute_hashes: !d.nohash,
        });
        if (!r.ok) {
          log(r.error, "err");
          showNotice("err", r.error);
          return;
        }
        setJob({
          id: r.job,
          kind: "extract",
          state: "queued",
          phase: "starting",
          percent: 0,
          started_ms: Date.now(),
        });
        pollJob(r.job);
      } catch (e: any) {
        log("recover failed: " + e.message, "err");
      }
    })();
  };

  const shutdownEngine = () => {
    if (!window.confirm("Stop the engine and release the port?")) return;
    apiPost("/api/shutdown", {}).catch(() => {});
    setOffline(true);
  };

  /* -------------------------------------------------------------- render */

  const busy = !!job && (job.state === "running" || job.state === "queued");

  const stepState = (name: Screen) => {
    const order: Screen[] = ["source", "partitions", "workspace"];
    const cur = order.indexOf(screen);
    const me = order.indexOf(name);
    return me < cur ? "done" : me === cur ? "active" : "";
  };

  const stepClass = (s: string) =>
    s === "active"
      ? "text-primary border-primary/50"
      : s === "done"
        ? "text-emerald-300 border-emerald-400/30"
        : "text-muted-foreground/60 border-border/50";

  return (
    <section
      id="console"
      className="relative border-y border-border/70 bg-surface/25 py-24 sm:py-32"
    >
      <div className="mx-auto max-w-7xl px-5">
        <SectionHeading
          kicker="live console"
          title={
            <>
              Start a <span className="text-spectral">recovery</span>
            </>
          }
          blurb="When you run the engine, this console talks to it on localhost — pick a disk or image, scan or carve it, and download the results. Everything is read-only."
        />

        <Reveal>
          <div className="mt-12 overflow-hidden rounded-2xl border border-border bg-card shadow-spectral">
            {/* topbar */}
            <div className="flex flex-wrap items-center gap-3 border-b border-border bg-surface-2/60 px-4 py-3">
              <span className="flex items-center gap-2 font-mono text-xs font-bold tracking-[0.2em]">
                <Terminal className="h-3.5 w-3.5 text-primary" /> CONSOLE
                {health && (
                  <span className="rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 font-mono text-[10px] tracking-widest text-primary">
                    v{health.version}
                  </span>
                )}
              </span>

              <div className="flex items-center gap-1.5 font-mono text-[10px]">
                {(["source", "partitions", "workspace"] as Screen[]).map((s, i) => (
                  <span key={s} className="flex items-center gap-1.5">
                    {i > 0 && <span className="text-muted-foreground/40">›</span>}
                    <span
                      className={`flex items-center gap-1 rounded border px-1.5 py-0.5 tracking-widest uppercase ${stepClass(stepState(s))}`}
                    >
                      <span>{i + 1}</span>
                      {s === "partitions" ? "Volume" : s === "workspace" ? "Recover" : "Source"}
                    </span>
                  </span>
                ))}
              </div>

              <div className="grow" />

              {offline ? (
                <span className="font-mono text-[10px] tracking-wider text-rose-300">
                  engine offline
                </span>
              ) : (
                <>
                  {health && health.is_root ? (
                    <span className={pillOk}>
                      <ShieldCheck className="mr-1 inline h-3 w-3" /> full disk access
                    </span>
                  ) : (
                    <button className={btnWarn} onClick={() => openModal("elevate")}>
                      <Lock className="h-3 w-3" /> Unlock disk access
                    </button>
                  )}
                  <span className="flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
                    <span
                      className={`h-1.5 w-1.5 rounded-full ${busy ? "bg-rose-400" : "bg-emerald-400"}`}
                    />
                    {busy ? job.phase || "working" : "idle"}
                  </span>
                  <button className={btn} onClick={() => setLogOpen((v) => !v)}>
                    Log {logs.length ? `(${logs.length})` : ""}
                  </button>
                  {health && (
                    <button
                      className={btn}
                      onClick={shutdownEngine}
                      title="Stop the engine and release the port"
                    >
                      Shut down
                    </button>
                  )}
                </>
              )}
            </div>

            {offline ? (
              <div className="p-10 text-center">
                <Terminal className="mx-auto h-8 w-8 text-muted-foreground/50" />
                <p className="mt-4 font-mono text-sm text-foreground/90">
                  The engine is not running here.
                </p>
                <p className="mx-auto mt-2 max-w-xl text-xs leading-6 text-muted-foreground">
                  This console activates when you launch the release binary on your machine — it
                  serves this page at <span className="font-mono text-primary">127.0.0.1:3030</span>{" "}
                  with the full recovery engine behind it. On GitHub Pages only the static marketing
                  site is available.
                </p>
              </div>
            ) : (
              <>
                {notice && (
                  <div
                    className={`flex items-start gap-2 border-b px-4 py-2.5 font-mono text-[11px] ${
                      notice.kind === "err"
                        ? "border-rose-400/30 bg-rose-400/10 text-rose-300"
                        : "border-emerald-400/30 bg-emerald-400/10 text-emerald-300"
                    }`}
                  >
                    <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <pre className="whitespace-pre-wrap">{notice.msg}</pre>
                  </div>
                )}

                {screen === "source" && (
                  <div className="p-4 sm:p-6">
                    <h3 className="font-mono text-sm tracking-widest text-foreground uppercase">
                      Choose a source
                    </h3>
                    <p className="mt-1 text-xs text-muted-foreground">
                      Pick a physical disk, or open a disk image (.img, .dd, .raw, .iso, .vmdk).
                      Everything is opened read-only.
                    </p>

                    <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                      {disks.length === 0 && !disksBusy && (
                        <div className="col-span-full rounded-xl border border-border/60 bg-surface/30 px-4 py-5 text-center font-mono text-xs text-muted-foreground">
                          No block devices are readable. Restart the engine with sudo to see
                          physical disks, or open a disk image below.
                        </div>
                      )}
                      {disks.map((d, i) => {
                        const sel = selDisk === d.device_path;
                        return (
                          <button
                            key={d.device_path}
                            onClick={() => pickDisk(i)}
                            className={`rounded-xl border bg-surface/30 p-4 text-left transition-colors ${
                              sel
                                ? "border-primary/60 bg-primary/5"
                                : "border-border/60 hover:border-primary/40"
                            }`}
                          >
                            <div className="flex items-start gap-3">
                              <HardDrive className="mt-0.5 h-5 w-5 shrink-0 text-primary/70" />
                              <div className="min-w-0 grow">
                                <div className="truncate font-mono text-xs font-semibold text-foreground">
                                  {d.display_name || d.name}
                                </div>
                                <div className="truncate font-mono text-[10px] text-muted-foreground">
                                  {d.device_path}
                                </div>
                                <div className="mt-1 text-[10px] text-muted-foreground">
                                  {d.type_label}
                                  {d.partition_count
                                    ? ` · ${d.partition_count} partition${d.partition_count === 1 ? "" : "s"}`
                                    : ""}
                                </div>
                                {!d.accessible && (
                                  <div className="mt-2 flex items-center gap-1.5 font-mono text-[10px] text-amber-300">
                                    <Lock className="h-3 w-3" /> {d.status_message}
                                  </div>
                                )}
                              </div>
                              <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                                {fmtSize(d.size_bytes)}
                              </span>
                            </div>
                          </button>
                        );
                      })}
                      {disksBusy && (
                        <div className="col-span-full flex items-center justify-center gap-2 py-4 font-mono text-xs text-muted-foreground">
                          <Loader2 className="h-3.5 w-3.5 animate-spin" /> scanning devices…
                        </div>
                      )}
                    </div>

                    <div className="mt-5 flex flex-wrap items-center gap-2.5">
                      <button className={btn} onClick={() => loadDisks()}>
                        <RefreshCw className="h-3 w-3" /> Rescan devices
                      </button>
                      <button className={btn} onClick={() => openModal("attach")}>
                        <FolderOpen className="h-3 w-3" /> Open image file…
                      </button>
                      {health && !health.is_root && (
                        <button className={btnWarn} onClick={() => openModal("elevate")}>
                          <Lock className="h-3 w-3" /> Unlock disk access
                        </button>
                      )}
                      <div className="grow" />
                      <button className={btnPrimary} disabled={!selDisk} onClick={continueToSource}>
                        Continue →
                      </button>
                    </div>
                  </div>
                )}

                {screen === "partitions" && source && (
                  <div className="p-4 sm:p-6">
                    <h3 className="truncate font-mono text-sm text-foreground">{source.path}</h3>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {fmtSize(parts ? parts.image_size : source.size)} ·{" "}
                      {(parts && (parts.partition_table || "unknown").toUpperCase()) || "…"} table
                      {parts && parts.partition_table === "gpt" && (
                        <span className="ml-2">
                          primary GPT{" "}
                          {parts.gpt_primary_ok ? (
                            <span className={pillOk}>valid</span>
                          ) : (
                            <span className={pillBad}>damaged</span>
                          )}{" "}
                          backup GPT{" "}
                          {parts.gpt_backup_ok ? (
                            <span className={pillOk}>valid</span>
                          ) : (
                            <span className={pillBad}>damaged</span>
                          )}
                        </span>
                      )}
                    </p>

                    {parts && parts.error && (
                      <div className="mt-3 rounded border border-amber-400/40 bg-amber-400/10 px-3 py-2 font-mono text-[11px] text-amber-200">
                        {parts.error}
                      </div>
                    )}
                    {(parts?.warnings || []).map((w) => (
                      <div
                        key={w}
                        className="mt-2 rounded border border-amber-400/40 bg-amber-400/10 px-3 py-2 font-mono text-[11px] text-amber-200"
                      >
                        {w}
                      </div>
                    ))}

                    {/* partition map */}
                    <div className="mt-4 flex h-8 w-full overflow-hidden rounded border border-border/60 bg-surface/40">
                      {parts &&
                        (() => {
                          const segs: {
                            w: number;
                            c?: string;
                            label: string;
                            onClick: () => void;
                            title: string;
                          }[] = [];
                          const total = parts.image_size || source.size || 1;
                          const all = [
                            ...(parts.partitions || []).map((x, i) => ({
                              x,
                              kind: "part",
                              idx: i,
                            })),
                            ...(parts.deleted_partitions || []).map((x, i) => ({
                              x,
                              kind: x.recovered ? "rec" : "free",
                              idx: i,
                            })),
                          ].sort((a, b) => a.x.start_byte - b.x.start_byte);
                          let prevEnd = 0;
                          all.forEach((sg) => {
                            if (sg.x.start_byte > prevEnd) {
                              const pct = ((sg.x.start_byte - prevEnd) / total) * 100;
                              if (pct >= 0.4)
                                segs.push({
                                  w: pct,
                                  label: "",
                                  onClick: () => {},
                                  title: "gap",
                                });
                            }
                            const pct = (sg.x.size_bytes / total) * 100;
                            prevEnd = sg.x.start_byte + sg.x.size_bytes;
                            if (pct < 0.4) return;
                            if (sg.kind === "part")
                              segs.push({
                                w: pct,
                                c: PART_COLOURS[sg.idx % PART_COLOURS.length],
                                label: "P" + sg.x.entry,
                                onClick: () => pickPartition(sg.idx),
                                title: `${sg.x.filesystem || sg.x.type || ""} · ${fmtSize(sg.x.size_bytes)}`,
                              });
                            else if (sg.kind === "rec")
                              segs.push({
                                w: pct,
                                c: "bg-orange-400",
                                label: "REC",
                                onClick: () => pickRegion(sg.idx),
                                title: `recovered volume · ${fmtSize(sg.x.size_bytes)}`,
                              });
                            else
                              segs.push({
                                w: pct,
                                label: "FREE",
                                onClick: () => pickRegion(sg.idx),
                                title: `free space · ${fmtSize(sg.x.size_bytes)}`,
                              });
                          });
                          if (!segs.length)
                            segs.push({
                              w: 100,
                              label: partBusy ? "scanning…" : "no partitions",
                              onClick: () => {},
                              title: "",
                            });
                          return segs.map((s, i) => (
                            <button
                              key={i}
                              onClick={s.onClick}
                              title={s.title}
                              className={`flex h-full items-center justify-center overflow-hidden font-mono text-[9px] text-black/80 ${
                                s.c || "bg-surface-2 text-muted-foreground"
                              }`}
                              style={{ width: s.w + "%" }}
                            >
                              {s.label}
                            </button>
                          ));
                        })()}
                    </div>
                    {parts && (parts.partitions || []).length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1">
                        {parts.partitions.slice(0, 10).map((x, i) => (
                          <span
                            key={i}
                            className="flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground"
                          >
                            <span
                              className={`h-2 w-2 rounded-sm ${PART_COLOURS[i % PART_COLOURS.length]}`}
                            />
                            P{x.entry} {x.filesystem || x.type || ""}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* partition table */}
                    <div className="no-scrollbar mt-4 overflow-x-auto rounded-lg border border-border/60">
                      <table className="w-full font-mono text-[11px]">
                        <thead>
                          <tr className="border-b border-border bg-surface-2/60 text-left text-[10px] tracking-wider text-muted-foreground uppercase">
                            <th className="px-3 py-2">#</th>
                            <th className="px-3 py-2">Volume</th>
                            <th className="px-3 py-2">Filesystem</th>
                            <th className="px-3 py-2">State</th>
                            <th className="px-3 py-2 text-right">Size</th>
                            <th className="px-3 py-2">Start LBA</th>
                            <th className="px-3 py-2">Type</th>
                            <th className="px-3 py-2"></th>
                          </tr>
                        </thead>
                        <tbody>
                          {(parts?.partitions || []).map((x, i) => (
                            <tr
                              key={i}
                              onClick={() => pickPartition(i)}
                              className="cursor-pointer border-b border-border/40 last:border-0 hover:bg-surface-2/40"
                            >
                              <td
                                className="px-3 py-2 font-bold"
                                style={{ color: `var(--color-primary)` }}
                              >
                                P{x.entry}
                              </td>
                              <td className="px-3 py-2 text-foreground">
                                {x.label || x.name || "—"}
                              </td>
                              <td className="px-3 py-2 text-emerald-300">
                                {x.filesystem || (
                                  <span className="text-muted-foreground/50">—</span>
                                )}
                              </td>
                              <td className="px-3 py-2">
                                {x.fs_status === "healthy" && (
                                  <span className={pillOk}>healthy</span>
                                )}
                                {x.fs_status === "damaged" && (
                                  <span className={pillBad}>damaged</span>
                                )}
                                {!x.fs_status && (
                                  <span className={pillWarn}>{x.fs_status || "unknown"}</span>
                                )}
                              </td>
                              <td className="px-3 py-2 text-right text-muted-foreground">
                                {fmtSize(x.size_bytes)}
                              </td>
                              <td className="px-3 py-2 text-muted-foreground">
                                {fmtNum(x.start_lba)}
                              </td>
                              <td className="px-3 py-2 text-muted-foreground">{x.type}</td>
                              <td className="px-3 py-2 text-right">
                                <button
                                  className={btn + " !px-2 !py-1"}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    pickPartition(i);
                                  }}
                                >
                                  Open
                                </button>
                              </td>
                            </tr>
                          ))}
                          {(parts?.deleted_partitions || []).map((x, i) => (
                            <tr
                              key={"d" + i}
                              onClick={() => pickRegion(i)}
                              className="cursor-pointer border-b border-border/40 last:border-0 opacity-80 hover:bg-surface-2/40"
                            >
                              <td className="px-3 py-2 text-muted-foreground/60">
                                {x.recovered ? "⟳" : "—"}
                              </td>
                              <td className="px-3 py-2 text-muted-foreground/60">
                                {x.recovered ? "Recovered volume" : "Free space"}
                              </td>
                              <td className="px-3 py-2 text-amber-300">
                                {x.filesystem || (
                                  <span className="text-muted-foreground/50">—</span>
                                )}
                              </td>
                              <td className="px-3 py-2">
                                {x.recovered ? (
                                  <span className={pillWarn}>recovered</span>
                                ) : (
                                  <span className="text-muted-foreground/60">unallocated</span>
                                )}
                              </td>
                              <td className="px-3 py-2 text-right text-muted-foreground">
                                {fmtSize(x.size_bytes)}
                              </td>
                              <td className="px-3 py-2 text-muted-foreground">
                                {fmtNum(x.start_lba)}
                              </td>
                              <td className="px-3 py-2 text-muted-foreground/60">{x.note || ""}</td>
                              <td className="px-3 py-2 text-right">
                                <button
                                  className={btn + " !px-2 !py-1"}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    pickRegion(i);
                                  }}
                                >
                                  {x.recovered ? "Open" : "Carve"}
                                </button>
                              </td>
                            </tr>
                          ))}
                          {parts &&
                            !parts.partitions.length &&
                            !parts.deleted_partitions.length && (
                              <tr>
                                <td
                                  colSpan={8}
                                  className="px-3 py-6 text-center text-muted-foreground/60"
                                >
                                  {partBusy ? "Scanning…" : "No partitions found."}
                                </td>
                              </tr>
                            )}
                        </tbody>
                      </table>
                    </div>

                    <div className="mt-4 flex flex-wrap items-center gap-2.5">
                      <button className={btn} onClick={() => setScreen("source")}>
                        <ArrowLeft className="h-3 w-3" /> Back
                      </button>
                      <label className="flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
                        <input
                          type="checkbox"
                          className="accent-[var(--primary)]"
                          checked={deepPartScan}
                          onChange={(e) => setDeepPartScan(e.target.checked)}
                        />
                        Search for deleted partitions
                      </label>
                      <button
                        className={btn}
                        disabled={partBusy}
                        onClick={() => source && loadPartitions(source.path, deepPartScan)}
                      >
                        <RefreshCw className="h-3 w-3" /> Rescan
                      </button>
                      <div className="grow" />
                      <button className={btn} onClick={useWholeDisk}>
                        Work on the whole disk
                      </button>
                    </div>
                  </div>
                )}

                {screen === "workspace" && source && (
                  <div>
                    {/* toolbar */}
                    <div className="flex flex-wrap items-center gap-2.5 border-b border-border/60 bg-surface/20 px-4 py-3">
                      <button
                        className={btnPrimary}
                        disabled={busy}
                        onClick={() => startJob("scan")}
                        title="Read filesystem metadata to list live and deleted files"
                      >
                        <ScanSearch className="h-3 w-3" /> Scan filesystem
                      </button>
                      <button
                        className={btn}
                        disabled={busy}
                        onClick={() => openModal("carve")}
                        title="Search raw sectors for known file signatures"
                      >
                        <Database className="h-3 w-3" /> Carve signatures…
                      </button>
                      <button
                        className={btnPrimary}
                        disabled={busy}
                        onClick={() => startJob("deep")}
                        title="Scan and carve, merged and deduplicated"
                      >
                        <Play className="h-3 w-3" /> Deep recovery
                      </button>
                      <span className="mx-1 h-5 w-px bg-border/60" />
                      <button
                        className={btn}
                        disabled={!(results && results.files.length)}
                        onClick={() => openModal("extract")}
                      >
                        <Download className="h-3 w-3" /> Recover files…
                      </button>
                      <span className="mx-1 h-5 w-px bg-border/60" />
                      <button className={btn} onClick={backToVolumes}>
                        <ArrowLeft className="h-3 w-3" /> Volumes
                      </button>
                      <div className="grow" />
                      <span
                        className="max-w-[280px] truncate font-mono text-[10px] text-muted-foreground"
                        title={source.path}
                      >
                        {source.title || source.path}
                        {source.offset ? " @ " + fmtSize(source.offset) : ""}
                        {source.fs ? " · " + source.fs : ""} ·{" "}
                        {fmtSize(source.length || source.size)}
                      </span>
                    </div>

                    {/* job progress */}
                    {busy && (
                      <div className="flex flex-wrap items-center gap-3 border-b border-border/60 bg-surface/20 px-4 py-2.5">
                        <span className={pillOk}>{job.kind}</span>
                        <span className="font-mono text-[10px] text-muted-foreground">
                          {job.phase || ""}
                        </span>
                        <div className="h-1.5 min-w-24 grow overflow-hidden rounded-full bg-surface-2">
                          <div
                            className="h-full bg-primary transition-all"
                            style={{ width: `${Number(job.percent) || 0}%` }}
                          />
                        </div>
                        <span className="font-mono text-[10px] text-muted-foreground">
                          {Math.round(Number(job.percent) || 0)}%
                        </span>
                        {job.found ? (
                          <span className="font-mono text-[10px] text-muted-foreground">
                            {fmtNum(job.found)} found
                          </span>
                        ) : null}
                        <button className={btnWarn + " !px-2 !py-1"} onClick={cancelJob}>
                          Cancel
                        </button>
                      </div>
                    )}

                    <div className="grid gap-4 p-4 lg:grid-cols-[220px_1fr_260px] sm:p-6">
                      {/* sidebar summary */}
                      <div className="rounded-xl border border-border/60 bg-surface/30 p-3">
                        <div className="font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                          Volume
                        </div>
                        <SidebarKV k="Source" v={source.path.split("/").pop() || source.path} />
                        {source.offset ? <SidebarKV k="Offset" v={fmtSize(source.offset)} /> : null}
                        <SidebarKV k="Size" v={fmtSize(source.length || source.size)} />
                        {source.fs ? <SidebarKV k="Filesystem" v={source.fs} /> : null}
                        {source.label ? <SidebarKV k="Label" v={source.label} /> : null}

                        {summary && summary.scan && (
                          <>
                            <div className="mt-3 border-t border-border/60 pt-2 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                              Filesystem scan
                            </div>
                            {!summary.scan.ok && summary.scan.error && (
                              <div className="mt-2 rounded border border-amber-400/40 bg-amber-400/10 px-2 py-1.5 font-mono text-[10px] text-amber-200">
                                {summary.scan.error}
                              </div>
                            )}
                            <SidebarKV k="Files found" v={fmtNum(summary.scan.file_count)} />
                            <SidebarKV k="Deleted" v={fmtNum(summary.scan.deleted_found)} />
                            {summary.scan.block_size ? (
                              <SidebarKV k="Block size" v={fmtNum(summary.scan.block_size)} />
                            ) : null}
                            {summary.scan.total_blocks ? (
                              <SidebarKV k="Blocks" v={fmtNum(summary.scan.total_blocks)} />
                            ) : null}
                            {summary.scan.free_blocks > 0 ? (
                              <SidebarKV k="Free blocks" v={fmtNum(summary.scan.free_blocks)} />
                            ) : null}
                          </>
                        )}
                        {summary && summary.carve && (
                          <>
                            <div className="mt-3 border-t border-border/60 pt-2 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                              Carving
                            </div>
                            {summary.carve.error && (
                              <div className="mt-2 rounded border border-amber-400/40 bg-amber-400/10 px-2 py-1.5 font-mono text-[10px] text-amber-200">
                                {summary.carve.error}
                              </div>
                            )}
                            <SidebarKV k="Scanned" v={fmtSize(summary.carve.bytes_scanned)} />
                            <SidebarKV k="Signatures" v={fmtNum(summary.carve.signatures_loaded)} />
                            <SidebarKV k="Recovered" v={fmtNum(summary.carve.files_recovered)} />
                            {summary.carve.elapsed_ms ? (
                              <SidebarKV k="Elapsed" v={fmtDuration(summary.carve.elapsed_ms)} />
                            ) : null}
                          </>
                        )}
                      </div>

                      {/* results table */}
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <div className="relative grow">
                            <Search className="absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground/50" />
                            <input
                              className={inputCls + " !pl-8"}
                              placeholder="Filter by name or path…"
                              value={filter.q}
                              onChange={(e) => setFilter((f) => ({ ...f, q: e.target.value }))}
                              onKeyDown={(e) => e.key === "Enter" && applyFilter({})}
                            />
                          </div>
                          <select
                            className={inputCls + " !w-auto"}
                            value={filter.ext}
                            onChange={(e) => applyFilter({ ext: e.target.value })}
                          >
                            <option value="">All types</option>
                            {Object.entries(results?.by_ext || {})
                              .sort((a, b) => b[1] - a[1])
                              .map(([e, n]) => (
                                <option key={e} value={e}>
                                  {e} ({n})
                                </option>
                              ))}
                          </select>
                          <select
                            className={inputCls + " !w-auto"}
                            value={filter.only}
                            onChange={(e) => applyFilter({ only: e.target.value })}
                          >
                            <option value="">Everything</option>
                            <option value="deleted">Deleted only</option>
                            <option value="live">Existing only</option>
                          </select>
                          <button className={btn + " !px-2 !py-1"} onClick={selectAllShown}>
                            <CheckSquare className="h-3 w-3" /> Select page
                          </button>
                          <button
                            className={btn + " !px-2 !py-1"}
                            onClick={() => setSelected(new Set())}
                          >
                            Clear
                          </button>
                          <span className="font-mono text-[10px] text-muted-foreground">
                            {selected.size ? selected.size + " selected" : ""}
                          </span>
                        </div>

                        <div className="no-scrollbar mt-3 overflow-x-auto rounded-lg border border-border/60">
                          {!results ? (
                            <div className="p-8 text-center">
                              <Layers className="mx-auto h-7 w-7 text-muted-foreground/40" />
                              <p className="mt-3 font-mono text-xs text-foreground/80">
                                No results yet.
                              </p>
                              <p className="mx-auto mt-1 max-w-md text-[11px] leading-5 text-muted-foreground">
                                Scan filesystem reads the volume's metadata and lists files,
                                including deleted ones. Carve signatures finds files by content — it
                                still works when the filesystem is destroyed. Deep recovery does
                                both and merges the results.
                              </p>
                            </div>
                          ) : !results.files.length ? (
                            <div className="p-8 text-center font-mono text-xs text-muted-foreground">
                              Nothing matches the current filter.
                            </div>
                          ) : (
                            <table className="w-full font-mono text-[11px]">
                              <thead>
                                <tr className="border-b border-border bg-surface-2/60 text-left text-[10px] tracking-wider text-muted-foreground uppercase">
                                  <th className="w-8 px-2 py-2"></th>
                                  {(
                                    [
                                      ["name", "Name", ""],
                                      ["", "Path", ""],
                                      ["size", "Size", "text-right"],
                                      ["", "Recoverable", "text-right"],
                                      ["", "Flags", ""],
                                      ["confidence", "Conf", ""],
                                      ["", "Recovered by", ""],
                                      ["mtime", "Modified", ""],
                                    ] as const
                                  ).map(([key, label, cls]) =>
                                    key ? (
                                      <th key={key} className={`px-3 py-2 ${cls}`}>
                                        <button
                                          className="uppercase hover:text-primary"
                                          onClick={() => setSort(key)}
                                        >
                                          {label}
                                          {filter.sort === key ? " ▾" : ""}
                                        </button>
                                      </th>
                                    ) : (
                                      <th key={label} className={`px-3 py-2 ${cls}`}>
                                        {label}
                                      </th>
                                    ),
                                  )}
                                </tr>
                              </thead>
                              <tbody>
                                {results.files.map((f) => {
                                  const flags = [
                                    f.deleted ? (
                                      <span key="d" className={pillBad}>
                                        deleted
                                      </span>
                                    ) : null,
                                    f.recoverable < f.size ? (
                                      <span key="i" className={pillWarn}>
                                        incomplete
                                      </span>
                                    ) : null,
                                    f.encrypted ? (
                                      <span key="e" className={pillWarn}>
                                        encrypted
                                      </span>
                                    ) : null,
                                    f.compressed ? (
                                      <span key="c" className={pillWarn}>
                                        compressed
                                      </span>
                                    ) : null,
                                    f.ads ? (
                                      <span key="a" className={pillOk}>
                                        ADS
                                      </span>
                                    ) : null,
                                  ].filter(Boolean);
                                  return (
                                    <tr
                                      key={f.index}
                                      onClick={() => selectFile(f)}
                                      className={`cursor-pointer border-b border-border/40 last:border-0 hover:bg-surface-2/40 ${
                                        selIndex === f.index ? "bg-primary/10" : ""
                                      }`}
                                    >
                                      <td className="px-2 py-1.5">
                                        <button
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            toggleSel(f.index);
                                          }}
                                          className="text-muted-foreground hover:text-primary"
                                        >
                                          {selected.has(f.index) ? (
                                            <CheckSquare className="h-3.5 w-3.5" />
                                          ) : (
                                            <Square className="h-3.5 w-3.5" />
                                          )}
                                        </button>
                                      </td>
                                      <td
                                        className="max-w-40 truncate px-3 py-1.5 text-foreground"
                                        title={f.path || f.name}
                                      >
                                        {f.name}
                                      </td>
                                      <td
                                        className="max-w-40 truncate px-3 py-1.5 text-muted-foreground/70"
                                        title={f.path}
                                      >
                                        {f.path}
                                      </td>
                                      <td className="px-3 py-1.5 text-right text-muted-foreground">
                                        {fmtSize(f.size)}
                                      </td>
                                      <td
                                        className={`px-3 py-1.5 text-right ${f.recoverable < f.size ? "text-muted-foreground/50" : "text-muted-foreground"}`}
                                      >
                                        {fmtSize(f.recoverable)}
                                      </td>
                                      <td className="px-3 py-1.5">
                                        <span className="flex flex-wrap gap-1">{flags}</span>
                                      </td>
                                      <td className="px-3 py-1.5">
                                        <span
                                          className={
                                            f.confidence >= 0.9
                                              ? pillOk
                                              : f.confidence >= 0.5
                                                ? pillWarn
                                                : pillBad
                                          }
                                        >
                                          {Math.round(f.confidence * 100)}%
                                        </span>
                                      </td>
                                      <td className="px-3 py-1.5 text-muted-foreground/70">
                                        {f.method.replace(/_/g, " ")}
                                      </td>
                                      <td className="px-3 py-1.5 text-muted-foreground/70">
                                        {f.mtime_iso.replace("T", " ").replace("Z", "")}
                                      </td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          )}
                        </div>

                        {/* pager */}
                        {results && (
                          <div className="mt-3 flex flex-wrap items-center gap-3 font-mono text-[10px] text-muted-foreground">
                            <button
                              className={btn + " !px-2 !py-1"}
                              disabled={results.offset <= 0}
                              onClick={() => {
                                const np = Math.max(0, page - 1);
                                setPage(np);
                                if (resultJob) loadResults(np, filter, resultJob);
                              }}
                            >
                              <ChevronLeft className="h-3 w-3" />
                            </button>
                            <span>
                              {fmtNum(results.matched ? results.offset + 1 : 0)}–
                              {fmtNum(Math.min(results.offset + results.limit, results.matched))} of{" "}
                              {fmtNum(results.matched)}
                              {results.matched !== results.total
                                ? ` (filtered from ${fmtNum(results.total)})`
                                : ""}
                            </span>
                            <button
                              className={btn + " !px-2 !py-1"}
                              disabled={results.offset + results.limit >= results.matched}
                              onClick={() => {
                                const np = page + 1;
                                setPage(np);
                                if (resultJob) loadResults(np, filter, resultJob);
                              }}
                            >
                              <ChevronRight className="h-3 w-3" />
                            </button>
                            <span className="text-muted-foreground/60">
                              page {Math.floor(results.offset / results.limit) + 1}/
                              {Math.max(1, Math.ceil(results.matched / results.limit))}
                            </span>
                            <div className="grow" />
                            <button
                              className={btnPrimary}
                              disabled={!selected.size}
                              onClick={() => openModal("extract")}
                            >
                              <Download className="h-3 w-3" />
                              Recover {selected.size ? selected.size + " selected" : "files"}
                            </button>
                          </div>
                        )}
                      </div>

                      {/* inspector */}
                      <Inspector
                        file={results?.files.find((f) => f.index === selIndex) || null}
                        info={fileInfo}
                        job={resultJob}
                      />
                    </div>
                  </div>
                )}
              </>
            )}

            {/* log drawer */}
            {logOpen && (
              <div className="max-h-48 overflow-y-auto border-t border-border bg-background/60 p-3 font-mono text-[10px] leading-5">
                {logs.length === 0 && (
                  <div className="text-muted-foreground/60">no log entries yet</div>
                )}
                {logs.map((l, i) => (
                  <div
                    key={i}
                    className={
                      l.level === "err"
                        ? "text-rose-300"
                        : l.level === "warn"
                          ? "text-amber-300"
                          : "text-muted-foreground"
                    }
                  >
                    <span className="text-muted-foreground/50">[{l.t}]</span> {l.msg}
                  </div>
                ))}
              </div>
            )}
          </div>
        </Reveal>
      </div>

      {/* modals */}
      {modal && !offline && (
        <div
          className="fixed inset-0 z-[70] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
          onClick={(e) => {
            if (e.target === e.currentTarget) setModal(null);
          }}
        >
          <div className="w-full max-w-lg overflow-hidden rounded-2xl border border-border bg-card shadow-spectral">
            <div className="flex items-center justify-between border-b border-border bg-surface-2/60 px-4 py-3">
              <span className="font-mono text-xs tracking-widest uppercase">
                {modal === "elevate"
                  ? "Unlock disk access"
                  : modal === "attach"
                    ? "Open a disk image"
                    : modal === "carve"
                      ? "Carve signatures"
                      : "Recover files to disk"}
              </span>
              <button className={btn + " !px-1.5 !py-1"} onClick={() => setModal(null)}>
                <X className="h-3 w-3" />
              </button>
            </div>

            <div className="max-h-[65vh] overflow-y-auto p-4">
              {modal === "elevate" && (
                <ElevateBody
                  elevating={elevating}
                  health={health}
                  privileges={privileges}
                  onElevate={elevate}
                  onBack={() => setElevating(null)}
                />
              )}

              {modal === "attach" && (
                <div>
                  <div className="field">
                    <label className="mb-1 block font-mono text-[10px] tracking-wider text-muted-foreground uppercase">
                      Path to an image file or device
                    </label>
                    <input
                      className={inputCls}
                      placeholder="/path/to/disk.img or /dev/sdb"
                      value={modalData.path || ""}
                      onChange={(e) => setModalData((d) => ({ ...d, path: e.target.value }))}
                    />
                    <p className="mt-1.5 text-[10px] leading-4 text-muted-foreground">
                      Raw images (.img, .dd, .raw), ISO files and block devices all work. The file
                      is opened read-only.
                    </p>
                  </div>
                  <div className="mt-3 rounded-lg border border-border/60 bg-surface/30">
                    <div className="border-b border-border/60 px-3 py-2 font-mono text-[10px] text-primary">
                      {browsePath || "/"}
                    </div>
                    <div className="max-h-48 overflow-y-auto">
                      {browseEntries.length === 0 && (
                        <div className="px-3 py-3 font-mono text-[10px] text-muted-foreground/60">
                          empty
                        </div>
                      )}
                      {browseEntries.map((e) => (
                        <button
                          key={e.name}
                          onClick={() => pickBrowse(e)}
                          className="flex w-full items-center gap-2 px-3 py-1.5 text-left font-mono text-[11px] hover:bg-surface-2/60"
                        >
                          <span className="text-muted-foreground">
                            {e.is_dir ? (
                              <FolderOpen className="h-3.5 w-3.5" />
                            ) : (
                              <FileText className="h-3.5 w-3.5" />
                            )}
                          </span>
                          <span
                            className={`grow truncate ${e.is_dir ? "text-cyan-300" : "text-foreground"}`}
                          >
                            {e.name}
                          </span>
                          {!e.is_dir && (
                            <span className="shrink-0 text-muted-foreground/60">
                              {fmtSize(e.size)}
                            </span>
                          )}
                        </button>
                      ))}
                      {browsePath && browsePath !== "/" && (
                        <button
                          onClick={() => browseTo(joinPath(browsePath, ".."))}
                          className="w-full border-t border-border/40 px-3 py-1.5 text-left font-mono text-[11px] text-muted-foreground hover:bg-surface-2/60"
                        >
                          ../ parent
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {modal === "carve" && (
                <div>
                  <div className="mb-3 rounded border border-primary/30 bg-primary/5 px-3 py-2 font-mono text-[10px] leading-4 text-muted-foreground">
                    Carving reads every sector and identifies files by their contents, so it works
                    even when the filesystem is gone. It cannot recover filenames — only data.
                  </div>
                  <label className="mb-1 block font-mono text-[10px] tracking-wider text-muted-foreground uppercase">
                    Limit to these categories (none selected = all)
                  </label>
                  <div className="flex flex-wrap gap-1.5">
                    {carverCats.length === 0 && (
                      <span className="font-mono text-[10px] text-muted-foreground/60">
                        loading…
                      </span>
                    )}
                    {carverCats.map((c) => {
                      const cats: string[] = modalData.cats || [];
                      const on = cats.includes(c);
                      return (
                        <button
                          key={c}
                          onClick={() =>
                            setModalData((d) => {
                              const arr: string[] = [...(d.cats || [])];
                              const i = arr.indexOf(c);
                              if (i >= 0) arr.splice(i, 1);
                              else arr.push(c);
                              return { ...d, cats: arr };
                            })
                          }
                          className={`rounded border px-2 py-1 font-mono text-[10px] transition-colors ${
                            on
                              ? "border-primary/60 bg-primary/10 text-primary"
                              : "border-border/60 text-muted-foreground hover:border-primary/40"
                          }`}
                        >
                          {on ? <Check className="mr-1 inline h-3 w-3" /> : null}
                          {c}
                        </button>
                      );
                    })}
                  </div>
                  <CheckRow
                    label="Only search free space (faster; finds deleted files, skips existing ones)"
                    checked={!!modalData.unalloc}
                    onChange={(v) => setModalData((d) => ({ ...d, unalloc: v }))}
                  />
                  <CheckRow
                    label="Also recover loose runs of text"
                    checked={!!modalData.text}
                    onChange={(v) => setModalData((d) => ({ ...d, text: v }))}
                  />
                  <CheckRow
                    label="Validate file structure (recommended — removes most false positives)"
                    checked={!modalData.novalidate}
                    onChange={(v) => setModalData((d) => ({ ...d, novalidate: !v }))}
                  />
                  <div className="mt-3">
                    <label className="mb-1 block font-mono text-[10px] tracking-wider text-muted-foreground uppercase">
                      Maximum files
                    </label>
                    <input
                      className={inputCls}
                      type="number"
                      value={modalData.max ?? 20000}
                      onChange={(e) =>
                        setModalData((d) => ({ ...d, max: parseInt(e.target.value) || 20000 }))
                      }
                    />
                  </div>
                </div>
              )}

              {modal === "extract" && (
                <div>
                  <div className="field">
                    <label className="mb-1 block font-mono text-[10px] tracking-wider text-muted-foreground uppercase">
                      Destination folder
                    </label>
                    <input
                      className={inputCls}
                      value={
                        modalData.dest ??
                        (health
                          ? health.output_root + "/recovered"
                          : "~/ghost-recover-output/recovered")
                      }
                      onChange={(e) => setModalData((d) => ({ ...d, dest: e.target.value }))}
                    />
                    <p className="mt-1.5 text-[10px] leading-4 text-muted-foreground">
                      Never write recovered files back onto the disk you are recovering from — doing
                      so overwrites the very data you are trying to get back.
                    </p>
                  </div>
                  <CheckRow
                    label="Rebuild the original folder structure"
                    checked={!modalData.flat}
                    onChange={(v) => setModalData((d) => ({ ...d, flat: !v }))}
                  />
                  <CheckRow
                    label="Restore modification times"
                    checked={!modalData.notimes}
                    onChange={(v) => setModalData((d) => ({ ...d, notimes: !v }))}
                  />
                  <CheckRow
                    label="Write a manifest with MD5/SHA-1 hashes"
                    checked={!modalData.nohash}
                    onChange={(v) => setModalData((d) => ({ ...d, nohash: !v }))}
                  />
                  <div className="mt-3 rounded border border-primary/30 bg-primary/5 px-3 py-2 font-mono text-[10px] text-muted-foreground">
                    {selected.size ? (
                      <b className="text-foreground">{selected.size}</b>
                    ) : (
                      <>
                        All <b className="text-foreground">{fmtNum(results?.matched || 0)}</b>
                      </>
                    )}{" "}
                    file(s) will be recovered to disk.
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-2.5 border-t border-border bg-surface-2/40 px-4 py-3">
              {modal === "elevate" ? (
                <>
                  {elevating && elevating.phase === "failed" ? (
                    <>
                      <button className={btn} onClick={() => setElevating(null)}>
                        Back
                      </button>
                      <button className={btn} onClick={() => setModal(null)}>
                        Close
                      </button>
                    </>
                  ) : elevating ? (
                    <button
                      className={btn}
                      onClick={() => {
                        elevCancelRef.current = true;
                        setElevating(null);
                      }}
                    >
                      Cancel
                    </button>
                  ) : (
                    <>
                      <button className={btn} onClick={() => setModal(null)}>
                        Not now
                      </button>
                      {privileges && privileges.sudo && !privileges.sudo_nopasswd && (
                        <button className={btnWarn} onClick={() => elevate("sudo-password")}>
                          Unlock
                        </button>
                      )}
                    </>
                  )}
                </>
              ) : (
                <>
                  <button className={btn} onClick={() => setModal(null)}>
                    Cancel
                  </button>
                  {modal === "attach" && (
                    <button
                      className={btnPrimary}
                      disabled={!modalData.path}
                      onClick={attachConfirm}
                    >
                      Open
                    </button>
                  )}
                  {modal === "carve" && (
                    <button className={btnPrimary} onClick={runCarve}>
                      Start carving
                    </button>
                  )}
                  {modal === "extract" && (
                    <button className={btnPrimary} onClick={runExtract}>
                      Recover
                    </button>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

/* ------------------------------------------------------------ sub pieces */

function SidebarKV({ k, v }: { k: string; v: string }) {
  return (
    <div className="mt-1.5 flex items-baseline justify-between gap-3">
      <span className="shrink-0 font-mono text-[10px] text-muted-foreground/70">{k}</span>
      <span className="truncate font-mono text-[10px] text-foreground/90">{v}</span>
    </div>
  );
}

function CheckRow({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="mt-2.5 flex items-start gap-2 font-mono text-[11px] text-foreground/85">
      <input
        type="checkbox"
        className="mt-0.5 accent-[var(--primary)]"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>{label}</span>
    </label>
  );
}

function ElevateBody({
  elevating,
  health,
  privileges,
  onElevate,
  onBack,
}: {
  elevating: Record<string, any> | null;
  health: Health | null;
  privileges: Privileges | null;
  onElevate: (m: string) => void;
  onBack: () => void;
}) {
  if (health && health.is_root) {
    return (
      <div className="rounded border border-emerald-400/30 bg-emerald-400/10 px-3 py-2.5 font-mono text-[11px] text-emerald-300">
        The engine already has full disk access — every physical disk can be read.
      </div>
    );
  }

  if (elevating) {
    const failed = elevating.phase === "failed";
    return (
      <div className="py-6 text-center">
        <div
          className={`mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-full border font-mono text-lg ${failed ? "border-rose-400/50 text-rose-300" : "border-amber-400/50 text-amber-300"}`}
        >
          {failed ? "✕" : <Loader2 className="h-5 w-5 animate-spin" />}
        </div>
        <div className="font-mono text-sm text-foreground">{elevating.title || ""}</div>
        <div className="mx-auto mt-1.5 max-w-sm text-[11px] leading-5 text-muted-foreground">
          {elevating.message || ""}
        </div>
      </div>
    );
  }

  if (!privileges) {
    return <div className="font-mono text-xs text-muted-foreground">Checking…</div>;
  }

  const blocked = privileges.inaccessible_disks || 0;
  const why = (
    <div className="mb-3 rounded border border-amber-400/40 bg-amber-400/10 px-3 py-2.5 font-mono text-[11px] leading-5 text-amber-200">
      Reading a physical disk sector by sector requires administrator access, and this engine is
      running as an ordinary user.
      {blocked ? (
        <>
          {" "}
          <b>{blocked}</b> attached disk{blocked === 1 ? " is" : "s are"} locked because of it.
        </>
      ) : null}
      <br />
      <br />
      Everything stays read-only: elevation only grants the ability to <i>read</i> raw devices.
      Repairs still need <span className="font-mono text-amber-100">--allow-writes</span> as well.
    </div>
  );

  if (!privileges.preferred) {
    return (
      <div>
        {why}
        <div className="rounded border border-rose-400/40 bg-rose-400/10 px-3 py-2.5 font-mono text-[11px] text-rose-300">
          {privileges.note ||
            "This system offers no way for the program to raise its own privileges."}
        </div>
        <div className="mt-3">
          <label className="mb-1 block font-mono text-[10px] tracking-wider text-muted-foreground uppercase">
            Run this in a terminal instead
          </label>
          <input
            className={inputCls + " cursor-text select-all"}
            readOnly
            value="sudo ghost_recover"
            onFocus={(e) => e.currentTarget.select()}
          />
        </div>
      </div>
    );
  }

  return (
    <div>
      {why}
      {privileges.pkexec && (
        <div className="mb-3">
          <button
            className={btn + " w-full !justify-center !py-2.5 !text-xs"}
            onClick={() => onElevate("pkexec")}
          >
            <ShieldCheck className="h-3.5 w-3.5" /> Authenticate with the system dialog
          </button>
          <p className="mt-1 text-[10px] leading-4 text-muted-foreground">
            Recommended. Your desktop's own polkit prompt appears; the password never passes through
            this program.
          </p>
        </div>
      )}
      {privileges.sudo_nopasswd && (
        <div className="mb-3">
          <button
            className={btn + " w-full !justify-center !py-2.5 !text-xs"}
            onClick={() => onElevate("sudo-nopasswd")}
          >
            Restart with administrator access
          </button>
          <p className="mt-1 text-[10px] leading-4 text-muted-foreground">
            sudo is already authorised for this session, so no password is needed.
          </p>
        </div>
      )}
      {privileges.sudo && !privileges.sudo_nopasswd && (
        <div>
          <label className="mb-1 block font-mono text-[10px] tracking-wider text-muted-foreground uppercase">
            {privileges.pkexec ? "Or enter your sudo password" : "Enter your sudo password"}
          </label>
          <input
            id="ghost-sudopw"
            className={inputCls}
            type="password"
            autoComplete="off"
            placeholder="your account password"
            onKeyDown={(e) => e.key === "Enter" && onElevate("sudo-password")}
          />
          <p className="mt-1 text-[10px] leading-4 text-muted-foreground">
            Used once, piped straight to <span className="font-mono">sudo</span>, and never stored
            or written to the log. Sent only to this engine on localhost.
          </p>
        </div>
      )}
      {privileges.note && (
        <div className="mt-3 rounded border border-primary/30 bg-primary/5 px-3 py-2 font-mono text-[10px] text-muted-foreground">
          {privileges.note}
        </div>
      )}
    </div>
  );
}

function Inspector({
  file,
  info,
  job,
}: {
  file: ResultFile | null;
  info: Record<string, any> | null;
  job: string | null;
}) {
  const [previewMode, setPreviewMode] = useState<"auto" | "raw" | "text">("auto");

  if (!file) {
    return (
      <div className="rounded-xl border border-dashed border-border/60 p-5 text-center font-mono text-[10px] text-muted-foreground/60">
        Select a file to inspect it.
      </div>
    );
  }

  const ext = file.ext.toLowerCase();
  const kind =
    previewMode === "text"
      ? "text"
      : previewMode === "raw"
        ? "raw"
        : IMG.includes(ext)
          ? "img"
          : VID.includes(ext)
            ? "vid"
            : AUD.includes(ext)
              ? "aud"
              : TXT.includes(ext) || file.kind === "text"
                ? "text"
                : "raw";

  const d = info && info.detail;
  const url = job
    ? contentUrl(job, file.index, kind === "img" ? 2048 : kind === "vid" ? 0 : 0)
    : "";

  return (
    <div className="rounded-xl border border-border/60 bg-surface/30 p-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate font-mono text-xs font-semibold text-foreground">
            {file.name}
          </div>
          <div
            className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground"
            title={file.path}
          >
            {file.path}
          </div>
        </div>
        <a href={url} download={file.name} className={btnPrimary + " shrink-0 !px-2 !py-1"}>
          <Download className="h-3 w-3" /> Save
        </a>
      </div>

      <div className="mt-3 flex gap-1.5">
        {(["auto", "text", "raw"] as const).map((m) => (
          <button
            key={m}
            onClick={() => setPreviewMode(m)}
            className={`rounded border px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider transition-colors ${
              previewMode === m
                ? "border-primary/60 bg-primary/10 text-primary"
                : "border-border/60 text-muted-foreground hover:border-primary/40"
            }`}
          >
            {m}
          </button>
        ))}
      </div>

      <div className="mt-3 h-40 overflow-hidden rounded-lg border border-border/60 bg-background/60">
        {kind === "img" ? (
          <img src={url} alt={file.name} className="h-full w-full object-contain" />
        ) : kind === "vid" ? (
          <video src={url} controls className="h-full w-full object-contain" />
        ) : kind === "aud" ? (
          <audio src={url} controls className="mt-16 w-full px-3" />
        ) : kind === "text" ? (
          <iframe src={url} title={file.name} className="h-full w-full" sandbox="" />
        ) : (
          <div className="flex h-full items-center justify-center p-4 text-center font-mono text-[10px] text-muted-foreground/60">
            binary — no inline preview. Download to open it locally.
          </div>
        )}
      </div>

      <div className="mt-3 space-y-1.5">
        <SidebarKV k="Size" v={fmtSize(file.size)} />
        <SidebarKV k="Recoverable" v={fmtSize(file.recoverable)} />
        <SidebarKV k="Confidence" v={Math.round(file.confidence * 100) + "%"} />
        <SidebarKV k="Recovered by" v={file.method.replace(/_/g, " ")} />
        <SidebarKV k="Modified" v={file.mtime_iso.replace("T", " ").replace("Z", "")} />
        {d && (
          <>
            <SidebarKV k="Allocated" v={fmtSize(d.alloc_size)} />
            {d.codec ? <SidebarKV k="Encoding" v={d.codec} /> : null}
            <SidebarKV k="Extents" v={fmtNum(d.extent_count)} />
          </>
        )}
      </div>
    </div>
  );
}
