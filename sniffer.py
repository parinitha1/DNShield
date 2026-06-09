"""
sniffer.py — DNS Shield
Real-time DNS packet capture, ML inference, and logging pipeline.

Architecture
------------
  Scapy sniff()  →  _process_packet()  →  blocker check (fast path)
                                        →  feature extraction
                                        →  IsolationForest.predict()
                                        →  if anomaly: blocker.add() + MongoDB log

The sniffer runs inside a daemon thread managed by `start_sniffer_thread()`.
The main FastAPI process imports and calls that function once on startup.
"""

import os
import threading
import datetime
import logging
from typing import Optional

import joblib
import numpy as np

from features import extract_features
from blocker  import blocker   # module-level singleton

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger("dns_shield.sniffer")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)

# ──────────────────────────────────────────────────────────────────────────────
# Global state (shared with main.py via direct import)
# ──────────────────────────────────────────────────────────────────────────────

# The ML model is loaded once into memory at startup.
_model = None
_model_lock = threading.Lock()

# MongoDB collection reference — injected by main.py after DB connect.
_log_collection = None

# Performance counters (thread-safe via GIL for simple int increments)
stats = {
    "total":         0,   # all DNS packets seen
    "blocked_fast":  0,   # packets dropped at blocker fast-path
    "clean":         0,   # classified as benign
    "new_blocked":   0,   # newly detected anomalies this session
}

MODEL_PATH = "dns_model.pkl"

# ──────────────────────────────────────────────────────────────────────────────
# Model management
# ──────────────────────────────────────────────────────────────────────────────

def load_model(path: str = MODEL_PATH) -> None:
    """
    Load the serialised IsolationForest from disk into the global `_model`.
    Called once at startup from main.py.

    Parameters
    ----------
    path : str
        Path to the joblib-serialised model file.

    Raises
    ------
    FileNotFoundError : If the model file does not exist.
    """
    global _model
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Model file not found: '{path}'. "
            "Run  python train.py  first to generate it."
        )
    with _model_lock:
        _model = joblib.load(path)
    logger.info("ML model loaded from '%s'", path)


def set_log_collection(collection) -> None:
    """
    Inject the MongoDB collection reference.
    Must be called from main.py after establishing the DB connection.
    """
    global _log_collection
    _log_collection = collection
    logger.info("MongoDB log collection registered.")


# ──────────────────────────────────────────────────────────────────────────────
# Core packet processor
# ──────────────────────────────────────────────────────────────────────────────

def _process_packet(packet) -> None:
    """
    Callback invoked by Scapy for every captured UDP/53 packet.

    Pipeline
    --------
    1. Extract QNAME from DNS Question Record.
    2. FAST PATH: If domain already blocked → drop silently, increment counter.
    3. Extract (length, entropy) features.
    4. Run IsolationForest prediction.
    5. If anomaly (-1): block domain, persist log entry to MongoDB.
    6. If benign (+1): persist log entry to MongoDB.
    """
    global stats

    # ── Import Scapy lazily to avoid import-time errors in test environments ──
    try:
        from scapy.layers.dns import DNSQR
    except ImportError:
        logger.error("Scapy not installed. pip install scapy")
        return

    # ── Guard: must contain a DNS Question Record ─────────────────────────────
    if not packet.haslayer(DNSQR):
        return

    # ── Extract QNAME ─────────────────────────────────────────────────────────
    try:
        raw_qname = packet[DNSQR].qname
        # Scapy returns bytes; decode and strip trailing dot
        if isinstance(raw_qname, bytes):
            domain = raw_qname.decode("utf-8", errors="replace").rstrip(".")
        else:
            domain = str(raw_qname).rstrip(".")
    except Exception as exc:
        logger.debug("Failed to extract QNAME: %s", exc)
        return

    if not domain:
        return

    stats["total"] += 1

    # ── FAST PATH: already on block list ──────────────────────────────────────
    if blocker.is_blocked(domain):
        stats["blocked_fast"] += 1
        logger.debug("FAST-DROP  %s", domain)
        return

    # ── Feature extraction ────────────────────────────────────────────────────
    try:
        features = extract_features(domain)
    except (TypeError, ValueError) as exc:
        logger.warning("Feature extraction failed for '%s': %s", domain, exc)
        return

    length  = features["length"]
    entropy = features["entropy"]

    # ── ML inference ─────────────────────────────────────────────────────────
    with _model_lock:
        if _model is None:
            logger.warning("Model not loaded — skipping inference for '%s'", domain)
            return
        X = np.array([[length, entropy]])
        raw_pred = _model.predict(X)[0]   # +1 inlier, -1 outlier

    is_anomaly = (raw_pred == -1)
    status     = "blocked" if is_anomaly else "clean"
    timestamp  = datetime.datetime.utcnow()

    # ── Block if anomaly ──────────────────────────────────────────────────────
    if is_anomaly:
        newly_added = blocker.add(domain)
        if newly_added:
            stats["new_blocked"] += 1
        logger.warning(
            "ANOMALY DETECTED  domain=%-60s  len=%d  entropy=%.4f",
            domain, length, entropy
        )
    else:
        stats["clean"] += 1
        logger.info(
            "CLEAN             domain=%-60s  len=%d  entropy=%.4f",
            domain, length, entropy
        )

    # ── Persist log entry to MongoDB ──────────────────────────────────────────
    _persist_log(
        domain=domain,
        length=length,
        entropy=entropy,
        status=status,
        timestamp=timestamp,
    )


def _persist_log(
    domain: str,
    length: int,
    entropy: float,
    status: str,
    timestamp: datetime.datetime,
) -> None:
    """
    Write a query log document to MongoDB.
    Fails silently so a DB outage never crashes the sniffer thread.
    """
    if _log_collection is None:
        return   # DB not yet initialised — silently skip

    try:
        _log_collection.insert_one({
            "domain":    domain,
            "length":    length,
            "entropy":   round(entropy, 6),
            "status":    status,            # "clean" | "blocked"
            "timestamp": timestamp,
        })
    except Exception as exc:
        logger.error("MongoDB insert failed: %s", exc)


# ──────────────────────────────────────────────────────────────────────────────
# Sniffer thread
# ──────────────────────────────────────────────────────────────────────────────

_sniffer_thread: Optional[threading.Thread] = None
_sniffer_running = threading.Event()


def start_sniffer_thread(iface: Optional[str] = None) -> threading.Thread:
    """
    Launch the Scapy packet capture loop as a background daemon thread.

    The thread is non-blocking; it sets `_sniffer_running` once active.
    Passing iface=None lets Scapy choose the default interface.

    Parameters
    ----------
    iface : str, optional
        Network interface name (e.g. "eth0", "en0").  Defaults to None
        (Scapy auto-selects).

    Returns
    -------
    threading.Thread
        The started daemon thread.
    """
    global _sniffer_thread

    if _sniffer_thread and _sniffer_thread.is_alive():
        logger.warning("Sniffer thread already running — ignoring duplicate start.")
        return _sniffer_thread

    def _run():
        # Import Scapy here so that the rest of the application can be imported
        # on machines without Scapy installed (e.g. CI pipelines).
        try:
            from scapy.all import sniff as scapy_sniff
        except ImportError:
            logger.error(
                "Scapy is not installed.  "
                "Install it with:  pip install scapy"
            )
            return

        logger.info(
            "Sniffer thread started — capturing UDP/53 packets%s",
            f" on interface '{iface}'" if iface else " on all interfaces",
        )
        _sniffer_running.set()

        # BPF filter: only UDP port 53 (DNS queries)
        scapy_sniff(
            filter="udp port 53",
            prn=_process_packet,
            store=False,        # do NOT accumulate packets in memory
            iface=iface,
        )

    _sniffer_thread = threading.Thread(
        target=_run,
        name="dns-sniffer",
        daemon=True,   # dies with the main process
    )
    _sniffer_thread.start()
    return _sniffer_thread


def is_sniffer_running() -> bool:
    """Return True if the sniffer daemon thread is alive."""
    return _sniffer_thread is not None and _sniffer_thread.is_alive()


# ──────────────────────────────────────────────────────────────────────────────
# Entry point (standalone test — requires root/sudo for raw socket capture)
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import time

    print("[*] DNS Shield Sniffer — standalone mode")
    print("    This requires root/admin privileges for raw packet capture.")

    try:
        load_model()
    except FileNotFoundError as e:
        print(f"[WARN] {e}")
        print("       Sniffer will run but skip ML inference until model is present.")

    t = start_sniffer_thread()
    print("[*] Sniffer running. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(5)
            print(
                f"[stats] total={stats['total']}  "
                f"clean={stats['clean']}  "
                f"new_blocked={stats['new_blocked']}  "
                f"fast_dropped={stats['blocked_fast']}  "
                f"blocked_list_size={blocker.size()}"
            )
    except KeyboardInterrupt:
        print("\n[*] Stopping.")
