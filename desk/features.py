"""Feature helpers: a plain-English glossary and the vector space precedents live in.

The glossary covers the features that show up most in explanations. Anything not listed
falls back to its column name, which is still the exact UDPFlowLyzer / QUICFlowLyzer name.
"""
from __future__ import annotations

import numpy as np

GLOSSARY: dict[str, str] = {
    "duration": "flow duration (s)",
    "pkt_count": "packets in the flow",
    "byte_count": "bytes in the flow",
    "pps": "packets per second",
    "bps": "bits per second",
    "avg_pkt_size": "mean packet size (bytes)",
    "min_pkt": "smallest packet (bytes)",
    "max_pkt": "largest packet (bytes)",
    "size_var": "packet size variance",
    "mean_iat": "mean gap between packets (s)",
    "median_iat": "median gap between packets (s)",
    "iat_std": "spread of packet gaps",
    "std_iat": "spread of packet gaps",
    "iat_entropy": "randomness of packet gaps",
    "jitter": "jitter",
    "burst_cnt": "number of bursts",
    "burst_count": "number of bursts",
    "idle_ratio": "share of time idle",
    "pkt_count_fwd": "packets sent forward",
    "pkt_count_bwd": "packets sent back",
    "byte_count_fwd": "bytes sent forward",
    "byte_count_bwd": "bytes sent back",
    "payload_bytes_fwd": "payload bytes forward",
    "payload_bytes_bwd": "payload bytes back",
    "fwd_bwd_pkt_ratio": "forward to backward packet ratio",
    "fwd_bwd_byte_ratio": "forward to backward byte ratio",
    "directional_asymmetry": "one-way-ness of the flow (1 = all one way)",
    "pkt_size_entropy": "variety of packet sizes",
    "fwd_packet_size_entropy": "variety of forward packet sizes",
    "rev_packet_size_entropy": "variety of reply packet sizes",
    "delta_pay_size_min": "smallest change in payload size",
    "delta_pkt_size_mean": "mean change in packet size",
    "header_overhead_ratio": "header share of bytes",
    "payload_efficiency": "payload share of bytes",
    "peak_pkt_rate_1s": "peak packets in one second",
    "windowed_95pct_rate": "95th percentile packet rate",
    "periodic_flow_flag": "regular, periodic timing",
    "flow_regularity_index": "timing regularity",
    "silence_ratio": "share of silent windows",
    "max_idle_gap": "longest idle gap (s)",
    "has_quic_subflow": "carries QUIC",
    "quic_match_count": "QUIC sub-flows matched",
    "quic_paths_max": "QUIC paths seen",
    "quic_migrations_sum": "QUIC connection migrations",
    "pkt_size_iqr": "packet size spread (IQR)",
    "pkt_size_75th_percentile": "75th percentile packet size",
    "pkt_size_90th_percentile": "90th percentile packet size",
    "median_pkt_size": "median packet size",
    "payload_size_median": "median payload size",
    "dest_multicast_flag": "multicast destination",
    "frag_ratio": "share of fragmented packets",
}

# Columns shown on every case card and precedent row: cheap, readable, always present.
KEY_FEATURES = [
    "pkt_count", "duration", "pps", "avg_pkt_size", "min_pkt", "max_pkt",
    "mean_iat", "directional_asymmetry", "fwd_bwd_byte_ratio", "has_quic_subflow",
]


def describe(name: str) -> str:
    return GLOSSARY.get(name, name)


def fit_scaler(X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Median and IQR of the signed-log features, fitted on training rows only."""
    Z = signed_log(X)
    med = np.median(Z, axis=0)
    q75, q25 = np.percentile(Z, [75, 25], axis=0)
    iqr = q75 - q25
    std = Z.std(axis=0)
    scale = np.where(iqr > 1e-9, iqr, np.where(std > 1e-9, std, 1.0))
    return med, scale


def signed_log(X: np.ndarray) -> np.ndarray:
    return np.sign(X) * np.log1p(np.abs(X))


def to_space(X: np.ndarray, med: np.ndarray, scale: np.ndarray) -> np.ndarray:
    """Signed log, robust scaling, clipped at +-10 so one wild column cannot own the distance."""
    return np.clip((signed_log(X) - med) / scale, -10.0, 10.0).astype(np.float32)
