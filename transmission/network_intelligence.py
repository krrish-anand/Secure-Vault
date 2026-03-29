"""
Network Intelligence Module

Monitors network conditions (latency, packet loss) and classifies network quality.
Used by adaptive encryption engine to decide encryption strength & block size.
"""

import socket
import time
import statistics
from enum import Enum
from typing import Tuple, Optional
from dataclasses import dataclass


class NetworkQuality(Enum):
    """Network quality classification based on latency and packet loss."""
    POOR = "poor"           # latency > 100ms or packet loss > 5%
    MODERATE = "moderate"   # latency 50-100ms or packet loss 2-5%
    GOOD = "good"           # latency < 50ms and packet loss < 2%


@dataclass
class NetworkMetrics:
    """Container for network quality metrics."""
    avg_latency_ms: float
    packet_loss_percent: float
    quality: NetworkQuality
    timestamp: float
    sample_count: int


class NetworkMonitor:
    """
    Monitors network conditions by measuring:
    1. Latency (RTT via ICMP ping or TCP handshake)
    2. Packet loss (simple count of failed pings/connections)
    """

    def __init__(self, target_host: str = "8.8.8.8", target_port: int = 53):
        """
        Initialize network monitor.
        
        Args:
            target_host: Host to ping for latency measurement (default: Google DNS)
            target_port: Port for TCP latency measurement (default: 53 for DNS)
        """
        self.target_host = target_host
        self.target_port = target_port
        self.latency_samples = []
        self.packet_loss_count = 0
        self.total_attempts = 0

    def measure_latency(self, sample_count: int = 5, timeout: float = 2.0) -> float:
        """
        Measure average latency (RTT) via TCP connection attempts.
        
        Args:
            sample_count: Number of measurements to take
            timeout: Socket timeout in seconds
            
        Returns:
            Average latency in milliseconds
        """
        latencies = []
        
        for _ in range(sample_count):
            try:
                start_time = time.time()
                
                # Create socket and measure RTT
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                try:
                    sock.connect((self.target_host, self.target_port))
                    elapsed = (time.time() - start_time) * 1000  # Convert to ms
                    latencies.append(elapsed)
                except (socket.timeout, socket.error):
                    # Connection failed, count as packet loss
                    self.packet_loss_count += 1
                finally:
                    sock.close()
                    
            except Exception:
                self.packet_loss_count += 1
            
            self.total_attempts += 1
        
        # Return average of successful measurements
        if latencies:
            avg_latency = statistics.mean(latencies)
            self.latency_samples.extend(latencies)
            return avg_latency
        else:
            return 9999.0  # High latency if all failed

    def measure_packet_loss(self, sample_count: int = 5, timeout: float = 2.0) -> float:
        """
        Measure packet loss percentage via attempted connections.
        
        Args:
            sample_count: Number of attempts
            timeout: Socket timeout in seconds
            
        Returns:
            Packet loss percentage (0-100)
        """
        failed_count = 0
        
        for _ in range(sample_count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                try:
                    sock.connect((self.target_host, self.target_port))
                except (socket.timeout, socket.error):
                    failed_count += 1
                finally:
                    sock.close()
                    
            except Exception:
                failed_count += 1
            
            self.total_attempts += 1
        
        loss_percent = (failed_count / sample_count) * 100 if sample_count > 0 else 0
        self.packet_loss_count += failed_count
        return loss_percent

    def get_network_quality(self, 
                           latency_threshold_poor: float = 100.0,
                           latency_threshold_moderate: float = 50.0,
                           loss_threshold_poor: float = 5.0,
                           loss_threshold_moderate: float = 2.0) -> NetworkQuality:
        """
        Classify network quality based on thresholds.
        
        Args:
            latency_threshold_poor: Latency > this = POOR (default: 100ms)
            latency_threshold_moderate: Latency > this = MODERATE (default: 50ms)
            loss_threshold_poor: Loss > this = POOR (default: 5%)
            loss_threshold_moderate: Loss > this = MODERATE (default: 2%)
            
        Returns:
            NetworkQuality enum value
        """
        # Get current metrics
        metrics = self.calculate_metrics()
        
        # Classification logic
        if metrics.avg_latency_ms > latency_threshold_poor or \
           metrics.packet_loss_percent > loss_threshold_poor:
            return NetworkQuality.POOR
        
        if metrics.avg_latency_ms > latency_threshold_moderate or \
           metrics.packet_loss_percent > loss_threshold_moderate:
            return NetworkQuality.MODERATE
        
        return NetworkQuality.GOOD

    def calculate_metrics(self) -> NetworkMetrics:
        """
        Calculate current network metrics.
        
        Returns:
            NetworkMetrics object with latency, packet loss, and quality
        """
        if self.latency_samples:
            avg_latency = statistics.mean(self.latency_samples)
        else:
            avg_latency = 0.0
        
        if self.total_attempts > 0:
            packet_loss = (self.packet_loss_count / self.total_attempts) * 100
        else:
            packet_loss = 0.0
        
        # Determine quality
        if avg_latency > 100 or packet_loss > 5:
            quality = NetworkQuality.POOR
        elif avg_latency > 50 or packet_loss > 2:
            quality = NetworkQuality.MODERATE
        else:
            quality = NetworkQuality.GOOD
        
        return NetworkMetrics(
            avg_latency_ms=avg_latency,
            packet_loss_percent=packet_loss,
            quality=quality,
            timestamp=time.time(),
            sample_count=len(self.latency_samples)
        )

    def reset_metrics(self):
        """Clear all collected samples and counters."""
        self.latency_samples = []
        self.packet_loss_count = 0
        self.total_attempts = 0

    def get_summary(self) -> str:
        """Get human-readable network summary."""
        metrics = self.calculate_metrics()
        return (
            f"Network Quality: {metrics.quality.value.upper()} | "
            f"Avg Latency: {metrics.avg_latency_ms:.2f}ms | "
            f"Packet Loss: {metrics.packet_loss_percent:.2f}% | "
            f"Samples: {metrics.sample_count}"
        )
