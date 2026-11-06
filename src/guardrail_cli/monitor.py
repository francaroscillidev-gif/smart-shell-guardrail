import os
import psutil
import time
from typing import Optional, Dict, Any
from pydantic import BaseModel

from .models import ResourceUsage

class ProcessMonitor:
    def __init__(self, pid: int):
        self.pid = pid
        try:
            self.process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            self.process = None
        self.max_rss = 0
        self.start_time = time.time()

    def sample(self):
        if not self.process:
            return
        try:
            if self.process.is_running():
                mem = self.process.memory_info().rss
                # Includi figli
                for child in self.process.children(recursive=True):
                    try:
                        mem += child.memory_info().rss
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                if mem > self.max_rss:
                    self.max_rss = mem
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def get_summary(self) -> ResourceUsage:
        duration_ms = round((time.time() - self.start_time) * 1000, 2)
        mem_mb = round(self.max_rss / (1024 * 1024), 2)
        return ResourceUsage(
            duration_ms=duration_ms,
            cpu_percent=0.0,
            max_memory_mb=mem_mb
        )
