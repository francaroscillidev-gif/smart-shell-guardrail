import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field

from .models import DiffResult

class SnapshotFile(BaseModel):
    path: str
    mtime: float
    size: int

class WorkspaceSnapshot(BaseModel):
    timestamp: float
    root_dir: str
    tracked_files: List[str] = Field(default_factory=list)
    backup_tar: Optional[str] = None

class RollbackManager:
    def __init__(self, target_dir: Optional[str] = None):
        self.target_dir = Path(target_dir or os.getcwd()).resolve()
        self.snapshots_dir = Path.home() / ".guardrail" / "snapshots"
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

    def create_snapshot(self) -> WorkspaceSnapshot:
        ts = time.time()
        # Salva file modificati/creati escludendo directory pesanti come .git, .venv, node_modules
        tracked = []
        ignore_dirs = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache"}

        archive_base = self.snapshots_dir / f"snapshot_{int(ts)}"
        
        # Crea backup comprimendo solo i file sorgente rilevanti
        temp_backup_dir = Path(tempfile.mkdtemp(prefix="gr_snap_"))
        try:
            for root, dirs, files in os.walk(self.target_dir):
                dirs[:] = [d for d in dirs if d not in ignore_dirs]
                for file in files:
                    full_p = Path(root) / file
                    rel_p = full_p.relative_to(self.target_dir)
                    tracked.append(str(rel_p))
                    dest = temp_backup_dir / rel_p
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        shutil.copy2(full_p, dest)
                    except Exception:
                        pass

            tar_file = shutil.make_archive(str(archive_base), "gztar", temp_backup_dir)
        finally:
            shutil.rmtree(temp_backup_dir, ignore_errors=True)

        return WorkspaceSnapshot(
            timestamp=ts,
            root_dir=str(self.target_dir),
            tracked_files=tracked,
            backup_tar=tar_file
        )

    def compute_diff(self, snapshot: WorkspaceSnapshot) -> DiffResult:
        ignore_dirs = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache"}
        current_files = set()
        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for file in files:
                rel_p = str((Path(root) / file).relative_to(self.target_dir))
                current_files.add(rel_p)

        orig_files = set(snapshot.tracked_files)

        created = list(current_files - orig_files)
        deleted = list(orig_files - current_files)
        # Modified check: file presenti in entrambi
        modified = []
        for f in current_files.intersection(orig_files):
            # semplificato: confronto dimensione/mtime
            p = self.target_dir / f
            try:
                if p.stat().st_mtime > snapshot.timestamp:
                    modified.append(f)
            except Exception:
                pass

        return DiffResult(
            created_files=created,
            modified_files=modified,
            deleted_files=deleted
        )

    def rollback(self, snapshot: WorkspaceSnapshot) -> bool:
        if not snapshot.backup_tar or not os.path.exists(snapshot.backup_tar):
            return False

        temp_restore = Path(tempfile.mkdtemp(prefix="gr_restore_"))
        try:
            shutil.unpack_archive(snapshot.backup_tar, temp_restore, "gztar")
            # Ripristina file nel workspace
            for root, dirs, files in os.walk(temp_restore):
                for file in files:
                    src = Path(root) / file
                    rel_p = src.relative_to(temp_restore)
                    dest = self.target_dir / rel_p
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dest)
            return True
        finally:
            shutil.rmtree(temp_restore, ignore_errors=True)
