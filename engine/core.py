# -*- coding: utf-8 -*-
"""
=============================================================================
 Engine Core - نواة المحرك
-----------------------------------------------------------------------------
 - JobManager   : إدارة مهام الفحص الخلفية (Background Jobs) مع تقدم حي
 - HistoryManager : إدارة سجل الفحوصات (JSON persistence)
=============================================================================
"""

import os
import json
import uuid
import threading
import time
from datetime import datetime


# ===========================================================================
# History Manager / إدارة سجل الفحوصات
# ===========================================================================

class HistoryManager:
    """يحفظ سجل الفحوصات في ملف JSON مع نسخة في الذاكرة."""

    def __init__(self, history_file):
        self.history_file = history_file
        self._lock = threading.Lock()
        self._entries = []
        self.load()

    def load(self):
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, "r", encoding="utf-8") as f:
                    self._entries = json.load(f)
            else:
                self._entries = []
        except Exception:
            self._entries = []
        return self._entries

    def save(self):
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(self._entries, f, ensure_ascii=False, indent=2)
            return True
        except Exception:
            return False

    def add(self, scan_type, target, summary, details=None):
        with self._lock:
            entry = {
                "id": (self._entries[-1]["id"] + 1) if self._entries else 1,
                "type": scan_type,
                "target": target,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "summary": summary,
                "details": details or {},
            }
            self._entries.append(entry)
            self.save()
            return entry

    def list(self, limit=100):
        with self._lock:
            return list(reversed(self._entries[-limit:]))

    def get(self, entry_id):
        with self._lock:
            return next((e for e in self._entries if e["id"] == entry_id), None)

    def clear(self):
        with self._lock:
            self._entries = []
            self.save()


# ===========================================================================
# Job Manager / إدارة المهام الخلفية
# ===========================================================================

class Job:
    """حاوية نتيجة مهمة واحدة."""

    __slots__ = ("id", "type", "target", "status", "progress", "result",
                 "error", "created_at", "finished_at", "_cancel", "entry_id")

    def __init__(self, job_id, job_type, target):
        self.id = job_id
        self.type = job_type
        self.target = target
        self.status = "queued"      # queued | running | done | error | cancelled
        self.progress = 0           # 0-100
        self.result = None
        self.error = None
        self.created_at = time.time()
        self.finished_at = None
        self._cancel = threading.Event()
        self.entry_id = None

    def to_dict(self, with_result=False):
        d = {
            "id": self.id,
            "type": self.type,
            "target": self.target,
            "status": self.status,
            "progress": self.progress,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
        }
        if self.error:
            d["error"] = self.error
        if self.entry_id is not None:
            d["entry_id"] = self.entry_id
        if with_result and self.result is not None:
            d["result"] = self.result
        return d


class JobManager:
    """يشغّل مهام الفحص في خيوط خلفية ويتتبع حالتها وتقدمها."""

    def __init__(self, max_workers=4, history=None, max_jobs=200):
        self._jobs = {}                 # job_id -> Job
        self._order = []                # job_id insertion order
        self._lock = threading.Lock()
        self._sem = threading.Semaphore(max_workers)
        self.history = history          # HistoryManager اختياري
        self.max_jobs = max_jobs

    # ------------------------------------------------------------------ #
    def submit(self, job_type, target, func, params=None):
        """تسجيل مهمة جديدة؛ func(job, params) يجب أن تستدعي job callbacks."""
        job_id = uuid.uuid4().hex[:12]
        job = Job(job_id, job_type, target)

        with self._lock:
            self._jobs[job_id] = job
            self._order.append(job_id)
            # تنظيف المهام القديمة المنتهية
            if len(self._order) > self.max_jobs:
                for old_id in list(self._order):
                    old = self._jobs[old_id]
                    if old.status in ("done", "error", "cancelled"):
                        del self._jobs[old_id]
                        self._order.remove(old_id)
                    if len(self._order) <= self.max_jobs:
                        break

        t = threading.Thread(target=self._run, args=(job, func, params or {}),
                             daemon=True)
        t.start()
        return job.to_dict()

    def _run(self, job, func, params):
        self._sem.acquire()
        try:
            if job._cancel.is_set():
                job.status = "cancelled"
                return
            job.status = "running"
            # حقن أدوات التقدم والإلغاء تلقائياً في params
            params = dict(params or {})
            params.setdefault("_progress", Progress(job))
            params.setdefault("_stop_event", job._cancel)
            result = func(job, params)
            job.result = result
        except Exception as e:
            job.status = "error"
            job.error = str(e)
        finally:
            job.finished_at = time.time()
            self._sem.release()
            # تسجيل في السجل
            if self.history is not None and job.status == "running":
                try:
                    summary = _summarize(job)
                    entry = self.history.add(job.type, job.target, summary, job.result)
                    job.entry_id = entry.get("id")
                except Exception:
                    pass
                job.status = "done"

    # ------------------------------------------------------------------ #
    def get(self, job_id, with_result=True):
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            return job.to_dict(with_result=with_result)

    def list(self):
        with self._lock:
            return [self._jobs[jid].to_dict() for jid in reversed(self._order)]

    def cancel(self, job_id):
        with self._lock:
            job = self._jobs.get(job_id)
        if job and job.status in ("queued", "running"):
            job._cancel.set()
            return True
        return False

    def active_count(self):
        with self._lock:
            return sum(1 for j in self._jobs.values()
                       if j.status in ("queued", "running"))


# ===========================================================================
# Progress Callbacks / آلية تتبع التقدم
# ===========================================================================

class Progress:
    """كائن يمرَّر لوحدات الفحص لتحديث حالة المهمة."""

    def __init__(self, job):
        self._job = job
        self._last = 0.0
        self._lock = threading.Lock()

    def update(self, pct, note=""):
        with self._lock:
            self._job.progress = max(0, min(100, int(pct)))
            self._last = time.time()

    def is_cancelled(self):
        return self._job._cancel.is_set()


def _summarize(job):
    """ملخص قصير لنتيجة المهمة لعرضه في السجل."""
    r = job.result or {}
    t = job.type
    if t == "code":
        return f"lines={r.get('lines')}, findings={r.get('total_findings')}"
    if t == "network":
        return f"open_ports={r.get('open_ports')}, elapsed={r.get('elapsed')}s"
    if t == "osint":
        return f"ip={r.get('ip')}, http={r.get('http_status')}"
    if t == "hash":
        return f"type={r.get('hash_type')}, found={'YES' if r.get('match') else 'NO'}"
    return "completed"
