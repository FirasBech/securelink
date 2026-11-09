"""Windows Job Object tracking for GPU workloads.

The process starts suspended, joins an unnamed Job Object, then resumes. This
closes the race where a child starts before containment. Standard CreateProcess
descendants inherit the job; see Microsoft's Job Objects documentation for
exceptions such as processes created by Win32_Process.Create.
"""
from __future__ import annotations

import os
import subprocess
import time
from typing import Any

from core.worker import WorkloadStillRunning


class WindowsProcessGuard:
    def __init__(self, argv: list[str], kwargs: dict[str, Any]) -> None:
        if os.name != "nt":
            raise ValueError("GPU subprocess tracking is currently supported only on Windows")
        import ctypes
        from ctypes import wintypes

        self.ctypes = ctypes
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure(wintypes)
        self.job = self.kernel.CreateJobObjectW(None, None)
        if not self.job:
            raise ctypes.WinError(ctypes.get_last_error())
        self.process: subprocess.Popen | None = None
        self.verified_empty = False
        assigned = False
        try:
            limits = self.ExtendedLimits()
            limits.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not self.kernel.SetInformationJobObject(self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                raise ctypes.WinError(ctypes.get_last_error())
            options = dict(kwargs)
            options["creationflags"] = options.get("creationflags", 0) | 0x00000004  # CREATE_SUSPENDED
            self.process = subprocess.Popen(argv, **options)
            if not self.kernel.AssignProcessToJobObject(self.job, int(self.process._handle)):
                raise ctypes.WinError(ctypes.get_last_error())
            assigned = True
            self._resume_primary_thread()
        except BaseException:
            try:
                if assigned:
                    # After assignment, assume the process could have resumed
                    # and created children, even if initialization then failed.
                    self.terminate()
                elif self.process is not None:
                    self.process.kill()
                    self.process.wait(timeout=10)
            except BaseException as exc:
                try:
                    self.close()
                except BaseException:
                    pass
                raise WorkloadStillRunning("Could not confirm a suspended workload stopped") from exc
            self.close()
            raise

    def _configure(self, wintypes) -> None:
        import ctypes

        class ThreadEntry(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                        ("th32ThreadID", wintypes.DWORD), ("th32OwnerProcessID", wintypes.DWORD),
                        ("tpBasePri", wintypes.LONG), ("tpDeltaPri", wintypes.LONG),
                        ("dwFlags", wintypes.DWORD)]

        class Accounting(ctypes.Structure):
            _fields_ = [("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong),
                        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                        ("TotalPageFaultCount", wintypes.DWORD), ("TotalProcesses", wintypes.DWORD),
                        ("ActiveProcesses", wintypes.DWORD), ("TotalTerminatedProcesses", wintypes.DWORD)]

        class BasicLimits(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BasicLimits), ("IoInfo", IoCounters),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        self.ThreadEntry, self.Accounting, self.ExtendedLimits = ThreadEntry, Accounting, ExtendedLimits
        k = self.kernel
        k.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        k.CreateJobObjectW.restype = wintypes.HANDLE
        k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k.AssignProcessToJobObject.restype = wintypes.BOOL
        k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        k.SetInformationJobObject.restype = wintypes.BOOL
        k.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                wintypes.DWORD, ctypes.c_void_p]
        k.QueryInformationJobObject.restype = wintypes.BOOL
        k.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k.TerminateJobObject.restype = wintypes.BOOL
        k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
        k.Thread32First.restype = wintypes.BOOL
        k.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
        k.Thread32Next.restype = wintypes.BOOL
        k.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k.OpenThread.restype = wintypes.HANDLE
        k.GetProcessIdOfThread.argtypes = [wintypes.HANDLE]
        k.GetProcessIdOfThread.restype = wintypes.DWORD
        k.ResumeThread.argtypes = [wintypes.HANDLE]
        k.ResumeThread.restype = wintypes.DWORD
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CloseHandle.restype = wintypes.BOOL

    def _resume_primary_thread(self) -> None:
        ctypes = self.ctypes
        snapshot = self.kernel.CreateToolhelp32Snapshot(0x00000004, 0)  # TH32CS_SNAPTHREAD
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry = self.ThreadEntry()
            entry.dwSize = ctypes.sizeof(entry)
            found = self.kernel.Thread32First(snapshot, ctypes.byref(entry))
            thread_ids = []
            while found:
                if entry.th32OwnerProcessID == self.process.pid:
                    thread_ids.append(entry.th32ThreadID)
                found = self.kernel.Thread32Next(snapshot, ctypes.byref(entry))
            if len(thread_ids) != 1:
                raise OSError("Expected exactly one suspended process thread")
            thread = self.kernel.OpenThread(0x0042, False, thread_ids[0])  # SUSPEND_RESUME | QUERY_INFORMATION
            if not thread:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                if self.kernel.GetProcessIdOfThread(thread) != self.process.pid:
                    raise OSError("Suspended process thread changed ownership")
                if self.kernel.ResumeThread(thread) != 1:
                    raise OSError("Suspended process thread had an unexpected suspend count")
            finally:
                self.kernel.CloseHandle(thread)
        finally:
            self.kernel.CloseHandle(snapshot)

    def active(self) -> bool:
        info = self.Accounting()
        if not self.kernel.QueryInformationJobObject(self.job, 1, self.ctypes.byref(info),
                                                     self.ctypes.sizeof(info), None):
            raise WorkloadStillRunning("Could not verify the GPU process tree")
        active = bool(info.ActiveProcesses)
        if not active:
            self.verified_empty = True
        return active

    def terminate(self) -> None:
        if not self.kernel.TerminateJobObject(self.job, 1):
            raise WorkloadStillRunning("Could not terminate the GPU process tree")
        deadline = time.monotonic() + 15
        while self.active():
            if time.monotonic() >= deadline:
                raise WorkloadStillRunning("GPU process tree did not stop")
            time.sleep(0.1)
        self.process.wait(timeout=5)

    def close(self) -> None:
        if self.job:
            self.kernel.CloseHandle(self.job)
            self.job = None

    def __del__(self) -> None:
        # If Python loses the guard during an exceptional handoff, closing the
        # final job handle asks Windows to terminate tracked processes. The
        # queue still retains the reservation until emptiness is verified.
        try:
            if getattr(self, "job", None):
                self.close()
        except BaseException:
            pass
