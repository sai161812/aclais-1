"""Fail-closed Windows worker launcher for the A2 demonstration installation."""

from __future__ import annotations

import ctypes
import json
import os
import re
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from aclais.launcher.models import (
    A3ProbeConfiguration,
    CapturedLine,
    DocumentToolsWorkerConfiguration,
    WorkerResult,
    windows_command_line,
)
from aclais.logging_config import redact_fields, redact_text

_LAB_ROOT = Path(r"C:\ACLAIS-Lab")
_CREDENTIAL_TARGET = "ACLAIS-1/AclaisWorker"
_WORKER_NAME = "AclaisWorker"
_PYTHON_EMBED_SHA256 = "4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3"
_CRED_TYPE_GENERIC = 1
_TOKEN_QUERY = 0x0008
_TOKEN_DUPLICATE = 0x0002
_TOKEN_USER = 1
_ADMINISTRATORS_SID = "S-1-5-32-544"
_CREATE_SUSPENDED = 0x00000004
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_CREATE_NO_WINDOW = 0x08000000
_STARTF_USESTDHANDLES = 0x00000100
_HANDLE_FLAG_INHERIT = 0x00000001
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_WAIT_FAILED = 0xFFFFFFFF
_STILL_ACTIVE = 259
_MAX_CAPTURE_BYTES = 256 * 1024
_MAX_LINE_BYTES = 16 * 1024
_MAX_CAPTURE_LINES = 1024
_PIPE_READ_BYTES = 4096
_CLEANUP_TIMEOUT_MS = 10_000
_POLL_INTERVAL_MS = 50


class LauncherError(RuntimeError):
    """An opaque, secret-free launch or cleanup failure."""

    def __init__(
        self, operation: str, winerror: int | None = None, diagnostic: str | None = None
    ) -> None:
        self.operation = operation
        self.winerror = winerror
        suffix = f" winerror={winerror}" if winerror is not None else ""
        if diagnostic:
            suffix += f" phase={diagnostic}"
        super().__init__(f"worker_{operation}_failed{suffix}")


class IdentityMismatch(LauncherError):
    """The suspended child token did not match the provisioned worker."""


class CredentialUnavailable(LauncherError):
    """The owner's A2 Credential Manager entry could not be read or validated."""


@dataclass(frozen=True)
class RuntimeLayout:
    """Paths and identities derived from the protected A2 installation manifest."""

    root: Path
    root_id: str
    owner_sid: str
    worker_sid: str
    machine: str
    selected_input: Path
    selected_root: Path
    output_root: Path
    selected_copy_root: Path
    task_output_root: Path
    verified_output_root: Path
    raw_evidence_root: Path
    code_root: Path
    python_exe: Path
    private_probe: Path
    source_sha256: str
    source_revision: str | None
    fixture_hashes: tuple[tuple[str, str], ...]

    @classmethod
    def open(cls, root: Path = _LAB_ROOT) -> RuntimeLayout:
        if os.name != "nt":
            raise LauncherError("windows_required")
        if root != _LAB_ROOT:
            raise LauncherError("unexpected_lab_root")

        api = _NativeApi()
        current_sid, is_admin = api.current_identity()
        if is_admin:
            raise LauncherError("controller_must_not_be_elevated")

        sentinel_path = root / ".owner-sentinel.json"
        manifest_path = root / "state" / "installation.json"
        trusted_state_path = root / "state" / "trusted-state.json"
        selected_root = root / "store" / "selected"
        output_root = root / "work" / "temporary-output"
        selected_copy_root = root / "work" / "selected-inputs"
        task_output_root = root / "work" / "task-output"
        verified_output_root = root / "work" / "verified-output"
        raw_evidence_root = root / "evidence" / "raw"
        code_root = root / "code"
        python_runtime = code_root / "python-runtime"
        python_exe = python_runtime / "python.exe"
        private_probe = code_root / "private-probes" / "a3_worker_probe.py"
        required_paths = (
            root,
            sentinel_path,
            root / "state",
            manifest_path,
            trusted_state_path,
            root / "store",
            selected_root,
            root / "evidence",
            root / "work",
            output_root,
            code_root,
            code_root / "venv",
            python_runtime,
            python_exe,
            code_root / "private-probes",
            private_probe,
        )
        for path in required_paths:
            _require_plain_path(api, path)

        try:
            sentinel = json.loads(sentinel_path.read_text(encoding="utf-8"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            trusted_state = json.loads(trusted_state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise LauncherError("installation_metadata_unavailable") from None

        if (
            sentinel.get("schema_version") != 1
            or manifest.get("schema_version") != 1
            or manifest.get("checkpoint") != "A2"
            or sentinel.get("root_id") != manifest.get("root_id")
            or sentinel.get("owner_sid") != manifest.get("owner_sid")
            or sentinel.get("machine", "").casefold()
            != os.environ.get("COMPUTERNAME", "").casefold()
            or manifest.get("machine", "").casefold()
            != os.environ.get("COMPUTERNAME", "").casefold()
            or Path(manifest.get("root_path", "")) != root
            or Path(manifest.get("code_root", "")) != code_root
            or Path(manifest.get("runtime_environment", "")) != code_root / "venv"
            or manifest.get("worker_name") != _WORKER_NAME
            or manifest.get("credential_target") != _CREDENTIAL_TARGET
            or manifest.get("credential_type") != "CRED_TYPE_GENERIC"
            or current_sid != manifest.get("owner_sid")
            or not isinstance(manifest.get("worker_sid"), str)
        ):
            raise LauncherError("installation_metadata_invalid")

        manifest_fixtures = manifest.get("fixtures")
        trusted_fixtures = trusted_state.get("fixture_hashes")
        if not isinstance(manifest_fixtures, list) or not isinstance(trusted_fixtures, list):
            raise LauncherError("trusted_state_invalid")
        try:
            manifest_hashes = tuple(
                sorted((item["path"], item["sha256"]) for item in manifest_fixtures)
            )
            trusted_hashes = tuple(
                sorted((item["path"], item["sha256"]) for item in trusted_fixtures)
            )
        except (KeyError, TypeError):
            raise LauncherError("trusted_state_invalid") from None
        if (
            trusted_state.get("schema_version") != 1
            or trusted_state.get("root_id") != manifest.get("root_id")
            or trusted_state.get("owner_sid") != manifest.get("owner_sid")
            or trusted_state.get("worker_sid") != manifest.get("worker_sid")
            or trusted_state.get("source_revision") != manifest.get("source_revision")
            or manifest_hashes != trusted_hashes
            or any(
                not isinstance(path, str)
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                for path, digest in manifest_hashes
            )
            or len({path for path, _digest in manifest_hashes}) != len(manifest_hashes)
        ):
            raise LauncherError("trusted_state_invalid")

        selected_relative = "store/selected/Selected_Input.csv"
        fixture = next(
            (
                item
                for item in manifest.get("fixtures", [])
                if item.get("path") == selected_relative
            ),
            None,
        )
        if not fixture or not re.fullmatch(r"[0-9a-f]{64}", fixture.get("sha256", "")):
            raise LauncherError("selected_input_manifest_invalid")
        selected_input = selected_root / "Selected_Input.csv"
        if _sha256_file(selected_input) != fixture["sha256"]:
            raise LauncherError("selected_input_integrity_failed")

        runtime_record = next(
            (
                item
                for item in manifest.get("protected_code", [])
                if item.get("path") == "code/private-probes/a3_worker_probe.py"
            ),
            None,
        )
        if not runtime_record or not re.fullmatch(
            r"[0-9a-f]{64}", runtime_record.get("sha256", "")
        ):
            raise LauncherError("private_entrypoint_not_installed")
        if _sha256_file(private_probe) != runtime_record["sha256"]:
            raise LauncherError("private_entrypoint_integrity_failed")

        a3_runtime = next(
            (
                item
                for item in manifest.get("checkpoint_runtime_updates", [])
                if item.get("checkpoint") == "A3"
            ),
            None,
        )
        if (
            not a3_runtime
            or Path(a3_runtime.get("python_runtime", "")) != python_runtime
            or a3_runtime.get("python_embed_sha256") != _PYTHON_EMBED_SHA256
            or a3_runtime.get("python_version") != "3.12.10"
        ):
            raise LauncherError("worker_runtime_manifest_invalid")
        interpreter_record = next(
            (
                item
                for item in manifest.get("protected_code", [])
                if item.get("path") == "code/python-runtime/python.exe"
            ),
            None,
        )
        if not interpreter_record or _sha256_file(python_exe) != interpreter_record.get("sha256"):
            raise LauncherError("worker_runtime_integrity_failed")

        return cls(
            root=root,
            root_id=manifest["root_id"],
            owner_sid=current_sid,
            worker_sid=manifest["worker_sid"],
            machine=os.environ["COMPUTERNAME"],
            selected_input=selected_input,
            selected_root=selected_root,
            output_root=output_root,
            selected_copy_root=selected_copy_root,
            task_output_root=task_output_root,
            verified_output_root=verified_output_root,
            raw_evidence_root=raw_evidence_root,
            code_root=code_root,
            python_exe=python_exe,
            private_probe=private_probe,
            source_sha256=runtime_record["sha256"],
            source_revision=(
                a3_runtime.get("source_revision")
                if isinstance(a3_runtime.get("source_revision"), str)
                and re.fullmatch(r"[0-9a-f]{7,40}", a3_runtime["source_revision"])
                else None
            ),
            fixture_hashes=tuple(
                sorted(
                    (item["path"], item["sha256"])
                    for item in manifest_fixtures
                    if isinstance(item, dict)
                    and isinstance(item.get("path"), str)
                    and isinstance(item.get("sha256"), str)
                )
            ),
        )

    def prepare_task_roots(self, api: _NativeApi | None = None) -> None:
        """Create or reassert A6 roots using protected, controller-owned DACLs."""

        native = api or _NativeApi()
        roots = (
            (self.selected_copy_root, "GX"),
            (self.task_output_root, "GX"),
            (self.verified_output_root, None),
            (self.raw_evidence_root, None),
        )
        for path, worker_rights in roots:
            if not path.exists():
                path.mkdir()
            _require_plain_path(native, path)
            if not path.is_dir():
                raise LauncherError("managed_root_not_directory")
            native.set_protected_directory_acl(
                path,
                owner_sid=self.owner_sid,
                worker_sid=self.worker_sid if worker_rights else None,
                worker_rights=worker_rights,
            )

    def protect_task_directory(
        self, path: Path, *, worker_rights: Literal["GRGX", "GRGWGX"]
    ) -> None:
        if path.parent not in {self.selected_copy_root, self.task_output_root}:
            raise LauncherError("task_directory_cleanup_scope")
        native = _NativeApi()
        _require_plain_path(native, path)
        native.set_protected_directory_acl(
            path,
            owner_sid=self.owner_sid,
            worker_sid=self.worker_sid,
            worker_rights=worker_rights,
        )


@dataclass
class _CapturedBytes:
    buffer: bytearray
    total: int = 0
    truncated_bytes: bool = False
    read_error: int | None = None


class _CredentialSecret:
    def __init__(self, user_name: str, password_buffer: Any) -> None:
        self.user_name = user_name
        self.password_buffer = password_buffer

    def clear(self) -> None:
        if self.password_buffer is not None:
            ctypes.memset(
                ctypes.addressof(self.password_buffer), 0, ctypes.sizeof(self.password_buffer)
            )
            self.password_buffer = None


class _NativeApi:
    """Small, explicit ctypes binding set; all errors omit native strings and secrets."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise LauncherError("windows_required")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self._declare_functions()

    def _declare_functions(self) -> None:
        k = self.kernel32
        a = self.advapi32
        handle = ctypes.c_void_p
        dword = ctypes.c_uint32
        bool_t = ctypes.c_int
        lpwstr = ctypes.c_wchar_p
        lpcwstr = ctypes.c_wchar_p

        class SECURITY_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("nLength", dword),
                ("lpSecurityDescriptor", handle),
                ("bInheritHandle", bool_t),
            ]

        class STARTUPINFOW(ctypes.Structure):
            _fields_ = [
                ("cb", dword),
                ("lpReserved", lpwstr),
                ("lpDesktop", lpwstr),
                ("lpTitle", lpwstr),
                ("dwX", dword),
                ("dwY", dword),
                ("dwXSize", dword),
                ("dwYSize", dword),
                ("dwXCountChars", dword),
                ("dwYCountChars", dword),
                ("dwFillAttribute", dword),
                ("dwFlags", dword),
                ("wShowWindow", ctypes.c_uint16),
                ("cbReserved2", ctypes.c_uint16),
                ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", handle),
                ("hStdOutput", handle),
                ("hStdError", handle),
            ]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("hProcess", handle),
                ("hThread", handle),
                ("dwProcessId", dword),
                ("dwThreadId", dword),
            ]

        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", dword), ("dwHighDateTime", dword)]

        class CREDENTIALW(ctypes.Structure):
            _fields_ = [
                ("Flags", dword),
                ("Type", dword),
                ("TargetName", lpwstr),
                ("Comment", lpwstr),
                ("LastWritten", FILETIME),
                ("CredentialBlobSize", dword),
                ("CredentialBlob", handle),
                ("Persist", dword),
                ("AttributeCount", dword),
                ("Attributes", handle),
                ("TargetAlias", lpwstr),
                ("UserName", lpwstr),
            ]

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", dword),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", dword),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", dword),
                ("SchedulingClass", dword),
            ]

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        class SID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Sid", handle), ("Attributes", dword)]

        class TOKEN_USER(ctypes.Structure):
            _fields_ = [("User", SID_AND_ATTRIBUTES)]

        self.SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES
        self.STARTUPINFOW = STARTUPINFOW
        self.PROCESS_INFORMATION = PROCESS_INFORMATION
        self.FILETIME = FILETIME
        self.CREDENTIALW = CREDENTIALW
        self.JOBOBJECT_EXTENDED_LIMIT_INFORMATION = JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        self.TOKEN_USER = TOKEN_USER

        k.CreatePipe.argtypes = [
            ctypes.POINTER(handle),
            ctypes.POINTER(handle),
            ctypes.POINTER(SECURITY_ATTRIBUTES),
            dword,
        ]
        k.CreatePipe.restype = bool_t
        k.GetFileAttributesW.argtypes = [lpcwstr]
        k.GetFileAttributesW.restype = dword
        k.OpenProcess.argtypes = [dword, bool_t, dword]
        k.OpenProcess.restype = handle
        k.SetHandleInformation.argtypes = [handle, dword, dword]
        k.SetHandleInformation.restype = bool_t
        k.CreateFileW.argtypes = [
            lpcwstr,
            dword,
            dword,
            ctypes.POINTER(SECURITY_ATTRIBUTES),
            dword,
            dword,
            handle,
        ]
        k.CreateFileW.restype = handle
        k.CloseHandle.argtypes = [handle]
        k.CloseHandle.restype = bool_t
        k.CreateJobObjectW.argtypes = [handle, lpcwstr]
        k.CreateJobObjectW.restype = handle
        k.SetInformationJobObject.argtypes = [handle, ctypes.c_int, handle, dword]
        k.SetInformationJobObject.restype = bool_t
        k.QueryInformationJobObject.argtypes = [
            handle,
            ctypes.c_int,
            handle,
            dword,
            ctypes.POINTER(dword),
        ]
        k.QueryInformationJobObject.restype = bool_t
        k.AssignProcessToJobObject.argtypes = [handle, handle]
        k.AssignProcessToJobObject.restype = bool_t
        k.IsProcessInJob.argtypes = [handle, handle, ctypes.POINTER(bool_t)]
        k.IsProcessInJob.restype = bool_t
        k.ResumeThread.argtypes = [handle]
        k.ResumeThread.restype = dword
        k.TerminateProcess.argtypes = [handle, ctypes.c_uint32]
        k.TerminateProcess.restype = bool_t
        k.TerminateJobObject.argtypes = [handle, ctypes.c_uint32]
        k.TerminateJobObject.restype = bool_t
        k.WaitForSingleObject.argtypes = [handle, dword]
        k.WaitForSingleObject.restype = dword
        k.GetExitCodeProcess.argtypes = [handle, ctypes.POINTER(dword)]
        k.GetExitCodeProcess.restype = bool_t
        k.GetProcessId.argtypes = [handle]
        k.GetProcessId.restype = dword
        k.GetProcessTimes.argtypes = [
            handle,
            ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME),
        ]
        k.GetProcessTimes.restype = bool_t
        k.ReadFile.argtypes = [handle, handle, dword, ctypes.POINTER(dword), handle]
        k.ReadFile.restype = bool_t
        k.GetCurrentProcess.argtypes = []
        k.GetCurrentProcess.restype = handle
        k.LocalFree.argtypes = [handle]
        k.LocalFree.restype = handle

        a.CredReadW.argtypes = [lpcwstr, dword, dword, ctypes.POINTER(handle)]
        a.CredReadW.restype = bool_t
        a.CreateProcessWithLogonW.argtypes = [
            lpcwstr,
            lpcwstr,
            lpcwstr,
            dword,
            lpcwstr,
            lpwstr,
            dword,
            handle,
            lpcwstr,
            ctypes.POINTER(STARTUPINFOW),
            ctypes.POINTER(PROCESS_INFORMATION),
        ]
        a.CreateProcessWithLogonW.restype = bool_t
        a.CredFree.argtypes = [handle]
        a.CredFree.restype = None
        a.OpenProcessToken.argtypes = [handle, dword, ctypes.POINTER(handle)]
        a.OpenProcessToken.restype = bool_t
        a.DuplicateToken.argtypes = [handle, ctypes.c_int, ctypes.POINTER(handle)]
        a.DuplicateToken.restype = bool_t
        a.GetTokenInformation.argtypes = [
            handle,
            ctypes.c_int,
            handle,
            dword,
            ctypes.POINTER(dword),
        ]
        a.GetTokenInformation.restype = bool_t
        a.ConvertSidToStringSidW.argtypes = [handle, ctypes.POINTER(lpwstr)]
        a.ConvertSidToStringSidW.restype = bool_t
        a.ConvertStringSidToSidW.argtypes = [lpcwstr, ctypes.POINTER(handle)]
        a.ConvertStringSidToSidW.restype = bool_t
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            lpcwstr,
            dword,
            ctypes.POINTER(handle),
            ctypes.POINTER(dword),
        ]
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = bool_t
        a.SetFileSecurityW.argtypes = [lpcwstr, dword, handle]
        a.SetFileSecurityW.restype = bool_t
        a.CheckTokenMembership.argtypes = [handle, handle, ctypes.POINTER(bool_t)]
        a.CheckTokenMembership.restype = bool_t

    def _raise_last_error(
        self, operation: str, error_type: type[LauncherError] = LauncherError
    ) -> None:
        raise error_type(operation, ctypes.get_last_error())

    def create_pipe(self) -> tuple[ctypes.c_void_p, ctypes.c_void_p]:
        security = self.SECURITY_ATTRIBUTES(ctypes.sizeof(self.SECURITY_ATTRIBUTES), None, True)
        read_handle = ctypes.c_void_p()
        write_handle = ctypes.c_void_p()
        if not self.kernel32.CreatePipe(
            ctypes.byref(read_handle), ctypes.byref(write_handle), ctypes.byref(security), 0
        ):
            self._raise_last_error("pipe_create")
        if not self.kernel32.SetHandleInformation(read_handle, _HANDLE_FLAG_INHERIT, 0):
            error = ctypes.get_last_error()
            self.close_handle(read_handle)
            self.close_handle(write_handle)
            raise LauncherError("pipe_parent_handle_protection", error)
        return read_handle, write_handle

    def create_null_input(self) -> ctypes.c_void_p:
        security = self.SECURITY_ATTRIBUTES(ctypes.sizeof(self.SECURITY_ATTRIBUTES), None, True)
        handle = self.kernel32.CreateFileW(
            "NUL", 0x80000000, 0x00000001 | 0x00000002, ctypes.byref(security), 3, 0x80, None
        )
        if not handle or handle == ctypes.c_void_p(-1).value:
            self._raise_last_error("stdin_create")
        return ctypes.c_void_p(handle)

    def hold_source_directory(self, path: Path) -> ctypes.c_void_p:
        """Prevent source-namespace rename without changing ancestor permissions."""
        handle = self.kernel32.CreateFileW(str(path), 1, 3, None, 3, 0x02000000, None)
        if not handle or handle == ctypes.c_void_p(-1).value:
            self._raise_last_error("source_namespace_guard")
        return ctypes.c_void_p(handle)

    def create_job(self) -> ctypes.c_void_p:
        handle = self.kernel32.CreateJobObjectW(None, None)
        if not handle:
            self._raise_last_error("job_create")
        return ctypes.c_void_p(handle)

    def configure_kill_on_close(self, job: ctypes.c_void_p) -> None:
        information = self.JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        information.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel32.SetInformationJobObject(
            job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            self._raise_last_error("job_configure")

    def verify_kill_on_close(self, job: ctypes.c_void_p) -> bool:
        information = self.JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        returned = ctypes.c_uint32()
        if not self.kernel32.QueryInformationJobObject(
            job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(information),
            ctypes.sizeof(information),
            ctypes.byref(returned),
        ):
            self._raise_last_error("job_verify")
        return information.BasicLimitInformation.LimitFlags == _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

    def set_protected_directory_acl(
        self,
        path: Path,
        *,
        owner_sid: str,
        worker_sid: str | None,
        worker_rights: str | None,
    ) -> None:
        if (worker_sid is None) != (worker_rights is None):
            raise ValueError("worker SID and access rights must be supplied together")
        sddl = f"D:P(A;OICI;FA;;;{owner_sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        if worker_sid is not None and worker_rights is not None:
            if worker_rights not in {"GX", "GRGX", "GRGWGX"}:
                raise ValueError("unsupported scoped worker directory right")
            inherit = "OICI" if worker_rights in {"GRGX", "GRGWGX"} else ""
            sddl += f"(A;{inherit};{worker_rights};;;{worker_sid})"
        descriptor = ctypes.c_void_p()
        descriptor_size = ctypes.c_uint32()
        if not self.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), ctypes.byref(descriptor_size)
        ):
            self._raise_last_error("directory_acl_descriptor")
        try:
            security_information = _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION
            if not self.advapi32.SetFileSecurityW(str(path), security_information, descriptor):
                self._raise_last_error("directory_acl_apply")
        finally:
            self.kernel32.LocalFree(descriptor)

    def assign_process_to_job(self, job: ctypes.c_void_p, process: ctypes.c_void_p) -> None:
        if not self.kernel32.AssignProcessToJobObject(job, process):
            self._raise_last_error("job_assign")

    def is_process_in_job(self, process: ctypes.c_void_p, job: ctypes.c_void_p) -> bool:
        in_job = ctypes.c_int()
        if not self.kernel32.IsProcessInJob(process, job, ctypes.byref(in_job)):
            self._raise_last_error("job_membership_check")
        return bool(in_job.value)

    def current_identity(self) -> tuple[str, bool]:
        process = self.kernel32.GetCurrentProcess()
        token = ctypes.c_void_p()
        if not self.advapi32.OpenProcessToken(
            process, _TOKEN_QUERY | _TOKEN_DUPLICATE, ctypes.byref(token)
        ):
            self._raise_last_error("current_token_open")
        try:
            return self._token_identity(token)
        finally:
            self.close_handle(token)

    def open_process(self, pid: int) -> ctypes.c_void_p | None:
        handle = self.kernel32.OpenProcess(
            0x00100000 | 0x00001000, False, pid
        )  # SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
        return ctypes.c_void_p(handle) if handle else None

    def process_identity(self, process: ctypes.c_void_p) -> tuple[str, bool]:
        token = ctypes.c_void_p()
        if not self.advapi32.OpenProcessToken(
            process, _TOKEN_QUERY | _TOKEN_DUPLICATE, ctypes.byref(token)
        ):
            self._raise_last_error("worker_token_open", IdentityMismatch)
        try:
            return self._token_identity(token)
        finally:
            self.close_handle(token)

    def _token_identity(self, token: ctypes.c_void_p) -> tuple[str, bool]:
        required = ctypes.c_uint32()
        self.advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(required))
        if required.value < ctypes.sizeof(self.TOKEN_USER) or required.value > 64 * 1024:
            self._raise_last_error("token_user_size")
        data = ctypes.create_string_buffer(required.value)
        if not self.advapi32.GetTokenInformation(
            token, _TOKEN_USER, data, required.value, ctypes.byref(required)
        ):
            self._raise_last_error("token_user_read")
        token_user = ctypes.cast(data, ctypes.POINTER(self.TOKEN_USER)).contents
        sid_string = ctypes.c_wchar_p()
        if not self.advapi32.ConvertSidToStringSidW(token_user.User.Sid, ctypes.byref(sid_string)):
            self._raise_last_error("token_sid_convert")
        try:
            sid_value = sid_string.value or ""
        finally:
            self.kernel32.LocalFree(ctypes.cast(sid_string, ctypes.c_void_p))

        admin_sid = ctypes.c_void_p()
        if not self.advapi32.ConvertStringSidToSidW(_ADMINISTRATORS_SID, ctypes.byref(admin_sid)):
            self._raise_last_error("administrator_sid_convert")
        impersonation_token = ctypes.c_void_p()
        try:
            if not self.advapi32.DuplicateToken(token, 2, ctypes.byref(impersonation_token)):
                self._raise_last_error("token_impersonation_duplicate")
            is_admin = ctypes.c_int()
            if not self.advapi32.CheckTokenMembership(
                impersonation_token, admin_sid, ctypes.byref(is_admin)
            ):
                self._raise_last_error("administrator_membership_check")
            return sid_value, bool(is_admin.value)
        finally:
            self.close_handle(impersonation_token)
            self.kernel32.LocalFree(admin_sid)

    def read_credential(self) -> _CredentialSecret:
        credential_pointer = ctypes.c_void_p()
        if not self.advapi32.CredReadW(
            _CREDENTIAL_TARGET, _CRED_TYPE_GENERIC, 0, ctypes.byref(credential_pointer)
        ):
            self._raise_last_error("credential_read", CredentialUnavailable)
        try:
            credential = ctypes.cast(credential_pointer, ctypes.POINTER(self.CREDENTIALW)).contents
            expected_user = rf"{os.environ.get('COMPUTERNAME', '')}\{_WORKER_NAME}"
            if (
                credential.Type != _CRED_TYPE_GENERIC
                or credential.TargetName != _CREDENTIAL_TARGET
                or credential.UserName is None
                or credential.UserName.casefold() != expected_user.casefold()
                or not credential.CredentialBlob
                or credential.CredentialBlobSize < 2
                or credential.CredentialBlobSize > 5120
                or credential.CredentialBlobSize % ctypes.sizeof(ctypes.c_wchar) != 0
            ):
                raise CredentialUnavailable("credential_validation")

            character_count = credential.CredentialBlobSize // ctypes.sizeof(ctypes.c_wchar)
            password_buffer = ctypes.create_unicode_buffer(character_count + 1)
            ctypes.memmove(
                ctypes.addressof(password_buffer),
                credential.CredentialBlob,
                credential.CredentialBlobSize,
            )
            if any(password_buffer[index] == "\x00" for index in range(character_count)):
                ctypes.memset(ctypes.addressof(password_buffer), 0, ctypes.sizeof(password_buffer))
                raise CredentialUnavailable("credential_blob_validation")
            return _CredentialSecret(credential.UserName, password_buffer)
        finally:
            self.advapi32.CredFree(credential_pointer)

    def create_process(
        self,
        credential: _CredentialSecret,
        application: Path,
        arguments: tuple[str, ...],
        environment: dict[str, str],
        working_directory: Path,
        stdin_handle: ctypes.c_void_p,
        stdout_handle: ctypes.c_void_p,
        stderr_handle: ctypes.c_void_p,
    ) -> tuple[ctypes.c_void_p, ctypes.c_void_p, int]:
        domain, user_name = credential.user_name.split("\\", 1)
        startup = self.STARTUPINFOW()
        startup.cb = ctypes.sizeof(startup)
        startup.dwFlags = _STARTF_USESTDHANDLES
        startup.hStdInput = stdin_handle
        startup.hStdOutput = stdout_handle
        startup.hStdError = stderr_handle
        process_information = self.PROCESS_INFORMATION()
        environment_text = (
            "\x00".join(
                f"{key}={value}"
                for key, value in sorted(environment.items(), key=lambda pair: pair[0].casefold())
            )
            + "\x00\x00"
        )
        environment_buffer = ctypes.create_unicode_buffer(environment_text)
        command_line = ctypes.create_unicode_buffer(
            windows_command_line(str(application), arguments)
        )
        creation_flags = _CREATE_SUSPENDED | _CREATE_UNICODE_ENVIRONMENT | _CREATE_NO_WINDOW
        try:
            created = self.advapi32.CreateProcessWithLogonW(
                user_name,
                domain,
                ctypes.cast(credential.password_buffer, ctypes.c_wchar_p),
                0,
                str(application),
                command_line,
                creation_flags,
                ctypes.cast(environment_buffer, ctypes.c_void_p),
                str(working_directory),
                ctypes.byref(startup),
                ctypes.byref(process_information),
            )
            if not created:
                self._raise_last_error("alternate_user_process_create")
            return (
                ctypes.c_void_p(process_information.hProcess),
                ctypes.c_void_p(process_information.hThread),
                int(process_information.dwProcessId),
            )
        finally:
            ctypes.memset(ctypes.addressof(command_line), 0, ctypes.sizeof(command_line))
            ctypes.memset(
                ctypes.addressof(environment_buffer), 0, ctypes.sizeof(environment_buffer)
            )

    def process_creation_time(self, process: ctypes.c_void_p) -> int:
        created, exited, kernel, user = (
            self.FILETIME(),
            self.FILETIME(),
            self.FILETIME(),
            self.FILETIME(),
        )
        if not self.kernel32.GetProcessTimes(
            process,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            self._raise_last_error("process_creation_time")
        return (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)

    def process_exit_code(self, process: ctypes.c_void_p) -> int:
        value = ctypes.c_uint32()
        if not self.kernel32.GetExitCodeProcess(process, ctypes.byref(value)):
            self._raise_last_error("process_exit_code")
        if value.value == _STILL_ACTIVE:
            raise LauncherError("process_exit_not_observed")
        return int(value.value)

    def resume_thread(self, thread: ctypes.c_void_p) -> int:
        previous_suspend_count = int(self.kernel32.ResumeThread(thread))
        if previous_suspend_count == _WAIT_FAILED:
            self._raise_last_error("worker_resume")
        return previous_suspend_count

    def terminate_process(self, process: ctypes.c_void_p) -> None:
        if not self.kernel32.TerminateProcess(process, 0xC000013A):
            error = ctypes.get_last_error()
            if self.wait(process, 0) != _WAIT_OBJECT_0:
                raise LauncherError("suspended_worker_terminate", error)

    def terminate_job(self, job: ctypes.c_void_p) -> None:
        if not self.kernel32.TerminateJobObject(job, 0xC000013A):
            error = ctypes.get_last_error()
            if self.wait(job, 0) != _WAIT_OBJECT_0:
                raise LauncherError("job_terminate", error)

    def wait(self, handle: ctypes.c_void_p, milliseconds: int) -> int:
        result = int(self.kernel32.WaitForSingleObject(handle, milliseconds))
        if result == _WAIT_FAILED:
            self._raise_last_error("handle_wait")
        return result

    def read_pipe(self, handle: ctypes.c_void_p) -> bytes:
        buffer = ctypes.create_string_buffer(_PIPE_READ_BYTES)
        read_count = ctypes.c_uint32()
        success = self.kernel32.ReadFile(
            handle, buffer, len(buffer), ctypes.byref(read_count), None
        )
        if not success:
            error = ctypes.get_last_error()
            if error in (109, 232):  # ERROR_BROKEN_PIPE / ERROR_NO_DATA
                return b""
            raise LauncherError("output_pipe_read", error)
        return buffer.raw[: read_count.value]

    def close_handle(self, handle: ctypes.c_void_p | None) -> None:
        if handle and handle.value not in (0, ctypes.c_void_p(-1).value):
            if not self.kernel32.CloseHandle(handle):
                self._raise_last_error("handle_close")


class _Win32Api(_NativeApi):
    """Named subclass so Windows-only tests can fail one native operation safely."""


class _Handle:
    def __init__(self, api: _NativeApi, raw: ctypes.c_void_p | None, name: str) -> None:
        self.api = api
        self.raw = raw
        self.name = name
        self.closed = raw is None

    def close(self) -> None:
        if self.closed:
            return
        raw = self.raw
        self.closed = True
        self.raw = None
        self.api.close_handle(raw)


class WindowsWorkerController:
    """Owns worker Job Objects and guarantees fail-closed alternate-user launches."""

    def __init__(
        self,
        layout: RuntimeLayout | None = None,
        *,
        api: _NativeApi | None = None,
        credential_reader: Any | None = None,
    ) -> None:
        self.layout = layout or RuntimeLayout.open()
        self._api = api or _Win32Api()
        self._credential_reader = credential_reader or self._api.read_credential
        self._active: set[WorkerHandle] = set()
        self._lock = threading.RLock()
        self._shutdown = False
        self._source_guards: list[ctypes.c_void_p] = []
        try:
            for directory in Path(__file__).resolve().parents:
                if directory.parent == directory:
                    break
                self._source_guards.append(self._api.hold_source_directory(directory))
        except Exception:
            for guard in self._source_guards:
                self._api.close_handle(guard)
            self._source_guards.clear()
            raise

    def start_a3_private_probe(
        self,
        *,
        deadline_seconds: int = 30,
        probe_case: Literal[
            "normal", "child_exit", "child_wait", "child_crash", "capture"
        ] = "normal",
        echo_arguments: tuple[str, ...] = (),
        task_id: uuid.UUID | None = None,
        selected_input: Path | None = None,
        temporary_output: Path | None = None,
        selected_document_id: Literal["doc-report", "doc-invoice"] | None = None,
        tool_id: Literal["report_formatter", "invoice_analyzer"] | None = None,
        broker_url: str | None = None,
        worker_credential: str | None = None,
        broker_probe: Literal["none", "allow_and_publish", "policy_denial"] = "none",
        before_resume: Callable[[int, int, str], None] | None = None,
    ) -> WorkerHandle:
        with self._lock:
            if self._shutdown:
                raise LauncherError("controller_shutdown")
            config = A3ProbeConfiguration(
                task_id=task_id or uuid.uuid4(),
                selected_input=str(selected_input or self.layout.selected_input),
                temporary_output=str(temporary_output or self.layout.output_root),
                deadline_seconds=deadline_seconds,
                probe_case=probe_case,
                echo_arguments=echo_arguments,
                selected_document_id=selected_document_id,
                tool_id=tool_id,
                broker_url=broker_url,
                worker_credential=worker_credential,
                broker_probe=broker_probe,
            )
            config_path, config_sha256 = self._write_protected_task_config(config)
            try:
                # Serialize launch admission with shutdown so no process can be
                # created in the gap between shutdown's active-job snapshot and
                # registration of this new handle.
                return self._start_configured_probe(
                    config, config_path, config_sha256, before_resume=before_resume
                )
            except Exception:
                if config_path.exists():
                    _remove_owned_task_config(config_path, self.layout.selected_root, config_sha256)
                raise

    def _write_protected_task_config(
        self,
        config: A3ProbeConfiguration | DocumentToolsWorkerConfiguration,
        *,
        prefix: str = ".aclais-a3-task-",
    ) -> tuple[Path, str]:
        import hashlib

        for _ in range(5):
            config_path = self.layout.selected_root / f"{prefix}{config.task_id.hex}.json"
            try:
                with config_path.open("xb") as stream:
                    payload = config.model_dump_json(exclude_none=True).encode("utf-8")
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                _require_plain_path(self._api, config_path)
                return config_path, hashlib.sha256(payload).hexdigest()
            except FileExistsError:
                continue
            except OSError as exc:
                raise LauncherError(
                    "task_configuration_create", getattr(exc, "winerror", None)
                ) from None
        raise LauncherError("task_configuration_collision")

    def _start_configured_probe(
        self,
        config: A3ProbeConfiguration,
        config_path: Path,
        config_sha256: str,
        *,
        before_resume: Callable[[int, int, str], None] | None = None,
    ) -> WorkerHandle:
        return self._start_configured_worker(
            config,
            config_path,
            config_sha256,
            entrypoint=self.layout.private_probe,
            expected_sha256=self.layout.source_sha256,
            extra_arguments=tuple(
                item for value in config.echo_arguments for item in ("--echo-arg", value)
            ),
            extra_checked_paths=(Path(config.selected_input),),
            before_resume=before_resume,
        )

    def start_registered_worker(
        self,
        config: DocumentToolsWorkerConfiguration,
        *,
        entrypoint: Path,
        expected_sha256: str,
        before_resume: Callable[[int, int, str], None] | None = None,
    ) -> WorkerHandle:
        """Start only the installed formatter under the verified A2 worker identity."""

        expected_entrypoint = (
            self.layout.code_root
            / "document-tools"
            / "workers"
            / "report_formatter"
            / "entrypoint.py"
        )
        if (
            entrypoint.resolve(strict=False) != expected_entrypoint.resolve(strict=False)
            or config.fixture_root != str(self.layout.root)
            or config.scope_manifest.root_id != uuid.UUID(self.layout.root_id)
            or config.scope_manifest.root_path != str(self.layout.root)
            or Path(config.temporary_output) != self.layout.task_output_root / str(config.task_id)
            or config.broker_url != "http://127.0.0.1:8765/api/broker/operations"
        ):
            raise LauncherError("registered_worker_scope_invalid")
        return self._start_worker_configuration(
            config,
            entrypoint=entrypoint,
            expected_sha256=expected_sha256,
            prefix=".aclais-doc-tools-task-",
            before_resume=before_resume,
        )

    def start_private_document_tools_worker_for_test(
        self,
        config: DocumentToolsWorkerConfiguration,
        *,
        before_resume: Callable[[int, int, str], None] | None = None,
    ) -> WorkerHandle:
        """Private harness path restricted to a new fixture below temporary-output."""

        entrypoint = (
            self.layout.code_root
            / "document-tools"
            / "workers"
            / "report_formatter"
            / "entrypoint.py"
        )
        try:
            baseline_root = Path(config.fixture_root).resolve(strict=True)
            baseline_root.relative_to(self.layout.output_root.resolve(strict=True))
            Path(config.temporary_output).resolve(strict=True).relative_to(baseline_root)
        except (OSError, ValueError):
            raise LauncherError("private_fixture_scope_invalid") from None
        if (
            config.scope_manifest.root_path != config.fixture_root
            or config.scope_manifest.root_id == uuid.UUID(self.layout.root_id)
            or not (baseline_root / ".fixture-sentinel.json").is_file()
        ):
            raise LauncherError("private_fixture_sentinel_invalid")
        return self._start_worker_configuration(
            config,
            entrypoint=entrypoint,
            expected_sha256=_sha256_file(entrypoint),
            prefix=".aclais-doc-tools-test-task-",
            before_resume=before_resume,
        )

    def _start_worker_configuration(
        self,
        config: DocumentToolsWorkerConfiguration,
        *,
        entrypoint: Path,
        expected_sha256: str,
        prefix: str,
        before_resume: Callable[[int, int, str], None] | None,
    ) -> WorkerHandle:
        with self._lock:
            if self._shutdown:
                raise LauncherError("controller_shutdown")
            if (
                not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
                or _sha256_file(entrypoint) != expected_sha256
            ):
                raise LauncherError("fixed_entrypoint_integrity_failed")
            config_path, config_sha256 = self._write_protected_task_config(config, prefix=prefix)
            try:
                return self._start_configured_worker(
                    config,
                    config_path,
                    config_sha256,
                    entrypoint=entrypoint,
                    expected_sha256=expected_sha256,
                    extra_arguments=(),
                    extra_checked_paths=(),
                    before_resume=before_resume,
                )
            except Exception:
                if config_path.exists():
                    _remove_owned_task_config(config_path, self.layout.selected_root, config_sha256)
                raise

    def _start_configured_worker(
        self,
        config: A3ProbeConfiguration | DocumentToolsWorkerConfiguration,
        config_path: Path,
        config_sha256: str,
        *,
        entrypoint: Path,
        expected_sha256: str,
        extra_arguments: tuple[str, ...],
        extra_checked_paths: tuple[Path, ...],
        before_resume: Callable[[int, int, str], None] | None = None,
    ) -> WorkerHandle:
        layout = self.layout
        api = self._api
        for path in (
            entrypoint,
            layout.python_exe,
            Path(config.temporary_output),
            *extra_checked_paths,
        ):
            _require_plain_path(api, path)
        if not layout.python_exe.is_file() or not entrypoint.is_file():
            raise LauncherError("fixed_entrypoint_missing")
        if _sha256_file(entrypoint) != expected_sha256:
            raise LauncherError("fixed_entrypoint_integrity_failed")

        current_sid, current_admin = api.current_identity()
        if current_sid != layout.owner_sid or current_admin:
            raise LauncherError("controller_identity_changed")

        stdout_read = _Handle(api, None, "stdout_read")
        stderr_read = _Handle(api, None, "stderr_read")
        stdout_write = _Handle(api, None, "stdout_write")
        stderr_write = _Handle(api, None, "stderr_write")
        stdin_null = _Handle(api, None, "stdin_null")
        job = _Handle(api, None, "job")
        process = _Handle(api, None, "process")
        primary_thread = _Handle(api, None, "primary_thread")
        read_threads: list[threading.Thread] = []
        captures = {"stdout": _CapturedBytes(bytearray()), "stderr": _CapturedBytes(bytearray())}
        config_cleanup_needed = True
        process_created = False
        ownership_transferred = False
        assigned = False
        launch_sequence: list[str] = []
        phase = "pipe_setup"
        cleanup_failure: LauncherError | None = None

        try:
            stdout_read_raw, stdout_write_raw = api.create_pipe()
            stdout_read = _Handle(api, stdout_read_raw, "stdout_read")
            stdout_write = _Handle(api, stdout_write_raw, "stdout_write")
            stderr_read_raw, stderr_write_raw = api.create_pipe()
            stderr_read = _Handle(api, stderr_read_raw, "stderr_read")
            stderr_write = _Handle(api, stderr_write_raw, "stderr_write")
            stdin_null = _Handle(api, api.create_null_input(), "stdin_null")
            job = _Handle(api, api.create_job(), "job")

            environment = _minimal_environment(config.temporary_output)
            args = (
                "-I",
                "-B",
                str(entrypoint),
                "--task-config",
                str(config_path),
                *extra_arguments,
            )
            phase = "credential_read"
            credential = self._credential_reader()
            try:
                phase = "alternate_user_process_create"
                process_raw, thread_raw, pid = api.create_process(
                    credential,
                    layout.python_exe,
                    args,
                    environment,
                    Path(config.temporary_output),
                    stdin_null.raw,
                    stdout_write.raw,
                    stderr_write.raw,
                )
                process_created = True
                process = _Handle(api, process_raw, "process")
                primary_thread = _Handle(api, thread_raw, "primary_thread")
                launch_sequence.append("created_suspended")
            finally:
                credential.clear()

            stdout_write.close()
            stderr_write.close()

            phase = "worker_identity_verify"
            observed_sid, worker_is_admin = api.process_identity(process.raw)
            if observed_sid != layout.worker_sid or worker_is_admin:
                raise IdentityMismatch("worker_identity_mismatch")
            launch_sequence.append("identity_verified")

            phase = "job_configuration"
            api.configure_kill_on_close(job.raw)
            if not api.verify_kill_on_close(job.raw):
                raise LauncherError("job_configuration_invalid")
            launch_sequence.append("job_configured")

            for channel, handle in (("stdout", stdout_read), ("stderr", stderr_read)):
                reader = threading.Thread(
                    target=_drain_pipe,
                    name=f"aclais-{channel}-drain-{pid}",
                    args=(api, handle.raw, captures[channel]),
                    daemon=True,
                )
                reader.start()
                read_threads.append(reader)

            phase = "job_assignment"
            api.assign_process_to_job(job.raw, process.raw)
            if not api.is_process_in_job(process.raw, job.raw):
                raise LauncherError("job_assignment_not_observed")
            assigned = True
            launch_sequence.append("assigned")
            creation_time = api.process_creation_time(process.raw)

            if before_resume is not None:
                phase = "pre_resume_commit"
                before_resume(pid, creation_time, observed_sid)

            phase = "job_resume"
            previous_suspend_count = api.resume_thread(primary_thread.raw)
            if previous_suspend_count != 1:
                raise LauncherError("worker_resume_count_invalid")
            launch_sequence.append("resumed")

            handle = WorkerHandle(
                controller=self,
                api=api,
                config=config.model_copy(update={"broker_url": None, "worker_credential": None}),
                config_path=config_path,
                process=process,
                primary_thread=primary_thread,
                job=job,
                stdout_read=stdout_read,
                stderr_read=stderr_read,
                readers=read_threads,
                captures=captures,
                pid=pid,
                creation_time=creation_time,
                worker_sid=observed_sid,
                config_sha256=config_sha256,
                launch_sequence=tuple(launch_sequence),
            )
            ownership_transferred = True
            process = primary_thread = job = stdout_read = stderr_read = None
            config_cleanup_needed = False
            with self._lock:
                if self._shutdown:
                    handle.terminate("controller_shutdown")
                    raise LauncherError("controller_shutdown")
                self._active.add(handle)
            return handle
        except Exception as exc:
            if process_created and process.raw:
                try:
                    if assigned and job.raw:
                        api.terminate_job(job.raw)
                        if api.wait(job.raw, _CLEANUP_TIMEOUT_MS) != _WAIT_OBJECT_0:
                            raise LauncherError("launch_job_cleanup_timeout")
                    else:
                        api.terminate_process(process.raw)
                        if api.wait(process.raw, _CLEANUP_TIMEOUT_MS) != _WAIT_OBJECT_0:
                            raise LauncherError("launch_process_cleanup_timeout")
                except Exception as cleanup_error:
                    cleanup_failure = LauncherError(
                        "launch_cleanup",
                        diagnostic=f"{type(cleanup_error).__name__}",
                    )
                    if job.raw:
                        try:
                            job.close()
                            if api.wait(process.raw, _CLEANUP_TIMEOUT_MS) != _WAIT_OBJECT_0:
                                cleanup_failure = LauncherError("launch_job_close_cleanup_timeout")
                        except Exception:
                            cleanup_failure = LauncherError("launch_job_close_cleanup")
            if cleanup_failure:
                raise cleanup_failure from None
            if isinstance(exc, LauncherError):
                if process_created:
                    exc.process_pid = pid
                raise
            symbol = getattr(exc, "name", None)
            safe_symbol = (
                f":{symbol}"
                if isinstance(symbol, str) and re.fullmatch(r"[A-Za-z0-9_]+", symbol)
                else ""
            )
            raise LauncherError(
                "launch_setup", diagnostic=f"{phase}:{type(exc).__name__}{safe_symbol}"
            ) from None
        finally:
            for handle in (stdout_write, stderr_write, stdin_null):
                if handle and not handle.closed:
                    try:
                        handle.close()
                    except Exception:
                        pass
            if process_created and not ownership_transferred:
                for reader in read_threads:
                    reader.join(timeout=2.0)
                if any(reader.is_alive() for reader in read_threads):
                    for handle in (stdout_read, stderr_read):
                        if handle and not handle.closed:
                            try:
                                handle.close()
                            except Exception:
                                pass
                    for reader in read_threads:
                        reader.join(timeout=1.0)
                if any(reader.is_alive() for reader in read_threads):
                    raise LauncherError("launch_pipe_reader_cleanup")
            for handle in (primary_thread, process, job, stdout_read, stderr_read):
                if handle and not handle.closed:
                    try:
                        handle.close()
                    except Exception:
                        pass
            if config_cleanup_needed:
                _remove_owned_task_config(config_path, layout.selected_root, config_sha256)

    def _finished(self, handle: WorkerHandle) -> None:
        with self._lock:
            self._active.discard(handle)

    def verify_stored_process_stopped(
        self, pid: int, creation_time_100ns: int, worker_sid: str
    ) -> bool:
        """Check a retained PID without signaling or terminating a recycled process."""

        process = self._api.open_process(pid)
        if process is None:
            error = ctypes.get_last_error()
            if error in (6, 87, 1168):  # INVALID_HANDLE, INVALID_PARAMETER, NOT_FOUND
                return True
            return False
        try:
            if self._api.process_creation_time(process) != creation_time_100ns:
                return True
            observed_sid, is_admin = self._api.process_identity(process)
            if observed_sid != worker_sid or is_admin:
                return False
            return self._api.wait(process, 0) == _WAIT_OBJECT_0
        except LauncherError:
            return False
        finally:
            self._api.close_handle(process)

    def cleanup_stale_task_configurations(self) -> None:
        """Remove only fixed-prefix task configs after startup has verified old workers stopped."""

        _require_plain_path(self._api, self.layout.selected_root)
        for prefix in (
            ".aclais-a3-task-",
            ".aclais-doc-tools-task-",
            ".aclais-doc-tools-test-task-",
        ):
            for path in self.layout.selected_root.glob(f"{prefix}*.json"):
                if path.parent != self.layout.selected_root:
                    raise LauncherError("task_configuration_cleanup_scope")
                _remove_owned_file(path, self.layout.selected_root)

    def shutdown(self) -> None:
        with self._lock:
            self._shutdown = True
            active = tuple(self._active)
        failures: list[Exception] = []
        for handle in active:
            try:
                handle.terminate("controller_shutdown")
            except Exception as exc:
                failures.append(exc)
        if failures:
            raise LauncherError("controller_shutdown_cleanup") from None
        with self._lock:
            for guard in self._source_guards:
                self._api.close_handle(guard)
            self._source_guards.clear()


class WorkerHandle:
    """Owns one running worker job until its process tree and pipes have closed."""

    def __init__(
        self,
        *,
        controller: WindowsWorkerController,
        api: _NativeApi,
        config: A3ProbeConfiguration | DocumentToolsWorkerConfiguration,
        config_path: Path,
        process: _Handle,
        primary_thread: _Handle,
        job: _Handle,
        stdout_read: _Handle,
        stderr_read: _Handle,
        readers: list[threading.Thread],
        captures: dict[str, _CapturedBytes],
        pid: int,
        creation_time: int,
        worker_sid: str,
        config_sha256: str,
        launch_sequence: tuple[str, ...],
    ) -> None:
        self.controller = controller
        self.api = api
        self.config = config
        self.config_path = config_path
        self.process = process
        self.primary_thread = primary_thread
        self.job = job
        self.stdout_read = stdout_read
        self.stderr_read = stderr_read
        self.readers = readers
        self.captures = captures
        self.pid = pid
        self.creation_time = creation_time
        self.worker_sid = worker_sid
        self.config_sha256 = config_sha256
        self.launch_sequence = launch_sequence
        self._lock = threading.RLock()
        self._finalize_lock = threading.Lock()
        self._termination_cause: (
            Literal["process_exit", "cancelled", "timeout", "controller_shutdown", "policy_denied"]
            | None
        ) = None
        self._result: WorkerResult | None = None
        self._started = time.monotonic()
        self._closed_handles = False

    @property
    def deadline_at(self) -> float:
        return self._started + self.config.deadline_seconds

    @property
    def handles_closed(self) -> bool:
        return self._closed_handles

    def wait_for_process_exit(self, milliseconds: int) -> bool:
        """Wait for the worker process handle without choosing or finalizing its cause."""

        if isinstance(milliseconds, bool) or not isinstance(milliseconds, int) or milliseconds < 0:
            raise ValueError("process wait duration must be a non-negative integer")
        if self._result is not None:
            return True
        if self.process.closed or self.process.raw is None:
            return self._result is not None
        status = self.api.wait(self.process.raw, milliseconds)
        if status == _WAIT_OBJECT_0:
            return True
        if status != _WAIT_TIMEOUT:
            raise LauncherError("worker_wait_status")
        return False

    def process_exit_observed(self) -> bool:
        return self.wait_for_process_exit(0)

    def finish_process_exit(self) -> WorkerResult:
        """Finalize a process exit already admitted by the shared task lock."""

        if not self.process_exit_observed():
            raise LauncherError("worker_exit_not_observed")
        return self._finalize("process_exit")

    def wait(self) -> WorkerResult:
        while True:
            with self._lock:
                if self._result is not None:
                    return self._result
                cause = self._termination_cause
            if cause is not None:
                return self._finalize(cause)

            remaining = self.deadline_at - time.monotonic()
            if remaining <= 0:
                self.terminate("timeout")
                continue
            wait_ms = min(_POLL_INTERVAL_MS, max(1, int(remaining * 1000)))
            status = self.api.wait(self.process.raw, wait_ms)
            if status == _WAIT_OBJECT_0:
                with self._lock:
                    if self._termination_cause is None:
                        self._termination_cause = (
                            "timeout" if time.monotonic() >= self.deadline_at else "process_exit"
                        )
                continue
            if status != _WAIT_TIMEOUT:
                raise LauncherError("worker_wait_status")

    def cancel(self) -> WorkerResult:
        return self.terminate("cancelled")

    def terminate(
        self,
        cause: Literal["cancelled", "timeout", "controller_shutdown", "policy_denied"],
    ) -> WorkerResult:
        with self._lock:
            if self._result is not None:
                return self._result
            if self._termination_cause is None:
                self._termination_cause = cause
            effective_cause = self._termination_cause
        return self._finalize(effective_cause)

    def _finalize(
        self,
        cause: Literal[
            "process_exit", "cancelled", "timeout", "controller_shutdown", "policy_denied"
        ],
    ) -> WorkerResult:
        with self._finalize_lock:
            with self._lock:
                if self._result is not None:
                    return self._result
                if self._termination_cause is None:
                    self._termination_cause = cause
                cause = self._termination_cause

            if cause == "process_exit":
                if self.api.wait(self.job.raw, 0) != _WAIT_OBJECT_0:
                    self.api.terminate_job(self.job.raw)
            else:
                self.api.terminate_job(self.job.raw)

            if self.api.wait(self.job.raw, _CLEANUP_TIMEOUT_MS) != _WAIT_OBJECT_0:
                # Closing the last handle still invokes KILL_ON_JOB_CLOSE. Do not
                # report a passing result when the job did not signal in time.
                self.job.close()
                raise LauncherError("job_tree_cleanup_timeout")
            if self.api.wait(self.process.raw, _CLEANUP_TIMEOUT_MS) != _WAIT_OBJECT_0:
                raise LauncherError("worker_process_cleanup_timeout")

            for reader in self.readers:
                reader.join(timeout=2.0)
            if any(reader.is_alive() for reader in self.readers):
                self.stdout_read.close()
                self.stderr_read.close()
                for reader in self.readers:
                    reader.join(timeout=1.0)
            if any(reader.is_alive() for reader in self.readers):
                raise LauncherError("worker_output_drain_timeout")

            if self.captures["stdout"].read_error is not None:
                raise LauncherError("stdout_pipe_read", self.captures["stdout"].read_error)
            if self.captures["stderr"].read_error is not None:
                raise LauncherError("stderr_pipe_read", self.captures["stderr"].read_error)

            exit_code = self.api.process_exit_code(self.process.raw)
            stdout_lines, stdout_line_truncated = _captured_lines("stdout", self.captures["stdout"])
            stderr_lines, stderr_line_truncated = _captured_lines("stderr", self.captures["stderr"])
            stdout_capture = self.captures["stdout"]
            stderr_capture = self.captures["stderr"]
            self._close_all_handles()
            config_unchanged = (
                self.config_path.is_file() and _sha256_file(self.config_path) == self.config_sha256
            )
            if not config_unchanged:
                _remove_owned_file(self.config_path, self.controller.layout.selected_root)
                self.controller._finished(self)
                raise LauncherError("task_configuration_integrity")
            _remove_owned_task_config(
                self.config_path, self.controller.layout.selected_root, self.config_sha256
            )

            result = WorkerResult(
                pid=self.pid,
                creation_time_100ns=self.creation_time,
                worker_sid=self.worker_sid,
                worker_is_administrator=False,
                assigned_to_job_before_resume=True,
                job_kill_on_close=True,
                task_configuration_unchanged=True,
                exit_code=exit_code,
                termination_cause=cause,
                process_tree_stopped=True,
                stdout=tuple(stdout_lines),
                stderr=tuple(stderr_lines),
                stdout_bytes_observed=stdout_capture.total,
                stderr_bytes_observed=stderr_capture.total,
                stdout_truncated=stdout_capture.truncated_bytes or stdout_line_truncated,
                stderr_truncated=stderr_capture.truncated_bytes or stderr_line_truncated,
                launch_sequence=self.launch_sequence,
            )
            with self._lock:
                self._result = result
            self.controller._finished(self)
            return result

    def _close_all_handles(self) -> None:
        failures: list[Exception] = []
        for handle in (
            self.primary_thread,
            self.process,
            self.stdout_read,
            self.stderr_read,
            self.job,
        ):
            if not handle.closed:
                try:
                    handle.close()
                except Exception as exc:
                    failures.append(exc)
        self._closed_handles = all(
            handle.closed
            for handle in (
                self.primary_thread,
                self.process,
                self.stdout_read,
                self.stderr_read,
                self.job,
            )
        )
        if failures or not self._closed_handles:
            raise LauncherError("worker_handle_cleanup") from None


def _minimal_environment(temporary_output: str) -> dict[str, str]:
    system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    if not system_root or not Path(system_root).is_absolute():
        raise LauncherError("system_root_unavailable")
    return {
        "SystemRoot": system_root,
        "WINDIR": system_root,
        "TEMP": temporary_output,
        "TMP": temporary_output,
    }


def _require_plain_path(api: _NativeApi, path: Path) -> None:
    try:
        if not path.is_absolute():
            raise LauncherError("path_not_absolute")
        current = Path(path.anchor)
        remainder = path.parts[1:]
        for index, part in enumerate(remainder):
            current = current / part
            if not current.exists():
                raise LauncherError("managed_path_missing")
            attributes = api.kernel32.GetFileAttributesW(str(current))
            if attributes == 0xFFFFFFFF:
                api._raise_last_error("managed_path_attributes")
            if attributes & 0x00000400:
                raise LauncherError("managed_reparse_point_refused")
            if index < len(remainder) - 1 and not current.is_dir():
                raise LauncherError("managed_parent_not_directory")
    except OSError as exc:
        raise LauncherError("managed_path_check", getattr(exc, "winerror", None)) from None


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _remove_owned_file(path: Path, parent: Path) -> None:
    try:
        if path.parent != parent:
            raise LauncherError("task_configuration_cleanup_scope")
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise LauncherError("task_configuration_cleanup", getattr(exc, "winerror", None)) from None


def _remove_owned_task_config(path: Path, parent: Path, expected_sha256: str) -> None:
    unchanged = path.is_file() and _sha256_file(path) == expected_sha256
    _remove_owned_file(path, parent)
    if not unchanged:
        raise LauncherError("task_configuration_integrity")


def _drain_pipe(api: _NativeApi, handle: ctypes.c_void_p, capture: _CapturedBytes) -> None:
    while True:
        try:
            chunk = api.read_pipe(handle)
        except LauncherError as exc:
            capture.read_error = exc.winerror
            return
        if not chunk:
            return
        capture.total += len(chunk)
        remaining = _MAX_CAPTURE_BYTES - len(capture.buffer)
        if remaining > 0:
            capture.buffer.extend(chunk[:remaining])
        if len(chunk) > remaining:
            capture.truncated_bytes = True


def _captured_lines(
    channel: Literal["stdout", "stderr"], capture: _CapturedBytes
) -> tuple[list[CapturedLine], bool]:
    lines: list[CapturedLine] = []
    truncated_line = False
    retained_bytes = 0
    raw_lines = bytes(capture.buffer).splitlines()
    if len(raw_lines) > _MAX_CAPTURE_LINES:
        raw_lines = raw_lines[:_MAX_CAPTURE_LINES]
        truncated_line = True
    for raw_line in raw_lines:
        clipped = raw_line[:_MAX_LINE_BYTES]
        if len(raw_line) > _MAX_LINE_BYTES:
            truncated_line = True
        text = clipped.decode("utf-8", errors="replace")
        try:
            parsed: Any = json.loads(text)
        except json.JSONDecodeError:
            safe_text = redact_text(text)
        else:
            safe_text = json.dumps(redact_fields(parsed), ensure_ascii=False, separators=(",", ":"))
        # Redaction can replace a short key/value with a longer marker. Keep the
        # final UTF-8 line bounded even in that case.
        safe_bytes = safe_text.encode("utf-8")
        if len(safe_bytes) > _MAX_LINE_BYTES:
            safe_text = safe_bytes[:_MAX_LINE_BYTES].decode("utf-8", errors="ignore")
            truncated_line = True
            safe_bytes = safe_text.encode("utf-8")
        remaining = _MAX_CAPTURE_BYTES - retained_bytes
        if len(safe_bytes) + 1 > remaining:
            safe_text = safe_bytes[: max(0, remaining - 1)].decode("utf-8", errors="ignore")
            safe_bytes = safe_text.encode("utf-8")
            truncated_line = True
        if remaining <= 0:
            truncated_line = True
            break
        lines.append(CapturedLine(channel=channel, text=safe_text))
        retained_bytes += len(safe_bytes) + 1
    return lines, truncated_line


__all__ = [
    "CredentialUnavailable",
    "IdentityMismatch",
    "LauncherError",
    "RuntimeLayout",
    "WorkerHandle",
    "WindowsWorkerController",
]
