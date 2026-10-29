"""A10 target-machine negative readiness and owned operator lifecycle checks."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

import pytest

from aclais.evidence import source_tree_sha256
from aclais.launcher.windows import RuntimeLayout, WindowsWorkerController, _NativeApi
from aclais.operator import plain, stop_controller
from aclais.readiness import Readiness, ReadinessError, boundary_check

pytestmark = pytest.mark.windows_enforcement


def test_g1_operator_refuses_actual_windows_junction_without_following_it(tmp_path: Path):
    owned, outside = tmp_path / "owned", tmp_path / "outside"
    owned.mkdir()
    outside.mkdir()
    (outside / "untouched.txt").write_text("synthetic outside target")
    script = tmp_path / "junction.ps1"
    script.write_text(
        "param($root,$outside)\n$ErrorActionPreference='Stop'\n"
        "New-Item -ItemType Junction -Path (Join-Path $root 'junction') "
        "-Target $outside | Out-Null\n"
    )
    result = subprocess.run(
        [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script),
            str(owned),
            str(outside),
        ],
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 0, "Real Windows junction fixture creation failed"
    with pytest.raises(ValueError, match="reparse"):
        plain(owned, "junction/untouched.txt")
    assert (outside / "untouched.txt").read_text() == "synthetic outside target"


def test_g1_controller_namespace_guards_protect_actual_worker_and_release_handles():
    controller = WindowsWorkerController(RuntimeLayout.open())
    guards = tuple(controller._source_guards)
    assert guards
    try:
        script = Path(__file__).resolve().parents[2] / "scripts/run_a2_access_probe.ps1"
        result = subprocess.run(
            [
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(script),
                "-UseExistingControllerNamespaceGuard",
            ],
            capture_output=True,
            timeout=120,
        )
        assert result.returncode == 0, "Actual worker namespace DELETE-access probe failed"
    finally:
        controller.shutdown()
    assert controller._source_guards == []
    for handle in guards:
        flags = ctypes.c_uint32()
        assert not controller._api.kernel32.GetHandleInformation(handle, ctypes.byref(flags))


def test_g1_checkout_reprotection_handles_noncanonical_dependency_acls(tmp_path: Path):
    checkout = tmp_path / "owned-acl-fixture"
    checkout.mkdir()
    (checkout / "dependency.py").write_text("# synthetic ACL test only\n")
    helper = Path(__file__).resolve().parents[2] / "scripts/a2_acl.ps1"
    script = r"""
param($helper, $target)
$ErrorActionPreference = 'Stop'
. $helper
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$worker = (Get-LocalUser -Name AclaisWorker).SID.Value
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm("D:P(A;;FA;;;$owner)(A;ID;FR;;;$worker)(A;;FA;;;SY)")
[AclaisA2AclNative]::ApplyDaclOnly($target, $acl.GetSecurityDescriptorBinaryForm())
if ((Get-Acl -LiteralPath $target).AreAccessRulesCanonical) {
    throw 'Test did not create a noncanonical ACL.'
}
Set-A2WorkerDenyTree -Path $target -WorkerSid $worker -Recursive
Set-A2WorkerDenyTree -Path $target -WorkerSid $worker -Recursive
foreach ($item in @(Get-Item -LiteralPath $target) + @(Get-ChildItem -LiteralPath $target)) {
    $actual = Get-Acl -LiteralPath $item.FullName
    if (-not $actual.AreAccessRulesCanonical) { throw 'Reprotection is not repeatable.' }
    $denials = @($actual.Access | Where-Object {
        $_.AccessControlType -eq 'Deny' -and
        $_.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value -eq $worker -and
        [int]$_.FileSystemRights -eq [int][Security.AccessControl.FileSystemRights]::FullControl
    })
    if ($denials.Count -lt 1) { throw 'Worker protection missing.' }
}
"""
    path = tmp_path / "canonical-acl.ps1"
    path.write_text(script)
    result = subprocess.run(
        [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(path),
            str(helper),
            str(checkout),
        ],
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, "Scoped ACL canonicalization/reapplication failed"


def test_g1_live_readiness_refuses_permission_drift_before_task_creation():
    layout = RuntimeLayout.open()
    boundary_check(require_idle=True)
    readiness = Readiness(layout)
    readiness.require_core()
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    sddl = subprocess.check_output(
        [
            str(powershell),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-Acl -LiteralPath 'C:\\ACLAIS-Lab\\store\\originals').Sddl",
        ],
        text=True,
    ).strip()
    api = _NativeApi()
    directory = layout.root / "store/originals"
    try:
        api.set_protected_directory_acl(
            directory,
            owner_sid=layout.owner_sid,
            worker_sid=layout.worker_sid,
            worker_rights="GRGX",
        )
        with pytest.raises(ReadinessError):
            readiness.require_core()
        assert not readiness.health().protection_ready
    finally:
        descriptor = ctypes.c_void_p()
        size = ctypes.c_uint32()
        assert api.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), ctypes.byref(size)
        )
        try:
            assert api.advapi32.SetFileSecurityW(str(directory), 4 | 0x80000000, descriptor)
        finally:
            api.kernel32.LocalFree(descriptor)
    readiness.require_core()


def test_g1_owned_start_duplicate_refusal_reset_stop_and_process_identity(tmp_path: Path):
    layout = RuntimeLayout.open()
    boundary_check(require_idle=True)
    code = (
        "import sys,webbrowser;webbrowser.open=lambda *a,**k:True;"
        "sys.argv=['aclais.operator','start'];from aclais.operator import main;main()"
    )
    console = plain(layout.root, "evidence/g1-owner-console.log")
    controller = None
    with console.open("wb") as capture:
        try:
            controller = subprocess.Popen(
                [sys.executable, "-c", code], cwd=tmp_path, stdout=capture, stderr=capture
            )
            # Two startup audits and the first health audit are each bounded at 45s.
            deadline = time.monotonic() + 3 * 45 + 5
            health = None
            while time.monotonic() < deadline:
                if controller.poll() is not None:
                    pytest.fail("protected operator startup exited before readiness")
                try:
                    with urllib.request.urlopen("http://127.0.0.1:8765/api/health", timeout=8) as r:
                        health = json.load(r)
                    break
                except OSError:
                    time.sleep(0.1)
            assert health is not None
            assert all(
                c["status"] == "pass" for c in health["checks"] if c["id"] != "g1_protection"
            )
            assert (
                next(c for c in health["checks"] if c["id"] == "g1_protection")["status"]
                == "unknown"
            )
            duplicate = subprocess.run(
                [sys.executable, "-c", code],
                cwd=tmp_path,
                stdout=capture,
                stderr=capture,
                timeout=20,
            )
            assert duplicate.returncode == 1 and controller.poll() is None
            reset = subprocess.run(
                [sys.executable, "-m", "aclais.operator", "reset"],
                stdout=capture,
                stderr=capture,
                timeout=45,
            )
            assert reset.returncode == 1 and controller.poll() is None
            stop_controller()
            assert controller.wait(timeout=15) == 0
            assert not plain(layout.root, "state/controller-instance.json").exists()
        finally:
            if controller is not None and controller.poll() is None:
                # Failure cleanup uses only this retained test child's handle, even
                # before its record exists. The passing path must use graceful stop.
                controller.terminate()
                controller.wait(timeout=20)
    unrelated = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(15)"])
    record = plain(layout.root, "state/controller-instance.json")
    try:
        record.write_text(
            json.dumps({"pid": unrelated.pid, "creation_time": 1, "instance_id": str(uuid.uuid4())})
        )
        with pytest.raises(ReadinessError):
            stop_controller()
        assert unrelated.poll() is None
    finally:
        record.unlink(missing_ok=True)
        unrelated.terminate()
        unrelated.wait(timeout=10)
    with console.open("ab") as capture:
        launcher = WindowsWorkerController(layout)
        handle = launcher.start_a3_private_probe(probe_case="child_wait", deadline_seconds=30)
        try:
            with pytest.raises(ReadinessError) as blocked:
                boundary_check(require_idle=True)
            assert any(
                c.id == "no_active_worker" and c.status == "fail" for c in blocked.value.checks
            )
            result = subprocess.run(
                [sys.executable, "-m", "aclais.operator", "reset"],
                stdout=capture,
                stderr=capture,
                timeout=45,
            )
            assert result.returncode == 1
            assert not handle.process_exit_observed()
        finally:
            stopped = handle.cancel()
            assert stopped.process_tree_stopped
            launcher.shutdown()
        result = subprocess.run(
            [sys.executable, "-m", "aclais.operator", "reset"],
            stdout=capture,
            stderr=capture,
            timeout=45,
        )
        assert result.returncode == 0
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "aclais.operator",
                "teardown",
                "--confirm-root-id",
                str(uuid.uuid4()),
            ],
            stdout=capture,
            stderr=capture,
            timeout=45,
        )
        assert result.returncode == 1 and layout.root.exists()
    Readiness(RuntimeLayout.open()).require_core()
    report = {
        "checkpoint": "A10",
        "passed": True,
        "tested_backend_sha256": source_tree_sha256(
            Path(__file__).resolve().parents[2] / "backend/src/aclais"
        ),
        "permission_drift_refused": True,
        "duplicate_start_refused": True,
        "active_controller_reset_refused": True,
        "active_worker_reset_refused": True,
        "scoped_stop_observed": True,
        "wrong_process_identity_refused": True,
        "owned_reset_completed": True,
        "wrong_teardown_confirmation_refused": True,
        "raw_values_committed": False,
    }
    destination = Path(__file__).resolve().parents[3] / "evidence/g1-operator-summary.json"
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
