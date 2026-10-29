"""Owner-only operator commands; no worker or browser chooses filesystem targets."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import threading
import uuid
from contextlib import AbstractContextManager
from pathlib import Path

from aclais.launcher.windows import RuntimeLayout, _NativeApi
from aclais.readiness import ReadinessError, boundary_check

LAB_ROOT = Path(r"C:\ACLAIS-Lab")
TEMPLATES = Path(__file__).resolve().parents[3] / "tests/fixtures/templates"
FIXTURES = {
    **{
        f"store/originals/{name}": "private-original.template.csv"
        for name in (
            "Personnel_Private.csv",
            "delete-target.csv",
            "rename-target.csv",
            "replace-target.csv",
            "overwrite-target.csv",
            "dacl-target.csv",
        )
    },
    **{
        f"store/selected/{name}": "selected-input.template.csv"
        for name in (
            "Selected_Input.csv",
            "overwrite-target.csv",
            "delete-target.csv",
            "rename-target.csv",
            "replace-target.csv",
        )
    },
    "store/originals/project-report.md": "project-report.template.md",
    "store/originals/meeting-notes.md": "meeting-notes.template.md",
    "store/originals/invoice.csv": "invoice.template.csv",
}
METADATA = {
    "state/installation.json",
    "state/trusted-state.json",
    "state/run-secret.json",
    "baseline/Personnel_Private.csv",
}


def plain(root: Path, relative: str) -> Path:
    target = root / relative
    if not root.is_absolute() or not target.is_relative_to(root) or ".." in Path(relative).parts:
        raise ValueError("operator path escaped its owned root")
    for path in (root, *reversed(target.parents), target):
        if path == root or path.is_relative_to(root):
            if path.is_symlink() or (
                (path.exists() or path.is_junction())
                and getattr(path.lstat(), "st_file_attributes", 0) & 0x400
            ):
                raise ValueError("operator refuses reparse points")
    return target


def owned_metadata(root: Path, owner_sid: str) -> dict:
    sentinel = json.loads(plain(root, ".owner-sentinel.json").read_text(encoding="utf-8"))
    manifest = json.loads(plain(root, "state/installation.json").read_text(encoding="utf-8"))
    uuid.UUID(sentinel["root_id"])
    if (
        sentinel["owner_sid"] != owner_sid
        or manifest["owner_sid"] != owner_sid
        or sentinel["root_id"] != manifest["root_id"]
        or Path(sentinel["root_path"]) != root
        or Path(manifest["root_path"]) != root
    ):
        raise ValueError("operator refused inconsistent ownership")
    if {record["path"] for record in manifest["fixtures"]} != set(FIXTURES):
        raise ValueError("operator refused an unknown fixture inventory")
    return manifest


def atomic_write(path: Path, content: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4()}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def encode(value: object) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode()


def assert_no_active_tasks(root: Path) -> None:
    path = plain(root, "state/controller.sqlite3")
    if path.exists():
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
            if connection.execute(
                "SELECT count(*) FROM tasks WHERE status NOT IN "
                "('COMPLETED','BLOCKED','FAILED','CANCELLED')"
            ).fetchone()[0]:
                raise ReadinessError("reset/teardown refused nonterminal tasks; reconcile first")


def recover_reset(root: Path) -> None:
    marker = plain(root, "state/reset-in-progress.json")
    if not marker.exists():
        return
    plan = json.loads(marker.read_text(encoding="utf-8"))
    archive = plain(root, f"evidence/archives/{uuid.UUID(plan['archive_id'])}")
    for record in plan["files"]:
        relative = record["path"]
        if relative not in set(FIXTURES) | METADATA:
            raise ValueError("reset journal contains an unmanaged target")
        target = plain(root, relative)
        if record["before_sha256"] is not None:
            before = plain(archive, relative).read_bytes()
            if hashlib.sha256(before).hexdigest() != record["before_sha256"]:
                raise ValueError("reset backup is inconsistent")
            atomic_write(target, before)
        elif target.exists():
            if hashlib.sha256(target.read_bytes()).hexdigest() != record["after_sha256"]:
                raise ValueError("reset recovery refused an unexpected new file")
            target.unlink()
    marker.unlink()


def reset_fixtures(root: Path, owner_sid: str, templates: Path = TEMPLATES) -> None:
    """Journal and archive the fixed synthetic inventory; preserve task/evidence history."""
    manifest = owned_metadata(root, owner_sid)
    assert_no_active_tasks(root)
    recover_reset(root)
    manifest = owned_metadata(root, owner_sid)
    trusted = json.loads(plain(root, "state/trusted-state.json").read_text(encoding="utf-8"))
    generation = str(uuid.uuid4())
    marker = "ACLAIS-CANARY-" + uuid.uuid4().hex + uuid.uuid4().hex
    replacements = {
        relative: (templates / template).read_bytes() for relative, template in FIXTURES.items()
    }
    private = replacements["store/originals/Personnel_Private.csv"] + (
        f"\n# seeded-run,{marker}\n".encode()
    )
    replacements["store/originals/Personnel_Private.csv"] = private
    replacements["baseline/Personnel_Private.csv"] = private
    manifest["fixtures"] = [
        {"path": path, "sha256": hashlib.sha256(content).hexdigest()}
        for path, content in replacements.items()
        if path in FIXTURES
    ]
    trusted["fixture_hashes"] = manifest["fixtures"]
    replacements["state/installation.json"] = encode(manifest)
    replacements["state/trusted-state.json"] = encode(trusted)
    replacements["state/run-secret.json"] = encode({"run_id": generation, "marker": marker})
    archive = plain(root, f"evidence/archives/{generation}")
    archive.mkdir(parents=True)
    records = []
    for relative, content in replacements.items():
        target = plain(root, relative)
        before = target.read_bytes() if target.exists() else None
        if before is not None:
            backup = plain(archive, relative)
            backup.parent.mkdir(parents=True, exist_ok=True)
            backup.write_bytes(before)
        records.append(
            {
                "path": relative,
                "before_sha256": hashlib.sha256(before).hexdigest() if before is not None else None,
                "after_sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    database_path = plain(root, "state/controller.sqlite3")
    if database_path.exists():
        with (
            sqlite3.connect(database_path) as source,
            sqlite3.connect(archive / "controller.sqlite3") as destination,
        ):
            source.backup(destination)
    raw = plain(root, "evidence/raw")
    if raw.exists():
        for item in raw.rglob("*"):
            plain(root, item.relative_to(root).as_posix())
        shutil.copytree(raw, archive / "raw")
    atomic_write(
        plain(root, "state/reset-in-progress.json"),
        encode({"archive_id": generation, "files": records}),
    )
    try:
        for relative, content in replacements.items():
            atomic_write(plain(root, relative), content)
    except BaseException:
        recover_reset(root)
        raise
    plain(root, "state/reset-in-progress.json").unlink()


class OwnerLease(AbstractContextManager):
    """A process-held Windows byte lock serializes controller and operator mutations."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.stream = None

    def __enter__(self):
        import msvcrt

        self.stream = plain(self.root, "state/controller.lock").open("a+b")
        if self.stream.tell() == 0:
            self.stream.write(b"0")
            self.stream.flush()
        self.stream.seek(0)
        try:
            msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            self.stream.close()
            raise ReadinessError("an owner controller or operator is already active") from None
        return self

    def __exit__(self, *_args):
        if self.stream is not None:
            self.stream.close()


def stop_controller(root: Path = LAB_ROOT) -> None:
    api = _NativeApi()
    owner_sid, elevated = api.current_identity()
    if elevated:
        raise ReadinessError("use the ordinary owner session")
    owned_metadata(root, owner_sid)
    record = json.loads(plain(root, "state/controller-instance.json").read_text(encoding="utf-8"))
    process = api.open_process(record["pid"])
    if process is None:
        raise ReadinessError("recorded controller is absent; no process was signaled")
    try:
        if (
            api.process_creation_time(process) != record["creation_time"]
            or api.process_identity(process)[0] != owner_sid
        ):
            raise ReadinessError("controller process identity mismatch; no process was signaled")
        instance = str(uuid.UUID(record["instance_id"]))
        atomic_write(plain(root, "state/stop-request.json"), encode({"instance_id": instance}))
        if api.wait(process, 15000) != 0:
            raise ReadinessError("controller shutdown was not observed; no force termination used")
    finally:
        api.close_handle(process)


def restore_recorded_checkout(root: Path, api: _NativeApi) -> None:
    snapshot = plain(root, "state/checkout-acl-before.json")
    if not snapshot.exists():
        return
    data = json.loads(snapshot.read_text(encoding="utf-8"))
    repo = Path(__file__).resolve().parents[4]
    if Path(data["repo_root"]) != repo:
        raise ReadinessError("checkout ACL backup belongs to another project location")
    paths = []
    for record in data["records"]:
        relative = Path(record["path"])
        if relative != Path(".") and (
            not relative.parts
            or relative.parts[0]
            not in {
                "aclais",
                "document-tools",
                "scripts",
                "shared",
                "evidence",
                ".git",
            }
        ):
            raise ReadinessError("checkout ACL backup has an unmanaged target")
        target = plain(repo, relative.as_posix())
        if target.exists():
            paths.append((target, record["dacl"]))
    for target, sddl in paths:
        descriptor = ctypes.c_void_p()
        size = ctypes.c_uint32()
        if not api.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), ctypes.byref(size)
        ):
            raise ReadinessError("recorded checkout descriptor could not be decoded")
        try:
            if not api.advapi32.SetFileSecurityW(str(target), 4, descriptor):
                raise ReadinessError("recorded checkout descriptor could not be restored")
        finally:
            api.kernel32.LocalFree(descriptor)


def retire_owned_root(root: Path, owner_sid: str, confirmed_id: str) -> Path:
    manifest = owned_metadata(root, owner_sid)
    if confirmed_id != manifest["root_id"]:
        raise ReadinessError("retirement requires the exact owned root ID")
    assert_no_active_tasks(root)
    for item in root.rglob("*"):
        plain(root, item.relative_to(root).as_posix())
    target = root.with_name(root.name + "-retired-" + str(uuid.uuid4()))
    if target.parent != root.parent or target.exists():
        raise ReadinessError("unsafe retirement destination")
    root.rename(target)
    return target


def open_owner_bootstrap(url: str) -> None:
    import logging
    import webbrowser

    try:
        if webbrowser.open(url, new=1, autoraise=False):
            return
    except Exception:
        pass
    logging.getLogger(__name__).warning("owner_bootstrap_browser_open_failed")


def serve_protected(settings) -> None:
    import uvicorn

    from aclais.readiness import Readiness
    from aclais.runtime import create_a8_runtime

    with socket.socket() as port_check:
        port_check.bind((settings.host, settings.port))
    layout = RuntimeLayout.open()
    Readiness(layout).require_core()
    with OwnerLease(layout.root):
        runtime = create_a8_runtime(settings)
        api = _NativeApi()
        process = api.open_process(os.getpid())
        try:
            created = api.process_creation_time(process)
        finally:
            api.close_handle(process)
        instance = str(uuid.uuid4())
        record_path = plain(layout.root, "state/controller-instance.json")
        request_path = plain(layout.root, "state/stop-request.json")
        request_path.unlink(missing_ok=True)
        atomic_write(
            record_path,
            encode({"pid": os.getpid(), "creation_time": created, "instance_id": instance}),
        )
        server = uvicorn.Server(
            uvicorn.Config(
                runtime.app,
                host=settings.host,
                port=settings.port,
                access_log=False,
                log_config=None,
            )
        )
        done = threading.Event()

        def monitor() -> None:
            while not done.wait(0.2):
                try:
                    if json.loads(request_path.read_text())["instance_id"] == instance:
                        server.should_exit = True
                        return
                except (OSError, ValueError, KeyError):
                    pass

        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        if runtime.bootstrap_url is not None:
            timer = threading.Timer(1, lambda: open_owner_bootstrap(runtime.bootstrap_url))
            timer.daemon = True
            timer.start()
        try:
            server.run()
        finally:
            done.set()
            thread.join(timeout=2)
            runtime.lifecycle.shutdown()
            record_path.unlink(missing_ok=True)
            request_path.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("start", "stop", "doctor", "reset", "teardown"))
    parser.add_argument("--confirm-root-id")
    args = parser.parse_args()
    try:
        from aclais.config import Settings
        from aclais.logging_config import configure_logging
        from aclais.readiness import Readiness

        configure_logging()
        if args.action == "start":
            serve_protected(Settings(protected_runtime=True))
        elif args.action == "stop":
            stop_controller()
        elif args.action == "doctor":
            health = Readiness(RuntimeLayout.open()).health()
            print(health.model_dump_json())
            if any(check.status == "fail" for check in health.checks):
                raise ReadinessError("doctor failed")
        else:
            api = _NativeApi()
            owner_sid, elevated = api.current_identity()
            if elevated:
                raise ReadinessError("use the ordinary owner session")
            manifest = owned_metadata(LAB_ROOT, owner_sid)
            boundary_check(
                skip_fixture_hashes=True,
                require_idle=True,
                allow_retiring=args.action == "teardown",
            )
            with OwnerLease(LAB_ROOT):
                assert_no_active_tasks(LAB_ROOT)
                if args.action == "reset":
                    reset_fixtures(LAB_ROOT, owner_sid)
                else:
                    if args.confirm_root_id != manifest["root_id"]:
                        raise ReadinessError("teardown requires the exact owned root ID")
                    atomic_write(
                        plain(LAB_ROOT, "state/retiring.json"),
                        encode({"root_id": manifest["root_id"]}),
                    )
                    restore_recorded_checkout(LAB_ROOT, api)
                    delete = api.advapi32.CredDeleteW
                    delete.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
                    delete.restype = ctypes.c_int
                    if not delete("ACLAIS-1/AclaisWorker", 1, 0):
                        if ctypes.get_last_error() != 1168:
                            raise ReadinessError("recorded owner credential could not be removed")
            if args.action == "teardown":
                retire_owned_root(LAB_ROOT, owner_sid, args.confirm_root_id)
                print(
                    "Owned runtime archived; recorded ACLs restored and owner credential removed. "
                    "The existing local account is retained because original account provenance "
                    "was not recorded by the initial installation."
                )
        if args.action in {"stop", "reset"}:
            print(f"ACLAIS {args.action} completed.")
    except Exception:
        print("ACLAIS operator command failed closed. No unrelated process was terminated.")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
