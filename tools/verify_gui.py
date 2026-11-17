"""Exercise the real Tk client against a local mutual-TLS server.

Tests use isolated data and downloads; application callbacks perform the work.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import tkinter as tk

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0,str(BASE))
from securetransfer.client import file_sha256
from securetransfer.gui import TransferApp, enable_dpi
from securetransfer.server import Server


def verify(profile_path=None, config_path=None):
    profile_path = Path(profile_path or BASE/"runtime/alice.json").resolve()
    config_path = Path(config_path or BASE/"runtime/server.json").resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    for key in ("ca","cert","key"):
        config["tls"][key] = str((config_path.parent/config["tls"][key]).resolve())
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    for key in ("ca","cert","key"):
        profile[key] = str((profile_path.parent/profile[key]).resolve())
    with tempfile.TemporaryDirectory(prefix="securebridge-gui-") as directory:
        test_root = Path(directory)
        config["storage_root"] = str(test_root/"server_data")
        config["port"] = 0
        # Moderate rate makes cancellation deterministic, but does not alter production config.
        config["users"]["alice"]["bandwidth"] = 1024*1024
        (test_root/"client_files").mkdir()
        profile["local_dir"] = "client_files"
        profile["download_dir"] = "downloads"
        local = test_root/"client_files"
        (local/"first.bin").write_bytes(bytes(range(256))*4096)
        (local/"second.txt").write_text("SecureBridge GUI concurrent transfer.\n"*500,encoding="utf-8")
        (local/"resume.bin").write_bytes(os.urandom(3*1024*1024))
        server = Server(config)
        server.start()
        profile["port"] = server.address[1]
        chosen_profile = test_root/"alice.json"
        chosen_profile.write_text(json.dumps(profile),encoding="utf-8")
        enable_dpi()
        root = tk.Tk()
        root.tk.call("tk","scaling",1.333333)
        app = TransferApp(root,chosen_profile)
        root.withdraw()
        exceptions = []
        root.report_callback_exception = lambda *args:exceptions.append(str(args))
        def wait(predicate, seconds=20):
            deadline = time.monotonic()+seconds
            while time.monotonic()<deadline:
                root.update()
                if predicate():
                    return
                time.sleep(0.015)
            raise AssertionError("GUI condition timed out")
        checks = []
        try:
            app.connect_profile()
            wait(lambda:app.client is not None)
            assert app.client.user == "alice"
            assert str(app.disconnect_button.cget("state")) == "normal"
            assert app.client.stats["connections"] == 4
            sessions = app.client.stats["session_ids"]
            checks.append("mTLS GUI connect, identity, 4 persistent channels, button state")
            a = app.queue_upload(local/"first.bin")
            b = app.queue_upload(local/"second.txt")
            wait(lambda:a.status==b.status=="完成")
            wait(lambda:len(app.remote_files)==2)
            checks.append("concurrent uploads and remote directory refresh")
            c = app.queue_download("first.bin",test_root/"downloads/first.bin")
            c2 = app.queue_download("second.txt",test_root/"downloads/second.txt")
            d = app.queue_upload(local/"resume.bin")
            wait(lambda:d.done >= 65536)
            app.job_tree.selection_set(str(d.id))
            app.pause_selected()
            wait(lambda:d.status=="已暂停")
            wait(lambda:c.status==c2.status=="完成")
            assert 0 < d.done < d.total
            assert file_sha256(test_root/"downloads/first.bin") == file_sha256(local/"first.bin")
            assert file_sha256(test_root/"downloads/second.txt") == file_sha256(local/"second.txt")
            checks.append("simultaneous upload and two downloads, pause button, byte integrity")
            app.job_tree.selection_set(str(d.id))
            app.resume_selected()
            resumed = app.jobs[max(app.jobs)]
            wait(lambda:resumed.status=="完成")
            assert resumed.result["resume_offset"] > 0
            assert app.client.stats["session_ids"] == sessions
            checks.append("resume button, nonzero restart offset, same TCP sessions after jobs")
            app.disconnect()
            wait(lambda:app.client is None)
            assert str(app.connect_button.cget("state")) == "normal"
            checks.append("explicit disconnect restores controls")
            assert not exceptions, exceptions
            evidence = {"result":"PASS","checks":checks,"tk_callback_errors":exceptions,
                        "upload_count":3,"download_count":2,"resumed_bytes":resumed.result["resume_offset"],
                        "persistent_session_ids":sessions}
            output = BASE/"evidence/gui_verification.json"
            output.parent.mkdir(exist_ok=True)
            output.write_text(json.dumps(evidence,ensure_ascii=False,indent=2),encoding="utf-8")
            print(json.dumps(evidence,ensure_ascii=False,indent=2))
            return evidence
        finally:
            app.close()
            server.stop()


if __name__ == "__main__":
    verify()
