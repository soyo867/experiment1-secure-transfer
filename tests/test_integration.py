"""Independent end-to-end security/transport tests using actual local TLS sockets.

Every test has an isolated storage directory. Certificates are generated into a
temporary laboratory directory, never copied from users' credentials.
"""
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import tempfile
import threading
import time
import unittest

from tools.setup_demo import provision
from securetransfer.client import SecureClient, ClientError, TransferCancelled
from securetransfer.server import Server
from securetransfer.protocol import send_frame, recv_frame


def sha(data):
    return hashlib.sha256(data).hexdigest()


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="secureharbor-tests-")
        cls.base = Path(cls.temp.name)
        cls.runtime = provision(cls.base/"identities",port=0)
        cls.other = provision(cls.base/"untrusted-identities",port=0)
        cls.template = json.loads((cls.runtime/"server.json").read_text())
        cls.metrics = {}

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.work = self.base/self._testMethodName
        self.work.mkdir()
        self.config = copy.deepcopy(self.template)
        self.config["storage_root"] = str(self.work/"storage")
        for key in ("ca","cert","key"):
            self.config["tls"][key] = str(self.runtime/self.config["tls"][key])
        self.server = None
        self.clients = []
        self.raws = []

    def tearDown(self):
        for client in self.clients:
            client.close()
        for raw in self.raws:
            try:
                raw.close()
            except OSError:
                pass
        if self.server:
            self.server.stop()

    def start(self):
        self.server = Server(self.config,base_dir=self.runtime)
        self.port = self.server.start(port=0)
        return self.server

    def profile(self,user="alice",runtime=None):
        runtime = runtime or self.runtime
        profile = json.loads((runtime/f"{user}.json").read_text())
        profile.update(host="127.0.0.1",port=self.port)
        for key in ("ca","cert","key"):
            profile[key] = str(runtime/profile[key])
        return profile

    def client(self,user="alice",pool=1,heartbeat=1):
        client = SecureClient(self.profile(user),pool_size=pool,heartbeat_interval=heartbeat)
        self.clients.append(client)
        return client.connect()

    def raw_tls(self,user="alice",cert=True):
        profile = self.profile(user)
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,cafile=profile["ca"])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if cert:
            context.load_cert_chain(profile["cert"],profile["key"])
        raw = socket.create_connection(("127.0.0.1",self.port),timeout=3)
        self.raws.append(raw)
        stream = context.wrap_socket(raw,server_hostname="localhost")
        self.raws.append(stream)
        stream.settimeout(3)
        return stream

    def rpc(self,stream,op,rid=1,payload=b"",**fields):
        send_frame(stream,rid,{"op":op,**fields},payload)
        return recv_frame(stream)

    def local(self,name,data):
        path = self.work/name
        path.write_bytes(data)
        return path

    def test_binary_unicode_empty_roundtrip(self):
        self.start()
        client = self.client()
        data_by_name = {"empty.bin":b"","二进制文件.bin":bytes(range(256))*1025,"large.bin":bytes(range(256))*32768}
        for name,data in data_by_name.items():
            with self.subTest(name=name):
                result = client.upload(self.local(name,data))
                self.assertEqual(result["sha256"],sha(data))
                output = self.work/("download-"+name)
                client.download(name,output)
                self.assertEqual(output.read_bytes(),data)
        names = {row["name"] for row in client.list_files()}
        self.assertTrue(set(data_by_name)<=names)

    def test_connection_persists_across_operations_and_heartbeat(self):
        self.start()
        client = self.client(heartbeat=0.2)
        original = client.stats["session_ids"]
        client.list_files()
        client.upload(self.local("session.bin",b"persistent TCP"))
        client.download("session.bin",self.work/"copy.bin")
        client.list_files()
        time.sleep(1.3)
        self.assertEqual(client.stats["session_ids"],original)
        self.assertGreater(client.stats["heartbeat_count"],0)
        self.assertEqual(client.connections[0].sock.getsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE),1)
        self.metrics["persistent_session_ids_unchanged"] = True
        self.metrics["heartbeat_count"] = client.stats["heartbeat_count"]

    def test_multiuser_simultaneous_upload_download(self):
        self.start()
        alice,bob = self.client("alice",pool=3),self.client("bob",pool=3)
        data = bytes(range(256))*4096
        local = self.local("parallel.bin",data)
        alice.upload(local,"seed.bin")
        bob.upload(local,"seed.bin")
        barrier = threading.Barrier(4)
        def work(client,n,upload):
            barrier.wait(timeout=5)
            if upload:
                return client.upload(local,f"upload-{n}.bin")
            output = self.work/f"download-{n}.bin"
            result = client.download("seed.bin",output)
            self.assertEqual(output.read_bytes(),data)
            return result
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(work,alice,0,True),pool.submit(work,alice,1,False),
                       pool.submit(work,bob,2,True),pool.submit(work,bob,3,False)]
            results = [f.result(timeout=30) for f in futures]
        self.assertEqual(len(results),4)
        self.metrics["concurrent_transfers"] = 4

    def test_user_roots_are_isolated(self):
        self.start()
        alice,bob = self.client(),self.client("bob")
        alice.upload(self.local("private.bin",b"alice private data"))
        self.assertNotIn("private.bin",{r["name"] for r in bob.list_files()})
        with self.assertRaises((ClientError,OSError,EOFError)):
            bob.download("private.bin",self.work/"stolen.bin")
        self.assertFalse((self.work/"stolen.bin").exists())

    def test_upload_cancel_and_resume(self):
        self.start()
        client = self.client()
        data = bytes(range(256))*4096
        path = self.local("resume-upload.bin",data)
        cancel = threading.Event()
        def progress(done,total):
            if done>=131072:
                cancel.set()
        with self.assertRaises(TransferCancelled):
            client.upload(path,progress=progress,cancel=cancel)
        self.assertNotIn(path.name,{r["name"] for r in client.list_files()})
        result = client.upload(path)
        self.assertGreaterEqual(result["resume_offset"],131072)
        client.download(path.name,self.work/"resumed-copy.bin")
        self.assertEqual((self.work/"resumed-copy.bin").read_bytes(),data)
        self.metrics["upload_resume_offset"] = result["resume_offset"]

    def test_download_cancel_and_resume(self):
        self.start()
        client = self.client()
        data = bytes(range(256))*4096
        client.upload(self.local("resume-download.bin",data))
        cancel = threading.Event()
        output = self.work/"downloaded.bin"
        def progress(done,total):
            if done>=131072:
                cancel.set()
        with self.assertRaises(TransferCancelled):
            client.download("resume-download.bin",output,progress=progress,cancel=cancel)
        self.assertFalse(output.exists())
        result = client.download("resume-download.bin",output)
        self.assertGreaterEqual(result["resume_offset"],131072)
        self.assertEqual(output.read_bytes(),data)
        self.metrics["download_resume_offset"] = result["resume_offset"]

    def test_bad_hostname_rejected(self):
        self.start()
        profile = self.profile()
        profile["server_hostname"] = "attacker.invalid"
        client = SecureClient(profile,pool_size=1)
        self.clients.append(client)
        with self.assertRaises((ssl.SSLError,OSError,RuntimeError)):
            client.connect()

    def test_untrusted_server_ca_rejected(self):
        self.start()
        profile = self.profile()
        profile["ca"] = str(self.other/"certs/ca.pem")
        client = SecureClient(profile,pool_size=1)
        self.clients.append(client)
        with self.assertRaises((ssl.SSLError,OSError,RuntimeError)):
            client.connect()

    def test_untrusted_client_certificate_rejected(self):
        self.start()
        profile = self.profile()
        profile["cert"] = str(self.other/"certs/alice.pem")
        profile["key"] = str(self.other/"certs/alice.key")
        client = SecureClient(profile,pool_size=1)
        self.clients.append(client)
        with self.assertRaises((ClientError,OSError,EOFError)):
            client.connect()

    def test_missing_client_certificate_rejected(self):
        self.start()
        with self.assertRaises((ssl.SSLError,OSError,EOFError,RuntimeError)):
            raw = self.raw_tls(cert=False)
            response = self.rpc(raw,"HELLO")
            if response.metadata.get("ok"):
                self.fail("Unauthenticated client received HELLO success")
            raise RuntimeError("Unauthenticated HELLO rejected")

    def test_revoked_pinned_certificate_rejected(self):
        self.config["users"]["alice"]["certificate_sha256"] = "00"*32
        self.start()
        with self.assertRaises((ClientError,OSError,EOFError)):
            self.client()

    def test_path_traversal_and_windows_special_names_rejected(self):
        self.start()
        raw = self.raw_tls()
        self.assertTrue(self.rpc(raw,"HELLO").metadata["ok"])
        bad = ["../bob/secret","..\\bob\\secret","/etc/passwd","C:\\Windows\\win.ini","file:stream","CON","a/b","a\\b",".",".."]
        for i,name in enumerate(bad,2):
            with self.subTest(name=name):
                response = self.rpc(raw,"PUT_BEGIN",i,name=name,size=1,sha256=sha(b"x"))
                self.assertFalse(response.metadata["ok"])
        self.assertTrue(self.rpc(raw,"PING",100).metadata["ok"])

    def test_symlink_cannot_escape_user_root(self):
        self.start()
        secret = self.local("outside-secret.bin",b"not in user root")
        link = self.work/"storage"/"alice"/"escape.bin"
        try:
            link.symlink_to(secret)
        except OSError as exc:
            self.skipTest(f"OS does not grant symlink creation: {exc}")
        client = self.client()
        self.assertNotIn("escape.bin",{r["name"] for r in client.list_files()})
        with self.assertRaises((ClientError,OSError,EOFError)):
            client.download("escape.bin",self.work/"leaked.bin")

    def test_oversized_frame_rejected_without_body(self):
        self.start()
        raw = self.raw_tls()
        raw.sendall(struct.pack("!4sBBHIII",b"SFT1",1,1,0,1,0xFFFFFFFF,0xFFFFFFFF))
        before = time.monotonic()
        try:
            answer = raw.recv(256)
            self.assertEqual(answer,b"")
        except (ssl.SSLError,ConnectionResetError):
            pass
        self.assertLess(time.monotonic()-before,2.0)
        self.assertEqual(self.client().list_files(),[])

    def test_malformed_json_or_magic_closes_only_offending_connection(self):
        self.start()
        for magic,body in [(b"BAD!",b"{}"),(b"SFT1",b"{bad")]:
            raw = self.raw_tls()
            raw.sendall(struct.pack("!4sBBHIII",magic,1,1,0,1,len(body),0)+body)
            try:
                self.assertEqual(raw.recv(256),b"")
            except (ssl.SSLError,ConnectionResetError):
                pass
        self.assertEqual(self.client().list_files(),[])

    def test_declared_file_size_limit(self):
        self.config["limits"]["max_file_size"] = 65536
        self.start()
        client = self.client()
        with self.assertRaises((ClientError,OSError,EOFError)):
            client.upload(self.local("oversize.bin",b"x"*65537))
        self.assertEqual(client.list_files(),[])

    def test_user_quota_reserves_pending_uploads(self):
        self.config["users"]["alice"]["quota"] = 100000
        self.start()
        raw = self.raw_tls()
        self.rpc(raw,"HELLO")
        one = self.rpc(raw,"PUT_BEGIN",2,name="a.bin",size=60000,sha256=sha(b"a"*60000))
        two = self.rpc(raw,"PUT_BEGIN",3,name="b.bin",size=60000,sha256=sha(b"b"*60000))
        self.assertTrue(one.metadata["ok"])
        self.assertFalse(two.metadata["ok"])

    def test_existing_final_file_cannot_be_overwritten(self):
        self.start()
        client = self.client()
        first = self.local("same.bin",b"original")
        client.upload(first)
        first.write_bytes(b"replacement")
        with self.assertRaises((ClientError,OSError,EOFError)):
            client.upload(first)
        client.download("same.bin",self.work/"original-copy.bin")
        self.assertEqual((self.work/"original-copy.bin").read_bytes(),b"original")

    def test_tls_handshake_timeout_releases_slot(self):
        self.config["limits"].update(max_connections=1,max_connections_per_ip=1,handshake_timeout=1)
        self.start()
        idle = socket.create_connection(("127.0.0.1",self.port),timeout=3)
        self.raws.append(idle)
        time.sleep(1.6)
        self.assertEqual(self.client().list_files(),[])

    def test_slow_frame_deadline_closes_connection(self):
        self.config["limits"]["frame_timeout"] = 1
        self.start()
        raw = self.raw_tls()
        raw.sendall(b"S")
        before = time.monotonic()
        try:
            self.assertEqual(raw.recv(256),b"")
        except (ssl.SSLError,ConnectionResetError):
            pass
        self.assertLess(time.monotonic()-before,2.5)

    def test_user_bandwidth_enforced(self):
        self.config["users"]["alice"]["bandwidth"] = 131072
        self.config["users"]["bob"]["bandwidth"] = 1048576
        self.start()
        slow,fast = self.client(),self.client("bob")
        data = b"rate-test"*(524288//9)+b"x"*(524288%9)
        path = self.local("speed.bin",data)
        before = time.monotonic()
        slow.upload(path)
        slow_duration = time.monotonic()-before
        before = time.monotonic()
        fast.upload(path)
        fast_duration = time.monotonic()-before
        self.assertGreater(slow_duration,2.0)
        self.assertLess(fast_duration,slow_duration)
        self.metrics["bandwidth_test"] = {"bytes":len(data),"slow_bytes_per_second":131072,"fast_bytes_per_second":1048576,
                                         "slow_seconds":round(slow_duration,3),"fast_seconds":round(fast_duration,3)}

    def test_aggregate_bandwidth_shared_by_same_identity_connections(self):
        self.config["users"]["alice"]["bandwidth"] = 131072
        self.start()
        client = self.client(pool=2)
        path = self.local("aggregate.bin",b"a"*262144)
        barrier = threading.Barrier(2)
        def upload(name):
            barrier.wait(timeout=3)
            return client.upload(path,name)
        before = time.monotonic()
        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = [pool.submit(upload,"one.bin"),pool.submit(upload,"two.bin")]
            for job in jobs:
                job.result(timeout=15)
        elapsed = time.monotonic()-before
        self.assertGreater(elapsed,3.5,"Two connections must not double one user's rate")
        self.metrics["aggregate_bandwidth"] = {"connections":2,"total_bytes":524288,"rate":131072,"seconds":round(elapsed,3)}

    def test_wrong_digest_never_publishes_file(self):
        self.start()
        raw = self.raw_tls()
        self.rpc(raw,"HELLO")
        started = self.rpc(raw,"PUT_BEGIN",2,name="integrity.bin",size=4,sha256=sha(b"good"))
        self.assertTrue(started.metadata["ok"])
        transfer = started.metadata["transfer_id"]
        self.assertTrue(self.rpc(raw,"PUT_CHUNK",3,payload=b"evil",transfer_id=transfer,offset=0).metadata["ok"])
        finished = self.rpc(raw,"PUT_COMMIT",4,transfer_id=transfer)
        self.assertFalse(finished.metadata["ok"])
        self.assertFalse((self.work/"storage/alice/integrity.bin").exists())

    def test_wrong_chunk_offset_and_early_commit_rejected(self):
        self.start()
        raw = self.raw_tls()
        self.rpc(raw,"HELLO")
        begun = self.rpc(raw,"PUT_BEGIN",2,name="offset.bin",size=4,sha256=sha(b"data"))
        transfer = begun.metadata["transfer_id"]
        self.assertFalse(self.rpc(raw,"PUT_CHUNK",3,payload=b"data",transfer_id=transfer,offset=1).metadata["ok"])
        self.assertFalse(self.rpc(raw,"PUT_COMMIT",4,transfer_id=transfer).metadata["ok"])
        self.assertFalse((self.work/"storage/alice/offset.bin").exists())

    def test_transfer_id_is_bound_to_user(self):
        self.start()
        alice = self.raw_tls("alice")
        bob = self.raw_tls("bob")
        self.rpc(alice,"HELLO")
        self.rpc(bob,"HELLO")
        begun = self.rpc(alice,"PUT_BEGIN",2,name="bound.bin",size=4,sha256=sha(b"data"))
        transfer = begun.metadata["transfer_id"]
        self.assertFalse(self.rpc(bob,"PUT_CHUNK",2,payload=b"data",transfer_id=transfer,offset=0).metadata["ok"])
        self.assertFalse(self.rpc(bob,"CANCEL",3,transfer_id=transfer,discard=True).metadata["ok"])
        self.assertTrue(self.rpc(alice,"PUT_CHUNK",3,payload=b"data",transfer_id=transfer,offset=0).metadata["ok"])
        self.assertTrue(self.rpc(alice,"PUT_COMMIT",4,transfer_id=transfer).metadata["ok"])

    def test_cancel_retains_part_across_new_connection(self):
        self.start()
        first = self.client()
        path = self.local("reconnect.bin",b"abcde"*65536)
        event = threading.Event()
        def pause(done,total):
            if done>=65536:
                event.set()
        with self.assertRaises(TransferCancelled):
            first.upload(path,cancel=event,progress=pause)
        old_ids = first.stats["session_ids"]
        first.close()
        second = self.client()
        result = second.upload(path)
        self.assertGreater(result["resume_offset"],0)
        self.assertNotEqual(second.stats["session_ids"],old_ids)
        second.download(path.name,self.work/"reconnected-copy.bin")
        self.assertEqual((self.work/"reconnected-copy.bin").read_bytes(),path.read_bytes())

    def test_connection_limit_rejects_excess_without_breaking_active_client(self):
        self.config["limits"].update(max_connections=1,max_connections_per_ip=1)
        self.start()
        first = self.client()
        with self.assertRaises((OSError,ssl.SSLError,EOFError,RuntimeError)):
            self.client("bob")
        self.assertEqual(first.list_files(),[])
        self.metrics["connection_limit_enforced"] = True

    def test_request_rate_limit(self):
        self.config["limits"].update(requests_per_second=1,request_burst=3)
        self.start()
        raw = self.raw_tls()
        rejected = False
        for rid in range(1,12):
            try:
                reply = self.rpc(raw,"HELLO" if rid==1 else "PING",rid)
                if not reply.metadata.get("ok"):
                    rejected = True
                    break
            except (EOFError,OSError):
                rejected = True
                break
        self.assertTrue(rejected,"Burst must be rejected")
        self.metrics["request_rate_limit_enforced"] = True

    def test_sql_metacharacters_are_only_filename_data(self):
        self.start()
        client = self.client()
        name = "quote' OR '1'='1.bin"
        data = b"This string must remain inert data"
        source = self.local("sql-data.bin",data)
        result = client.upload(source,name)
        self.assertEqual(result["sha256"],sha(data))
        self.assertEqual({r["name"] for r in client.list_files()},{name})

    def test_both_directions_resume_after_server_restart(self):
        self.start()
        client = self.client()
        data = bytes(range(256))*4096
        source = self.local("restart.bin",data)
        client.upload(source,"download-seed.bin")
        cancelled = threading.Event()
        def pause(done,total):
            if done>=131072:
                cancelled.set()
        output = self.work/"restart-copy.bin"
        with self.assertRaises(TransferCancelled):
            client.download("download-seed.bin",output,progress=pause,cancel=cancelled)
        cancelled.clear()
        with self.assertRaises(TransferCancelled):
            client.upload(source,progress=pause,cancel=cancelled)
        client.close()
        self.server.stop()
        self.server = Server(self.config,base_dir=self.runtime)
        self.server.start(port=self.port)
        client = self.client()
        uploaded = client.upload(source)
        downloaded = client.download("download-seed.bin",output)
        self.assertEqual(uploaded["resume_offset"],131072)
        self.assertEqual(downloaded["resume_offset"],131072)
        self.assertEqual(output.read_bytes(),data)
        client.download("restart.bin",self.work/"server-restart-upload-copy.bin")
        self.assertEqual((self.work/"server-restart-upload-copy.bin").read_bytes(),data)
        self.metrics["daemon_restart_resume"] = {"upload_offset":uploaded["resume_offset"],"download_offset":downloaded["resume_offset"]}

    def test_corrupt_upload_partial_rejected_then_explicit_reset(self):
        self.start()
        client = self.client()
        data = b"protected-prefix"*16384
        source = self.local("prefix.bin",data)
        cancelled = threading.Event()
        def pause(done,total):
            if done>=65536:
                cancelled.set()
        with self.assertRaises(TransferCancelled):
            client.upload(source,progress=pause,cancel=cancelled)
        part = next((self.work/"storage/alice/.uploads").glob("*.part"))
        original_size = part.stat().st_size
        with part.open("r+b") as stream:
            stream.write(b"X")
        with self.assertRaises(ClientError):
            client.upload(source)
        self.assertEqual(part.stat().st_size,original_size)
        self.assertFalse((self.work/"storage/alice/prefix.bin").exists())
        result = client.upload(source,reset=True)
        self.assertEqual(result["resume_offset"],0)
        client.download("prefix.bin",self.work/"prefix-copy.bin")
        self.assertEqual((self.work/"prefix-copy.bin").read_bytes(),data)

    def test_corrupt_download_partial_never_published_then_reset(self):
        self.start()
        client = self.client()
        data = b"protected-download"*16384
        source = self.local("download-integrity.bin",data)
        client.upload(source)
        cancelled = threading.Event()
        def pause(done,total):
            if done>=65536:
                cancelled.set()
        output = self.work/"verified-copy.bin"
        with self.assertRaises(TransferCancelled):
            client.download(source.name,output,progress=pause,cancel=cancelled)
        with output.with_name(output.name+".sft-part").open("r+b") as stream:
            stream.write(b"X")
        with self.assertRaises(ClientError):
            client.download(source.name,output)
        self.assertFalse(output.exists())
        result = client.download(source.name,output,reset=True)
        self.assertEqual(result["resume_offset"],0)
        self.assertEqual(output.read_bytes(),data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
