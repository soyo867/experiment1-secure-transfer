"""Focused adversarial unit tests for the protocol and storage state machine."""
from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import Mock

from securetransfer.protocol import (HEADER, MAGIC, VERSION, REQUEST, ProtocolError,
                                     recv_frame, send_frame)
from securetransfer.security import OperationError, file_name, RateLimiter
from securetransfer.server import DEFAULT_LIMITS, Server, UserStore


class FragmentedSocket:
    def __init__(self,data,step=1):
        self.stream=io.BytesIO(data)
        self.step=step
        self.timeout=None
    def recv(self,count): return self.stream.read(min(count,self.step))
    def gettimeout(self): return self.timeout
    def settimeout(self,value): self.timeout=value


class FramingTests(unittest.TestCase):
    def frame(self,raw=b'{"op":"PING"}',payload=b'',**override):
        fields=dict(magic=MAGIC,version=VERSION,kind=REQUEST,flags=0,request_id=1,json_length=len(raw),payload_length=len(payload))
        fields.update(override)
        return HEADER.pack(*fields.values())+raw+payload

    def test_one_byte_tcp_segmentation(self):
        frame=recv_frame(FragmentedSocket(self.frame(payload=b'payload')))
        self.assertEqual(frame.metadata,{"op":"PING"})
        self.assertEqual(frame.payload,b'payload')

    def test_two_coalesced_frames(self):
        sock=FragmentedSocket(self.frame()+self.frame(request_id=2),step=10000)
        self.assertEqual(recv_frame(sock).request_id,1)
        self.assertEqual(recv_frame(sock).request_id,2)

    def test_oversized_lengths_rejected_before_body(self):
        for kwargs in ({"json_length":0xFFFFFFFF},{"payload_length":65537},{"json_length":1}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ProtocolError):
                recv_frame(FragmentedSocket(self.frame(**kwargs)[:20]))

    def test_invalid_header_fields(self):
        for kwargs in ({"magic":b"FAIL"},{"version":2},{"kind":0},{"flags":1},{"request_id":0}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ProtocolError):
                recv_frame(FragmentedSocket(self.frame(**kwargs)))

    def test_invalid_json(self):
        for raw in (b'{"op":"PING","op":"BYE"}',b'[]',b'{"op":NaN}',b'\xff\xff',b'{{'):
            with self.subTest(raw=raw),self.assertRaises(ProtocolError):
                recv_frame(FragmentedSocket(self.frame(raw)))

    def test_truncated_stream(self):
        for end in (0,1,19,20,21):
            with self.subTest(end=end),self.assertRaises(EOFError):
                recv_frame(FragmentedSocket(self.frame()[:end]))

    def test_send_receive_real_socketpair(self):
        first,second=socket.socketpair()
        try:
            send_frame(first,99,{"op":"PUT_CHUNK","说明":"中文"},b"\x00\xffdata")
            frame=recv_frame(second)
            self.assertEqual(frame.request_id,99)
            self.assertEqual(frame.metadata["说明"],"中文")
            self.assertEqual(frame.payload,b"\x00\xffdata")
        finally:
            first.close(); second.close()

    def test_absolute_frame_timeout(self):
        first,second=socket.socketpair()
        try:
            first.sendall(b'S')
            with self.assertRaises(TimeoutError):
                recv_frame(second,timeout=0.03)
        finally:
            first.close(); second.close()


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config={"root":"alice","quota":200,"bandwidth":1000000,"certificate_sha256":"0"*64}
        self.store=UserStore("alice",self.config,Path(self.temp.name),DEFAULT_LIMITS)

    def begin(self,name,data,**extra):
        return self.store.begin({"name":name,"size":len(data),"sha256":hashlib.sha256(data).hexdigest(),**extra},"connection1")

    def test_rejected_filenames(self):
        for name in ('..','../outside','sub/file','sub\\file','C:stream','file:secret','.uploads','CON.txt','nul','a.','a ',"bad\x00name",'a..b','a\u202ename'):
            with self.subTest(name=name),self.assertRaises(OperationError):
                file_name(name)
        self.assertEqual(file_name("实验数据.txt"),"实验数据.txt")

    def test_quota_reserves_announced_size(self):
        self.begin("one.bin",b'a'*150)
        with self.assertRaises(OperationError) as caught:
            self.begin("two.bin",b'b'*100)
        self.assertEqual(caught.exception.code,'QUOTA')

    def test_upload_lease_is_connection_bound(self):
        info=self.begin("one.bin",b'abc')
        with self.assertRaises(OperationError):
            self.store.chunk(info['transfer_id'],0,b'abc',"connection2")
        with self.assertRaises(OperationError):
            self.store.begin({"name":"one.bin","size":3,"sha256":hashlib.sha256(b'abc').hexdigest()},"connection2")

    def test_disconnect_resume_prefix(self):
        info=self.begin("one.bin",b'abcdef')
        self.store.chunk(info['transfer_id'],0,b'abc',"connection1")
        self.store.release("connection1")
        next_info=self.store.begin({"name":"one.bin","size":6,"sha256":hashlib.sha256(b'abcdef').hexdigest()},"connection2")
        self.assertEqual(next_info['offset'],3)
        self.assertEqual(next_info['prefix_sha256'],hashlib.sha256(b'abc').hexdigest())
        self.store.chunk(next_info['transfer_id'],3,b'def',"connection2")
        result=self.store.commit(next_info['transfer_id'],"connection2")
        self.assertEqual(result['sha256'],hashlib.sha256(b'abcdef').hexdigest())
        self.assertEqual((self.store.root/'one.bin').read_bytes(),b'abcdef')

    def test_restart_resume(self):
        info=self.begin("one.bin",b'abcdef')
        self.store.chunk(info['transfer_id'],0,b'abc',"connection1")
        new=UserStore("alice",self.config,Path(self.temp.name),DEFAULT_LIMITS)
        restored=new.begin({"name":"one.bin","size":6,"sha256":hashlib.sha256(b'abcdef').hexdigest()},"connection2")
        self.assertEqual(restored['offset'],3)

    def test_restart_after_publish_before_partial_cleanup(self):
        data=b'x'*150
        info=self.begin("one.bin",data)
        ident=info['transfer_id']
        self.store.chunk(ident,0,data,"connection1")
        os.link(self.store.partial/(ident+'.part'),self.store.root/'one.bin')
        restored=UserStore("alice",self.config,Path(self.temp.name),DEFAULT_LIMITS)
        self.assertEqual(restored.usage(),len(data))
        self.assertFalse(restored.records)
        self.assertFalse(list(restored.partial.iterdir()))
        self.assertEqual((restored.root/'one.bin').read_bytes(),data)

    def test_restart_after_publish_and_partial_unlink(self):
        data=b'abc'
        info=self.begin("one.bin",data)
        ident=info['transfer_id']
        self.store.chunk(ident,0,data,"connection1")
        part=self.store.partial/(ident+'.part')
        os.link(part,self.store.root/'one.bin')
        part.unlink()
        restored=UserStore("alice",self.config,Path(self.temp.name),DEFAULT_LIMITS)
        self.assertEqual(restored.usage(),len(data))
        self.assertFalse(restored.records)
        self.assertFalse(list(restored.partial.iterdir()))

    def test_restart_cleans_unjournaled_temporary_files(self):
        ident='a'*32
        (self.store.partial/(ident+'.part')).write_bytes(b'cancelled bytes')
        (self.store.partial/(ident+'.json.new')).write_text('{}')
        restored=UserStore("alice",self.config,Path(self.temp.name),DEFAULT_LIMITS)
        self.assertEqual(restored.usage(),0)
        self.assertFalse(list(restored.partial.iterdir()))

    @unittest.skipUnless(os.name=='nt','Windows uses case-insensitive destination names')
    def test_case_variants_share_one_upload_lease(self):
        self.begin('Report.txt',b'abc')
        with self.assertRaises(OperationError) as caught:
            self.store.begin({'name':'REPORT.TXT','size':3,'sha256':hashlib.sha256(b'abc').hexdigest()},'connection2')
        self.assertEqual(caught.exception.code,'BUSY')

    def test_atomic_hash_mismatch_does_not_publish(self):
        info=self.begin("one.bin",b'abc')
        self.store.chunk(info['transfer_id'],0,b'bad',"connection1")
        with self.assertRaises(OperationError) as caught:
            self.store.commit(info['transfer_id'],"connection1")
        self.assertEqual(caught.exception.code,'HASH_MISMATCH')
        self.assertFalse((self.store.root/'one.bin').exists())

    def test_empty_file_commit(self):
        info=self.begin("empty.bin",b'')
        self.store.commit(info['transfer_id'],"connection1")
        self.assertEqual((self.store.root/'empty.bin').stat().st_size,0)

    def test_final_is_immutable(self):
        info=self.begin("one.bin",b'abc')
        self.store.chunk(info['transfer_id'],0,b'abc',"connection1")
        self.store.commit(info['transfer_id'],"connection1")
        with self.assertRaises(OperationError):
            self.begin("one.bin",b'other',reset=True)
        self.assertTrue(self.begin("one.bin",b'abc')['complete'])

    def test_incorrect_offset_and_declared_size(self):
        info=self.begin("one.bin",b'abc')
        with self.assertRaises(OperationError):
            self.store.chunk(info['transfer_id'],1,b'a',"connection1")
        with self.assertRaises(OperationError):
            self.store.chunk(info['transfer_id'],0,b'abcd',"connection1")

    def test_cancel_discard_releases_quota(self):
        info=self.begin("one.bin",b'x'*200)
        self.store.cancel(info['transfer_id'],"connection1",discard=True)
        self.assertEqual(self.store.usage(),0)
        self.begin("two.bin",b'x'*200)

    def test_full_width_directory_pages_fit_protocol(self):
        for index in range(130):
            (self.store.root/(str(index).zfill(3)+'x'*173+'.bin')).touch()
        names,cursor=[],0
        while True:
            page=self.store.list_page(cursor,64)
            sink=Mock()
            send_frame(sink,1,{'ok':True,**page})
            self.assertLessEqual(len(sink.sendall.call_args.args[0]),20+16384)
            names.extend(entry['name'] for entry in page['files'])
            cursor=page['next_cursor']
            if cursor is None:
                break
        self.assertEqual(len(names),130)
        self.assertEqual(len(set(names)),130)


class LifecycleTests(unittest.TestCase):
    def test_stop_during_socket_wrap_does_not_leave_untracked_tls_socket(self):
        raw,peer=socket.socketpair()
        self.addCleanup(raw.close)
        self.addCleanup(peer.close)
        wrapping,release=threading.Event(),threading.Event()
        wrapped=socket.socket(fileno=raw.detach())
        self.addCleanup(wrapped.close)
        tls=Mock()
        tls.close.side_effect=wrapped.close
        tls.do_handshake.side_effect=AssertionError('Handshake must not start after stop')

        def wrap(*args,**kwargs):
            wrapping.set()
            if not release.wait(2):
                raise TimeoutError('Test did not release wrap')
            return tls

        server=Server.__new__(Server)
        server.context=Mock(wrap_socket=Mock(side_effect=wrap))
        server.stop_event=threading.Event()
        server.lock=threading.RLock()
        server.limits=dict(DEFAULT_LIMITS)
        server.sockets={raw}
        server.ip_counts=Counter({'127.0.0.1':1})
        server.user_counts=Counter()
        server.metrics=Counter()
        server.listener=server.accept_thread=None
        # Keep the underlying raw socket valid until wrapping actually detaches it.
        # The mock's raw transport models the descriptor shell left by SSL wrapping.
        raw_transport=Mock()
        server.sockets={raw_transport}
        worker=threading.Thread(target=server._connection,args=(raw_transport,'127.0.0.1'))
        server.threads={worker}
        worker.start()
        self.assertTrue(wrapping.wait(1))
        stopper=threading.Thread(target=server.stop)
        stopper.start()
        self.assertTrue(server.stop_event.wait(1))
        release.set()
        stopper.join(2)
        worker.join(2)
        self.assertFalse(stopper.is_alive())
        self.assertFalse(worker.is_alive())
        self.assertEqual(wrapped.fileno(),-1)
        tls.do_handshake.assert_not_called()
        self.assertFalse(server.threads)
        self.assertFalse(server.sockets)
        self.assertFalse(server.ip_counts)
        self.assertEqual(server.metrics['internal_errors'],0)


if __name__=='__main__':
    unittest.main(verbosity=2)
