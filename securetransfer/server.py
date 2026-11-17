"""Bounded, mutually authenticated TLS file server for Experiment 1B.

Final filenames are immutable. Uploads are written to private temporary files,
acknowledged by byte offset, verified with SHA-256, then committed atomically.
No SQL engine, command shell, or dynamically evaluated input is used.
"""
from collections import Counter
import argparse
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import socket
import ssl
import threading
import time
import uuid

from .protocol import CHUNK_SIZE, REQUEST, RESPONSE, ProtocolError, keep_alive, recv_frame, send_frame
from .security import (BandwidthLimiter, OperationError, RateLimiter, confined, digest,
                       file_name, integer, no_link, secure_open, sha256_file)

LOG = logging.getLogger("securetransfer.server")
DEFAULT_LIMITS = {"max_connections":32, "max_connections_per_ip":16, "max_connections_per_user":8,
                  "max_file_size":32*1024*1024, "handshake_timeout":5, "frame_timeout":30,
                  "requests_per_second":100, "request_burst":200, "max_partial_uploads":64,
                  "max_files_per_user":1000}


def _atomic_json(path, value):
    temp = path.with_name(path.name+".new")
    no_link(temp)
    with os.fdopen(secure_open(temp, os.O_WRONLY|os.O_CREAT|os.O_TRUNC),"w",encoding="utf-8") as f:
        json.dump(value, f, separators=(",",":"), ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp,path)


class UserStore:
    def __init__(self, name, config, storage, limits):
        self.name, self.config, self.limits = name, config, limits
        component = file_name(config.get("root",name))
        self.root = storage/component
        no_link(self.root)
        self.root.mkdir(mode=0o700,parents=False,exist_ok=True)
        self.partial = self.root/".uploads"
        no_link(self.partial)
        self.partial.mkdir(mode=0o700,exist_ok=True)
        self.quota = integer(config.get("quota",64*1024*1024),"quota",1)
        self.bandwidth = integer(config.get("bandwidth",1024*1024),"bandwidth",1)
        self.pin = digest(config.get("certificate_sha256",config.get("cert_sha256")))
        self.limiter = BandwidthLimiter(self.bandwidth)
        self.requests = RateLimiter(limits["requests_per_second"],limits["request_burst"])
        self.lock = threading.RLock()
        self.leases = {}  # transfer_id -> connection_id; never trusted from client.
        self.active_names = {}  # immutable filename -> transfer_id
        self.records = {}
        # Resume persisted temporary state across daemon restart.
        for meta in self.partial.glob("*.json"):
            no_link(meta)
            if meta.stat().st_size > 16384:
                raise ValueError("Oversized persisted upload metadata")
            value = json.loads(meta.read_text(encoding="utf-8"))
            ident = meta.stem
            if not self.valid_id(ident):
                raise ValueError("Invalid persisted transfer ID")
            file_name(value["name"])
            integer(value["size"],"size",0,limits["max_file_size"])
            digest(value["sha256"])
            final = confined(self.root,value["name"])
            # A crash may occur after atomic publication but before journal cleanup.
            # Only a fully verified final file authorizes discarding this journal.
            if (final.is_file() and final.stat().st_size == value["size"] and
                    hmac.compare_digest(sha256_file(final),value["sha256"])):
                self._remove(ident)
                continue
            path = self.partial/(ident+".part")
            no_link(path)
            if not path.is_file() or path.stat().st_size > value["size"]:
                raise ValueError("Persisted upload metadata/data mismatch")
            name_key = os.path.normcase(value["name"])
            if name_key in self.active_names:
                raise ValueError("Duplicate persisted destination")
            self.records[ident] = value
            self.active_names[name_key] = ident
        # Creation writes data before the journal; cancellation removes the journal
        # first. Either interrupted operation can leave an unreferenced private file.
        for path in self.partial.iterdir():
            suffix = next((s for s in (".json.new",".part") if path.name.endswith(s)),None)
            if suffix is None:
                continue
            ident = path.name[:-len(suffix)]
            if self.valid_id(ident) and (suffix == ".json.new" or ident not in self.records):
                no_link(path)
                path.unlink()
        if len(self.records)>limits["max_partial_uploads"]:
            raise ValueError("Persisted upload count exceeds limit")
        if self.usage()>self.quota:
            raise ValueError("Configured quota smaller than existing/reserved data")

    @staticmethod
    def valid_id(ident):
        return isinstance(ident,str) and len(ident)==32 and all(c in "0123456789abcdef" for c in ident)

    def usage(self):
        no_link(self.root)
        total = sum(x["size"] for x in self.records.values())
        for path in self.root.iterdir():
            if path.name.startswith("."):
                continue
            no_link(path)
            if path.is_file():
                total += path.stat().st_size
        return total

    def listing(self):
        with self.lock:
            files = []
            no_link(self.root)
            for path in sorted(self.root.iterdir()):
                if path.name.startswith("."):
                    continue
                try:
                    no_link(path)
                except OperationError:
                    # Do not expose unsafe local entries; direct access still fails closed.
                    continue
                if path.is_file():
                    files.append({"name":path.name,"size":path.stat().st_size})
            # Metadata stays bounded even if the user's final directory is full.
            return files

    def list_page(self, cursor=0, limit=64):
        cursor = integer(cursor,"cursor",0,self.limits["max_files_per_user"])
        limit = integer(limit,"limit",1,64)
        files = self.listing()
        page = files[cursor:cursor+limit]
        next_cursor = cursor+len(page) if cursor+len(page)<len(files) else None
        return {"files":page,"next_cursor":next_cursor,"total":len(files)}

    def info(self, name):
        with self.lock:
            path = confined(self.root,name)
            if not path.is_file():
                raise OperationError("NOT_FOUND","File does not exist")
            size = path.stat().st_size
            if size > self.limits["max_file_size"]:
                raise OperationError("TOO_LARGE","Stored file exceeds configured file limit")
            return {"name":name,"size":size,"sha256":sha256_file(path)}

    def begin(self, metadata, connection):
        name = file_name(metadata.get("name"))
        size = integer(metadata.get("size"),"size",0,self.limits["max_file_size"])
        sha = digest(metadata.get("sha256"))
        reset = metadata.get("reset",False)
        if type(reset) is not bool:
            raise OperationError("INVALID_ARGUMENT","reset must be boolean")
        with self.lock:
            final = confined(self.root,name)
            no_link(self.partial)
            if final.exists():
                if final.is_file() and final.stat().st_size == size and hmac.compare_digest(sha256_file(final),sha):
                    return {"transfer_id":"","offset":size,"prefix_sha256":sha,"complete":True,"name":name,"size":size,"sha256":sha}
                raise OperationError("EXISTS","Destination exists; immutable files cannot be overwritten")
            name_key = os.path.normcase(name)
            ident = self.active_names.get(name_key)
            if ident:
                value = self.records[ident]
                if ident in self.leases and self.leases[ident] != connection:
                    raise OperationError("BUSY","Another connection owns this upload")
                if reset:
                    self._remove(ident)
                    ident = None
                elif value["size"] != size or not hmac.compare_digest(value["sha256"],sha):
                    raise OperationError("RESUME_MISMATCH","Different unfinished upload uses this destination; reset explicitly")
            if ident is None:
                if len(self.records)>=self.limits["max_partial_uploads"]:
                    raise OperationError("QUOTA","Too many unfinished uploads")
                if len(self.listing())+len(self.records)>=self.limits["max_files_per_user"]:
                    raise OperationError("QUOTA","Too many files")
                if self.usage()+size>self.quota:
                    raise OperationError("QUOTA","Per-user disk quota exceeded (includes full-size reservations)")
                ident = uuid.uuid4().hex
                value = {"name":name,"size":size,"sha256":sha}
                part = self.partial/(ident+".part")
                fd = secure_open(part,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
                os.close(fd)
                _atomic_json(self.partial/(ident+".json"),value)
                self.records[ident] = value
                self.active_names[name_key] = ident
            self.leases[ident] = connection
            part = self.partial/(ident+".part")
            no_link(part)
            offset = part.stat().st_size
            return {"transfer_id":ident,"offset":offset,"prefix_sha256":sha256_file(part),"complete":False}

    def _owned(self, ident, connection):
        if not self.valid_id(ident) or ident not in self.records or self.leases.get(ident) != connection:
            raise OperationError("NOT_OWNER","Transfer ID is not owned by this connection/user")
        no_link(self.root)
        no_link(self.partial)
        path = self.partial/(ident+".part")
        no_link(path)
        return self.records[ident],path

    def chunk(self, ident, offset, payload, connection):
        with self.lock:
            value,path = self._owned(ident,connection)
            offset = integer(offset,"offset",0,value["size"])
            if not payload:
                raise OperationError("INVALID_ARGUMENT","PUT_CHUNK payload cannot be empty")
            if offset != path.stat().st_size:
                raise OperationError("OFFSET","Upload offset does not equal durable partial length")
            if offset+len(payload)>value["size"]:
                raise OperationError("TOO_LARGE","Chunk exceeds declared size")
            with os.fdopen(secure_open(path,os.O_WRONLY|os.O_APPEND),"ab") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            return {"offset":offset+len(payload)}

    def commit(self, ident, connection):
        with self.lock:
            value,path = self._owned(ident,connection)
            if path.stat().st_size != value["size"]:
                raise OperationError("INCOMPLETE","Received length differs from declared size")
            actual = sha256_file(path)
            if not hmac.compare_digest(actual,value["sha256"]):
                raise OperationError("HASH_MISMATCH","Whole-file SHA-256 verification failed")
            final = confined(self.root,value["name"])
            if final.exists():
                raise OperationError("EXISTS","Destination already exists")
            # os.link is atomic and fails if the final name already exists, on NTFS and POSIX.
            # Files are on one filesystem (both below the same user root).
            try:
                os.link(path,final,follow_symlinks=False)
            except FileExistsError:
                raise OperationError("EXISTS","Destination already exists") from None
            result = dict(value)
            self._remove(ident)
            return result

    def _remove(self, ident):
        value = self.records.get(ident)
        paths = [self.partial/(ident+suffix) for suffix in (".json",".json.new",".part")]
        for path in paths:
            no_link(path)
        for path in paths:
            path.unlink(missing_ok=True)
        if value:
            self.active_names.pop(os.path.normcase(value["name"]),None)
        self.records.pop(ident,None)
        self.leases.pop(ident,None)

    def cancel(self, ident, connection, discard=False):
        if type(discard) is not bool:
            raise OperationError("INVALID_ARGUMENT","discard must be boolean")
        with self.lock:
            self._owned(ident,connection)
            if discard:
                self._remove(ident)
            else:
                self.leases.pop(ident,None)
            return {"retained":not discard}

    def read(self, name, offset, length):
        with self.lock:
            path = confined(self.root,name)
            if not path.is_file():
                raise OperationError("NOT_FOUND","File does not exist")
            size = path.stat().st_size
            if size > self.limits["max_file_size"]:
                raise OperationError("TOO_LARGE","Stored file exceeds configured file limit")
            offset = integer(offset,"offset",0,size)
            length = integer(length,"length",1,CHUNK_SIZE)
            with os.fdopen(secure_open(path,os.O_RDONLY),"rb") as f:
                f.seek(offset)
                data = f.read(min(length,size-offset))
            return {"offset":offset,"next_offset":offset+len(data),"eof":offset+len(data)==size},data

    def release(self, connection):
        with self.lock:
            for ident in [key for key,owner in self.leases.items() if owner==connection]:
                self.leases.pop(ident,None)


class Server:
    def __init__(self, config, base_dir=None):
        if isinstance(config,(str,Path)):
            path = Path(config).resolve()
            self.base = path.parent
            config = json.loads(path.read_text(encoding="utf-8"))
        else:
            self.base = Path(base_dir or ".").resolve()
        self.config = config
        self.limits = DEFAULT_LIMITS | config.get("limits",{})
        for key,value in self.limits.items():
            if not isinstance(value,(int,float)) or isinstance(value,bool) or value<=0:
                raise ValueError(f"Invalid positive resource limit: {key}")
        for key in ("max_connections","max_connections_per_ip","max_connections_per_user","max_file_size","max_partial_uploads","max_files_per_user"):
            integer(self.limits[key],key,1)
        self.stop_event = threading.Event()
        self.lock = threading.RLock()
        self.sockets,self.threads = set(),set()
        self.ip_counts,self.user_counts = Counter(),Counter()
        self.metrics = Counter()
        self.listener,self.accept_thread,self.address = None,None,None
        storage = self._path(config.get("storage_root","data"))
        no_link(storage)
        storage.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.users = {name:UserStore(name,settings,storage,self.limits) for name,settings in config["users"].items()}
        if not self.users:
            raise ValueError("At least one pinned user is required")
        roots = [user.root.resolve() for user in self.users.values()]
        if len(set(roots)) != len(roots):
            raise ValueError("Users must have distinct storage roots")
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.options |= ssl.OP_NO_COMPRESSION
        # AEAD forward-secret TLS 1.2 ciphers; TLS 1.3 uses OpenSSL's suites.
        self.context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
        tls = config["tls"]
        self.context.load_cert_chain(str(self._path(tls["cert"])),str(self._path(tls["key"])))
        self.context.load_verify_locations(cafile=str(self._path(tls["ca"])))
        # Disable resumption tickets so each new connection rechecks the certificate.
        self.context.options |= ssl.OP_NO_TICKET

    def _path(self,path):
        path = Path(path)
        return path if path.is_absolute() else self.base/path

    def start(self, host=None, port=None):
        if self.listener or self.threads or (self.accept_thread and self.accept_thread.is_alive()):
            raise RuntimeError("Server already started or still shutting down")
        self.stop_event.clear()
        listener = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            option = socket.SO_EXCLUSIVEADDRUSE if os.name == "nt" else socket.SO_REUSEADDR
            listener.setsockopt(socket.SOL_SOCKET,option,1)
            listener.bind((host if host is not None else self.config.get("host","127.0.0.1"),
                           port if port is not None else self.config.get("port",18443)))
            listener.listen(min(self.limits["max_connections"],128))
            listener.settimeout(0.2)
        except BaseException:
            listener.close()
            raise
        self.listener = listener
        self.address = listener.getsockname()
        self.accept_thread = threading.Thread(target=self._accept,name="sft-accept",daemon=True)
        self.accept_thread.start()
        return self.address[1]

    def _accept(self):
        while not self.stop_event.is_set():
            try:
                raw,address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            ip = address[0]
            with self.lock:
                if len(self.sockets)>=self.limits["max_connections"] or self.ip_counts[ip]>=self.limits["max_connections_per_ip"]:
                    self.metrics["capacity_rejected"] += 1
                    raw.close()
                    continue
                self.sockets.add(raw)
                self.ip_counts[ip] += 1
                self.metrics["accepted"] += 1
                thread = threading.Thread(target=self._connection,args=(raw,ip),name="sft-session",daemon=True)
                self.threads.add(thread)
            thread.start()

    def _connection(self,raw,ip):
        conn,user = raw,None
        session_id = uuid.uuid4().hex
        registered = False
        try:
            raw.settimeout(self.limits["handshake_timeout"])
            keep_alive(raw)
            conn = self.context.wrap_socket(raw,server_side=True,do_handshake_on_connect=False)
            with self.lock:
                self.sockets.discard(raw)
                # wrap_socket detaches raw's descriptor. stop() might have seen
                # only that detached raw socket while wrapping was in progress.
                if self.stop_event.is_set():
                    raise ConnectionAbortedError("Server is stopping")
                self.sockets.add(conn)
            conn.do_handshake()
            cert = conn.getpeercert()
            common_names = [value for row in cert.get("subject",()) for name,value in row if name=="commonName"]
            if len(common_names)!=1 or common_names[0] not in self.users:
                raise OperationError("AUTH","Client identity is not authorized")
            user = self.users[common_names[0]]
            cert_hash = hashlib.sha256(conn.getpeercert(binary_form=True)).hexdigest()
            if not hmac.compare_digest(cert_hash,user.pin):
                raise OperationError("AUTH","Client certificate was revoked or is not allowlisted")
            with self.lock:
                if self.user_counts[user.name]>=self.limits["max_connections_per_user"]:
                    raise OperationError("CAPACITY","Per-user connection limit exceeded")
                self.user_counts[user.name] += 1
                registered = True
                self.metrics["authenticated"] += 1
                self.metrics["active"] += 1
            conn.settimeout(self.limits["frame_timeout"])
            seen_hello = False
            while not self.stop_event.is_set():
                frame = recv_frame(conn,timeout=self.limits["frame_timeout"])
                if frame.frame_type != REQUEST:
                    raise ProtocolError("Server expects request frames")
                with self.lock:
                    self.metrics["requests"] += 1
                if not user.requests.allow():
                    send_frame(conn,frame.request_id,{"ok":False,"code":"RATE_LIMIT","error":"Per-user request rate exceeded"},frame_type=RESPONSE)
                    with self.lock:
                        self.metrics["rate_rejected"] += 1
                    break
                op = frame.metadata.get("op")
                if not seen_hello and op != "HELLO":
                    raise ProtocolError("First request must be HELLO")
                try:
                    response,payload = self._dispatch(user,session_id,frame)
                    send_frame(conn,frame.request_id,{"ok":True,**response},payload,frame_type=RESPONSE)
                    if op == "HELLO":
                        seen_hello = True
                    if op == "BYE":
                        break
                except OperationError as exc:
                    send_frame(conn,frame.request_id,{"ok":False,"code":exc.code,"error":str(exc)},frame_type=RESPONSE)
                except (FileNotFoundError,FileExistsError,PermissionError) as exc:
                    send_frame(conn,frame.request_id,{"ok":False,"code":"FILESYSTEM","error":type(exc).__name__},frame_type=RESPONSE)
        except (OSError,EOFError,ProtocolError,OperationError,ValueError) as exc:
            with self.lock:
                self.metrics["closed_or_rejected"] += 1
                if not registered:
                    self.metrics["authentication_or_handshake_rejected"] += 1
            LOG.debug("Session ended: %s",type(exc).__name__)
        except Exception:
            LOG.exception("Unexpected server session error")
            with self.lock:
                self.metrics["internal_errors"] += 1
        finally:
            if user:
                user.release(session_id)
            with self.lock:
                self.sockets.discard(raw)
                self.sockets.discard(conn)
                self.ip_counts[ip] -= 1
                if not self.ip_counts[ip]:
                    del self.ip_counts[ip]
                if registered:
                    self.user_counts[user.name] -= 1
                    self.metrics["active"] -= 1
                self.threads.discard(threading.current_thread())
            try:
                conn.close()
            except OSError:
                pass

    def _dispatch(self,user,connection,frame):
        m,data = frame.metadata,frame.payload
        op = m.get("op")
        if not isinstance(op,str):
            raise OperationError("INVALID_ARGUMENT","op must be a string")
        if op != "PUT_CHUNK" and data:
            raise OperationError("INVALID_ARGUMENT","Only PUT_CHUNK accepts request payload")
        if op == "HELLO":
            return {"user":user.name,"role":user.config.get("role","standard"),"connection_id":connection,
                    "session_id":connection,"chunk_size":CHUNK_SIZE,"keepalive_seconds":min(5,self.limits["frame_timeout"]/3),
                    "bandwidth":user.bandwidth,"quota":user.quota,"limits":self.limits},b""
        if op == "PING":
            return {"pong":True,"connection_id":connection},b""
        if op == "LIST":
            return user.list_page(m.get("cursor",0),m.get("limit",64)),b""
        if op == "PUT_BEGIN":
            return user.begin(m,connection),b""
        if op == "PUT_CHUNK":
            user.limiter.consume(len(data),self.stop_event)
            result = user.chunk(m.get("transfer_id"),m.get("offset"),data,connection)
            with self.lock:
                self.metrics["uploaded_bytes"] += len(data)
            return result,b""
        if op == "PUT_COMMIT":
            return user.commit(m.get("transfer_id"),connection),b""
        if op == "GET_BEGIN":
            return user.info(m.get("name")),b""
        if op == "GET_CHUNK":
            result,data = user.read(m.get("name"),m.get("offset"),m.get("length",CHUNK_SIZE))
            user.limiter.consume(len(data),self.stop_event)
            with self.lock:
                self.metrics["downloaded_bytes"] += len(data)
            return result,data
        if op == "CANCEL":
            keep = m.get("keep_partial",True)
            if type(keep) is not bool:
                raise OperationError("INVALID_ARGUMENT","keep_partial must be boolean")
            return user.cancel(m.get("transfer_id"),connection,m.get("discard",not keep)),b""
        if op == "BYE":
            return {"closed":True},b""
        raise OperationError("UNKNOWN_OPERATION","Unsupported operation")

    def stop(self):
        self.stop_event.set()
        if self.listener:
            self.listener.close()
        if self.accept_thread:
            self.accept_thread.join(timeout=2)
        with self.lock:
            sockets,threads = list(self.sockets),list(self.threads)
        for conn in sockets:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        deadline = time.monotonic()+2
        for thread in threads:
            thread.join(timeout=max(0,deadline-time.monotonic()))
        self.listener = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self,*_):
        self.stop()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config",default="runtime/server.json")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s")
    server = Server(args.config)
    server.start()
    print(f"SFT/1 TLS server listening on {server.address[0]}:{server.address[1]}",flush=True)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
