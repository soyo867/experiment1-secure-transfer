"""Verified mutual TLS client with a persistent, heartbeat-maintained RPC pool.

Each channel has exactly one reader at a time. File jobs borrow a channel but
return it without closing it, allowing simultaneous transfers and reuse across
multiple operations. Connections close only on explicit disconnect or failure.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import queue
import socket
import ssl
import threading
import time

from .protocol import recv_frame, send_frame, keep_alive

CHUNK_SIZE = 65536
_DESTINATIONS = set()
_DESTINATION_LOCK = threading.Lock()


class ClientError(RuntimeError):
    pass


class RemoteError(ClientError):
    def __init__(self, message, code="REMOTE_ERROR"):
        super().__init__(message)
        self.code = code


class TransferCancelled(ClientError):
    pass


def file_sha256(path, limit=None):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        remaining = limit
        while remaining is None or remaining > 0:
            data = stream.read(min(1024 * 1024, remaining) if remaining is not None else 1024 * 1024)
            if not data:
                break
            digest.update(data)
            if remaining is not None:
                remaining -= len(data)
    if remaining not in (None, 0):
        raise ClientError("文件长度小于待校验的断点偏移")
    return digest.hexdigest()


def safe_name(name):
    if not isinstance(name, str) or not name or name in (".", "..") or len(name.encode("utf-8")) > 240:
        raise ClientError("远端文件名为空或过长")
    if any(c in name for c in '/\\\x00:<>"|?*') or any(ord(c) < 32 for c in name) or name.endswith((" ", ".")):
        raise ClientError("远端只接受当前用户目录内的普通文件名")
    return name


def load_profile(profile):
    if isinstance(profile, (str, Path)):
        path = Path(profile).resolve()
        result = json.loads(path.read_text(encoding="utf-8"))
        directory = path.parent
    else:
        result = dict(profile)
        directory = Path.cwd()
    for key in ("ca", "cert", "key"):
        if key not in result:
            raise ClientError(f"连接配置缺少 {key}")
        value = Path(result[key])
        result[key] = str(value if value.is_absolute() else directory / value)
    result.setdefault("host", "127.0.0.1")
    result.setdefault("port", 9443)
    result.setdefault("server_hostname", "localhost")
    if not isinstance(result["port"], int) or not 1 <= result["port"] <= 65535:
        raise ClientError("端口应为 1–65535 的整数")
    result.setdefault("timeout", 30.0)
    if not isinstance(result["timeout"],(int,float)) or not 0 < result["timeout"] <= 120:
        raise ClientError("连接超时应在 0 到 120 秒之间")
    return result


class Channel:
    def __init__(self, profile, context):
        self.profile, self.context = profile, context
        self.sock = None
        self.hello = {}
        self.request_id = 0
        self.last_used = 0.0
        self._lock = threading.Lock()
        self.broken = False
        self._connect()

    def _connect(self):
        raw = socket.create_connection((self.profile["host"], self.profile["port"]), timeout=float(self.profile["timeout"]))
        try:
            keep_alive(raw)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.sock = self.context.wrap_socket(raw, server_hostname=self.profile["server_hostname"])
            self.sock.settimeout(float(self.profile["timeout"]))
            self.hello = self.rpc("HELLO")[0]
            self.hello["tls_version"] = self.sock.version()
            self.hello["cipher"] = self.sock.cipher()[0]
        except BaseException:
            raw.close()
            if self.sock:
                self.sock.close()
            self.sock = None
            raise

    def rpc(self, op, payload=b"", **fields):
        with self._lock:
            return self._rpc_locked(op, payload, **fields)

    def _rpc_locked(self, op, payload=b"", **fields):
        if self.sock is None or self.broken:
            raise ClientError("连接已断开；请重新连接后续传")
        self.request_id = (self.request_id % 0xFFFFFFFF) + 1
        try:
            send_frame(self.sock, self.request_id, {"op": op, **fields}, payload)
            frame = recv_frame(self.sock,timeout=min(float(self.profile["timeout"]),self.sock.gettimeout() or float(self.profile["timeout"])))
            if frame.frame_type != 2 or frame.request_id != self.request_id:
                raise ClientError("服务器响应的类型或请求编号不匹配")
            self.last_used = time.monotonic()
            metadata = frame.metadata
            if metadata.get("ok") is not True:
                raise RemoteError(str(metadata.get("error", "服务端拒绝请求")), str(metadata.get("code", "REMOTE_ERROR")))
            return metadata, frame.payload
        except RemoteError:
            raise
        except BaseException:
            self.broken = True
            self.abort()
            raise

    def heartbeat(self):
        if not self._lock.acquire(blocking=False):
            return False
        try:
            if self.broken or self.sock is None:
                return False
            self._rpc_locked("PING")
            return True
        finally:
            self._lock.release()

    def abort(self):
        sock, self.sock = self.sock, None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def close(self):
        # Never wait for a large file operation while the user closes the app.
        if self._lock.acquire(blocking=False):
            try:
                if self.sock is not None and not self.broken:
                    try:
                        self.sock.settimeout(1)
                        self._rpc_locked("BYE")
                    except (OSError, ClientError, ValueError, EOFError):
                        pass
            finally:
                self.abort()
                self._lock.release()
        else:
            self.abort()


class SecureClient:
    def __init__(self, profile, pool_size=4, heartbeat_interval=None):
        self.profile = load_profile(profile)
        if not isinstance(pool_size, int) or not 1 <= pool_size <= 8:
            raise ValueError("pool_size must be 1..8")
        self.pool_size = pool_size
        self.heartbeat_interval = heartbeat_interval
        if heartbeat_interval is not None and (not isinstance(heartbeat_interval,(int,float)) or not 0 < heartbeat_interval <= 60):
            raise ValueError("heartbeat_interval must be >0 and <=60 seconds")
        self.connections = []
        self._available = queue.Queue()
        self._stop = threading.Event()
        self._heartbeat = None
        self.heartbeat_count = 0
        self.connected = False
        self._lifecycle = threading.Lock()

    @property
    def hello(self):
        return self.connections[0].hello if self.connections else {}

    @property
    def user(self):
        return self.hello.get("user", "")

    @property
    def stats(self):
        return {"heartbeat_count": self.heartbeat_count,
                "connections": sum(c.sock is not None and not c.broken for c in self.connections),
                "session_ids": [c.hello.get("session_id", c.hello.get("connection_id")) for c in self.connections]}

    @property
    def connection_info(self):
        return {**self.hello, **self.stats}

    def connect(self):
        with self._lifecycle:
            if self.connected:
                return self
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.profile["ca"])
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_cert_chain(self.profile["cert"], self.profile["key"])
            self._stop.clear()
            self.connections = []
            self._available = queue.Queue()
            try:
                for _ in range(self.pool_size):
                    channel = Channel(self.profile, context)
                    self.connections.append(channel)
                    self._available.put(channel)
            except BaseException:
                for channel in self.connections:
                    channel.abort()
                self.connections = []
                raise
            self.connected = True
            if self.heartbeat_interval is None:
                advertised = self.hello.get("keepalive_seconds", 10)
                self.heartbeat_interval = max(1.0, min(10.0, float(advertised) / 2))
            self._heartbeat = threading.Thread(target=self._heartbeat_loop, name="secure-transfer-keepalive", daemon=True)
            self._heartbeat.start()
            return self

    def _heartbeat_loop(self):
        while not self._stop.wait(float(self.heartbeat_interval)):
            for channel in self.connections:
                if self._stop.is_set():
                    break
                if time.monotonic() - channel.last_used < float(self.heartbeat_interval):
                    continue
                try:
                    if channel.heartbeat():
                        self.heartbeat_count += 1
                except Exception:
                    # Preserve file partials; explicit reconnect makes failure visible.
                    channel.broken = True

    @contextmanager
    def _borrow(self, cancel=None):
        if not self.connected or self._stop.is_set():
            raise ClientError("请先连接服务器")
        while True:
            self._check_cancel(cancel)
            try:
                channel = self._available.get(timeout=0.1)
                break
            except queue.Empty:
                continue
        try:
            if channel.broken or channel.sock is None:
                raise ClientError("连接中断；请断开后重新连接以恢复传输")
            yield channel
        finally:
            if not self._stop.is_set():
                self._available.put(channel)

    def _check_cancel(self, cancel):
        if self._stop.is_set() or (cancel is not None and cancel.is_set()):
            raise TransferCancelled("传输已暂停，已传输的分块将用于续传")

    def list_files(self):
        with self._borrow() as channel:
            files, cursor = [],0
            for _ in range(1024):
                metadata, _ = channel.rpc("LIST",cursor=cursor,limit=64)
                files.extend(metadata["files"])
                next_cursor = metadata.get("next_cursor")
                if next_cursor is None:
                    return files
                if not isinstance(next_cursor,int) or next_cursor <= cursor:
                    raise ClientError("目录分页偏移无效")
                cursor = next_cursor
            raise ClientError("目录条目超过客户端显示上限")

    def upload(self, local, remote=None, progress=None, cancel=None, reset=False):
        local = Path(local)
        if not local.is_file() or local.is_symlink():
            raise ClientError("上传源必须为普通文件")
        remote = safe_name(remote or local.name)
        before = local.stat()
        total, digest = before.st_size, file_sha256(local)
        self._check_cancel(cancel)
        with self._borrow(cancel) as channel:
            begun, _ = channel.rpc("PUT_BEGIN", name=remote, size=total, sha256=digest, reset=bool(reset))
            offset, transfer_id = begun["offset"], begun["transfer_id"]
            if not isinstance(offset, int) or not 0 <= offset <= total:
                raise ClientError("服务端返回无效的续传偏移")
            if begun.get("complete"):
                if progress:
                    progress(total, total)
                return {**begun, "name": remote, "size": total, "sha256": digest, "resume_offset": total}
            try:
                if file_sha256(local, offset) != begun["prefix_sha256"]:
                    raise ClientError("续传前缀 SHA-256 不一致；请明确选择“从头重试”以重置远端暂存")
                resumed = offset
                if progress:
                    progress(offset, total)
                with local.open("rb") as stream:
                    stream.seek(offset)
                    while offset < total:
                        self._check_cancel(cancel)
                        chunk = stream.read(min(CHUNK_SIZE, total - offset))
                        if not chunk:
                            raise ClientError("上传源文件在传输过程中被截短")
                        metadata, _ = channel.rpc("PUT_CHUNK", chunk, transfer_id=transfer_id, offset=offset)
                        expected = offset + len(chunk)
                        if metadata.get("offset") != expected:
                            raise ClientError("上传确认偏移不匹配")
                        offset = expected
                        if progress:
                            progress(offset, total)
                after = local.stat()
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise ClientError("上传期间源文件被修改，已保留暂存但未提交")
                self._check_cancel(cancel)
                result, _ = channel.rpc("PUT_COMMIT", transfer_id=transfer_id)
                if result.get("sha256") != digest or result.get("size") != total:
                    raise ClientError("服务器提交结果与本地 SHA-256 或长度不一致")
                return {**result, "resume_offset": resumed}
            except BaseException:
                try:
                    if channel.sock is not None and not channel.broken:
                        channel.rpc("CANCEL", transfer_id=transfer_id, discard=False)
                except Exception:
                    pass
                raise

    def download(self, remote, local, progress=None, cancel=None, reset=False):
        destination = str(Path(local).resolve()).casefold() if os.name == "nt" else str(Path(local).resolve())
        with _DESTINATION_LOCK:
            if destination in _DESTINATIONS:
                raise ClientError("同一下载目标已有进行中的任务")
            _DESTINATIONS.add(destination)
        try:
            return self._download(remote,local,progress,cancel,reset)
        finally:
            with _DESTINATION_LOCK:
                _DESTINATIONS.discard(destination)

    def _download(self, remote, local, progress=None, cancel=None, reset=False):
        remote = safe_name(remote)
        local = Path(local)
        local.parent.mkdir(parents=True, exist_ok=True)
        part = local.with_name(local.name + ".sft-part")
        sidecar = local.with_name(local.name + ".sft-part.json")
        for path in (local, part, sidecar):
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise ClientError("下载目标或暂存路径不是普通文件")
        with self._borrow(cancel) as channel:
            info, _ = channel.rpc("GET_BEGIN", name=remote)
            total, digest = info["size"], info["sha256"]
            if not isinstance(total, int) or total < 0 or not isinstance(digest, str) or len(digest) != 64:
                raise ClientError("服务器返回的文件信息无效")
            identity = {"host": self.profile["host"], "port": self.profile["port"], "user": self.user,
                        "name": remote, "size": total, "sha256": digest}
            if local.exists():
                if local.stat().st_size == total and file_sha256(local) == digest:
                    if progress:
                        progress(total, total)
                    return {**info, "resume_offset": total, "local": str(local)}
                raise ClientError("目标文件已经存在且内容不同；请选择新的下载文件名")
            if part.exists() and not reset:
                try:
                    previous = json.loads(sidecar.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    raise ClientError("已有暂存文件缺少可信续传信息，请选择“从头重试”") from exc
                if previous != identity or part.stat().st_size > total:
                    raise ClientError("下载暂存与远端文件不一致，请选择“从头重试”")
            elif sidecar.exists() and not part.exists():
                # An interrupted rename may leave metadata, which can safely be overwritten.
                pass
            if reset or not part.exists():
                with part.open("wb"):
                    pass
                sidecar.write_text(json.dumps(identity, ensure_ascii=False), encoding="utf-8")
            offset = part.stat().st_size
            resumed = offset
            if progress:
                progress(offset, total)
            with part.open("ab") as stream:
                while offset < total:
                    self._check_cancel(cancel)
                    metadata, data = channel.rpc("GET_CHUNK", name=remote, offset=offset,
                                                 length=min(CHUNK_SIZE, total-offset))
                    if not data or len(data) > min(CHUNK_SIZE, total-offset) or metadata.get("offset") != offset or metadata.get("next_offset") != offset + len(data):
                        raise ClientError("下载块长度或偏移不匹配")
                    stream.write(data)
                    stream.flush()
                    offset += len(data)
                    if progress:
                        progress(offset, total)
                os.fsync(stream.fileno())
            self._check_cancel(cancel)
            if file_sha256(part) != digest:
                raise ClientError("下载 SHA-256 校验失败；目标文件未发布，请选择“从头重试”")
            # Never replace an existing destination. Another job may have created it.
            try:
                os.link(part, local)
            except FileExistsError:
                raise ClientError("目标已由另一任务创建，暂存仍保留") from None
            except OSError as exc:
                raise ClientError("无法原子发布下载文件；目标目录需支持硬链接，暂存已保留") from exc
            part.unlink()
            sidecar.unlink(missing_ok=True)
            return {**info, "resume_offset": resumed, "local": str(local)}

    def close(self):
        with self._lifecycle:
            self._stop.set()
            self.connected = False
            for channel in self.connections:
                channel.close()
        if self._heartbeat is not None and self._heartbeat is not threading.current_thread():
            self._heartbeat.join(timeout=2)

    def __enter__(self):
        return self.connect()

    def __exit__(self, *args):
        self.close()
