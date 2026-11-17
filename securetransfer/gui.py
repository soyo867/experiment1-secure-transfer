"""Native file-transfer workstation with concurrent jobs and safe Tk updates."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import queue
import json
import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .client import SecureClient, TransferCancelled

BASE = Path(__file__).resolve().parent.parent
INK, ACCENT, MUTED, BG, WHITE, LINE = "#16334b", "#087f8c", "#64798b", "#edf2f6", "#ffffff", "#d6e1e8"


def size_label(value):
    if value >= 1024**3:
        return f"{value/1024**3:.2f} GiB"
    if value >= 1024**2:
        return f"{value/1024**2:.2f} MiB"
    if value >= 1024:
        return f"{value/1024:.1f} KiB"
    return f"{value} B"


@dataclass
class Job:
    id: int
    direction: str
    local: Path
    remote: str
    status: str = "排队中"
    done: int = 0
    total: int = 0
    rate: float = 0
    started: float = 0
    initial_offset: int | None = None
    cancel: threading.Event = field(default_factory=threading.Event)
    result: dict = field(default_factory=dict)
    error: str = ""
    reset: bool = False


class TransferApp:
    def __init__(self, root, profile=None):
        self.root = root
        root.title("SecureBridge — 实验 1B 安全文件传输")
        root.geometry(f"{min(1400,root.winfo_screenwidth()-70)}x{min(840,root.winfo_screenheight()-100)}")
        root.minsize(1080,700)
        root.configure(bg=BG)
        self.client = None
        self.connecting = False
        self.closing = False
        self.events = queue.SimpleQueue()
        self.executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="securebridge")
        self.jobs = {}
        self.next_job = 1
        self.local_files = {}
        self.remote_files = {}
        self.local_directory = BASE / "runtime" / "client_files"
        self.download_directory = BASE / "runtime" / "downloads"
        self.last_stats_update = 0
        self._theme()
        self._build(profile)
        self.refresh_local()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(80, self._pump)

    def _theme(self):
        self.root.option_add("*Font", ("Microsoft YaHei UI",10))
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame",background=BG)
        style.configure("TLabel",background=BG,foreground=INK)
        style.configure("TButton",background=WHITE,foreground=INK,padding=(11,6),font=("Microsoft YaHei UI",10))
        style.map("TButton",background=[("active","#dbeef0")])
        style.configure("Accent.TButton",background=ACCENT,foreground=WHITE)
        style.map("Accent.TButton",background=[("active","#076874"),("disabled","#a2bac1")])
        style.configure("Treeview",background=WHITE,fieldbackground=WHITE,foreground=INK,rowheight=27,font=("Microsoft YaHei UI",9))
        style.configure("Treeview.Heading",background="#e3ebf1",foreground=INK,font=("Microsoft YaHei UI",9,"bold"),padding=7)
        style.map("Treeview",background=[("selected","#155d78")],foreground=[("selected",WHITE)])
        style.configure("TEntry",padding=6,fieldbackground=WHITE)
        style.configure("TNotebook",background=BG,borderwidth=0)
        style.configure("TNotebook.Tab",padding=(14,7))

    def _build(self, profile):
        mast = tk.Frame(self.root,bg=INK,height=80)
        mast.pack(fill="x")
        mast.pack_propagate(False)
        title = tk.Frame(mast,bg=INK)
        title.pack(side="left",padx=22,pady=12)
        tk.Label(title,text="SecureBridge",font=("Segoe UI",23,"bold"),fg=WHITE,bg=INK).pack(anchor="w")
        tk.Label(title,text="安全文件传输  /  SOFTWARE & SYSTEM SECURITY  /  EXPERIMENT 1B",font=("Microsoft YaHei UI",9),fg="#a8cbd8",bg=INK).pack(anchor="w")
        self.connection_badge = tk.Label(mast,text="DISCONNECTED  ·  未连接",font=("Microsoft YaHei UI",11,"bold"),fg="#bee4e3",bg="#284a63",padx=14,pady=9)
        self.connection_badge.pack(side="right",padx=22)
        connection = ttk.Frame(self.root,padding=(18,12,18,6))
        connection.pack(fill="x")
        ttk.Label(connection,text="连接配置",font=("Microsoft YaHei UI",10,"bold")).pack(side="left",padx=(0,10))
        self.profile_var = tk.StringVar(value=str(profile or BASE/"runtime"/"alice.json"))
        self.profile_entry = ttk.Entry(connection,textvariable=self.profile_var)
        self.profile_entry.pack(side="left",fill="x",expand=True)
        self.profile_button = ttk.Button(connection,text="选择配置",command=self.choose_profile)
        self.profile_button.pack(side="left",padx=7)
        self.connect_button = ttk.Button(connection,text="连接服务器",style="Accent.TButton",command=self.connect_profile)
        self.connect_button.pack(side="left",padx=(0,7))
        self.disconnect_button = ttk.Button(connection,text="断开连接",command=self.disconnect,state="disabled")
        self.disconnect_button.pack(side="left")
        self.connection_info = tk.StringVar(value="双向证书认证 · 服务器主机名校验 · 持久连接池 · SHA-256 完整性校验")
        ttk.Label(self.root,textvariable=self.connection_info,padding=(20,0,20,10),foreground=MUTED,font=("Microsoft YaHei UI",9)).pack(fill="x")
        footer = tk.Frame(self.root,bg=WHITE)
        footer.pack(side="bottom",fill="x")
        self.status_var = tk.StringVar(value="选择连接配置并连接；数据仅在认证通过后传输")
        tk.Label(footer,textvariable=self.status_var,bg=WHITE,fg=MUTED,anchor="w",padx=18,pady=7,font=("Microsoft YaHei UI",9)).pack(side="left",fill="x",expand=True)
        self.channel_label = tk.Label(footer,text="连接 0  ·  心跳 0",bg=WHITE,fg=ACCENT,padx=18,font=("Microsoft YaHei UI",9))
        self.channel_label.pack(side="right")
        self.main = ttk.Panedwindow(self.root,orient="vertical")
        self.main.pack(fill="both",expand=True,padx=18,pady=(0,10))
        files = ttk.Frame(self.main)
        self.main.add(files,weight=3)
        files.columnconfigure(0,weight=1,uniform="files")
        files.columnconfigure(1,weight=1,uniform="files")
        files.rowconfigure(0,weight=1)
        left,right = ttk.Frame(files),ttk.Frame(files)
        left.grid(row=0,column=0,sticky="nsew",padx=(0,6))
        right.grid(row=0,column=1,sticky="nsew",padx=(6,0))
        for parent,label in [(left,"本地文件"),(right,"远端用户目录")]:
            tk.Label(parent,text=label,bg=WHITE,fg=INK,anchor="w",padx=12,pady=9,font=("Microsoft YaHei UI",12,"bold")).pack(fill="x")
        local_controls = ttk.Frame(left,padding=(0,7))
        local_controls.pack(fill="x")
        self.local_path_var = tk.StringVar(value=str(self.local_directory))
        ttk.Entry(local_controls,textvariable=self.local_path_var,state="readonly").pack(side="left",fill="x",expand=True)
        ttk.Button(local_controls,text="选目录",command=self.choose_local).pack(side="left",padx=(6,0))
        ttk.Button(local_controls,text="刷新",command=self.refresh_local).pack(side="left",padx=(6,0))
        remote_controls = ttk.Frame(right,padding=(0,7))
        remote_controls.pack(fill="x")
        self.remote_path_var = tk.StringVar(value="认证用户独立目录 · 尚未连接")
        ttk.Entry(remote_controls,textvariable=self.remote_path_var,state="readonly").pack(side="left",fill="x",expand=True)
        ttk.Button(remote_controls,text="刷新远端",command=self.refresh_remote).pack(side="left",padx=(6,0))
        local_tree_frame,remote_tree_frame = ttk.Frame(left),ttk.Frame(right)
        local_tree_frame.pack(fill="both",expand=True)
        remote_tree_frame.pack(fill="both",expand=True)
        self.local_tree = self._tree(local_tree_frame,("name","size","modified"),[("文件名",260),("大小",90),("修改时间",145)])
        self.remote_tree = self._tree(remote_tree_frame,("name","size","hash"),[("文件名",240),("大小",90),("SHA-256",170)])
        local_actions = ttk.Frame(left,padding=(0,7))
        local_actions.pack(fill="x")
        ttk.Button(local_actions,text="↑  上传选中文件",style="Accent.TButton",command=self.upload_selected).pack(side="left")
        ttk.Button(local_actions,text="添加文件上传…",command=self.choose_upload).pack(side="left",padx=6)
        remote_actions = ttk.Frame(right,padding=(0,7))
        remote_actions.pack(fill="x")
        ttk.Button(remote_actions,text="↓  下载选中文件",style="Accent.TButton",command=self.download_selected).pack(side="left")
        ttk.Button(remote_actions,text="下载目录…",command=self.choose_download_directory).pack(side="left",padx=6)
        self.download_label = ttk.Label(remote_actions,text="runtime/downloads",foreground=MUTED,font=("Microsoft YaHei UI",8))
        self.download_label.pack(side="left",fill="x",expand=True)
        jobs_frame = ttk.Frame(self.main)
        self.main.add(jobs_frame,weight=2)
        tabs = ttk.Notebook(jobs_frame)
        tabs.pack(fill="both",expand=True)
        self.jobs_tab,logs_tab = ttk.Frame(tabs),ttk.Frame(tabs)
        tabs.add(self.jobs_tab,text="传输任务")
        tabs.add(logs_tab,text="事件日志")
        self.tabs = tabs
        buttons = ttk.Frame(self.jobs_tab,padding=(0,7))
        buttons.pack(fill="x")
        ttk.Label(buttons,text="最多 4 个并行任务 · 完成后保持连接",foreground=MUTED).pack(side="left",padx=8)
        ttk.Button(buttons,text="暂停选中",command=self.pause_selected).pack(side="right",padx=(5,0))
        ttk.Button(buttons,text="继续 / 重试",command=self.resume_selected).pack(side="right",padx=(5,0))
        ttk.Button(buttons,text="从头重试",command=lambda:self.resume_selected(True)).pack(side="right")
        job_tree_frame = ttk.Frame(self.jobs_tab)
        job_tree_frame.pack(fill="both",expand=True)
        self.job_tree = self._tree(job_tree_frame,("id","direction","name","progress","bytes","rate","status"),
            [("ID",45),("方向",70),("文件",260),("进度",75),("已完成 / 总计",170),("速率",100),("状态",200)])
        for tag,color in [("完成","#e2f4ed"),("已暂停","#fff2dc"),("失败","#fce7e5"),("传输中","#e6f2fb")]:
            self.job_tree.tag_configure(tag,background=color)
        self.log_text = tk.Text(logs_tab,state="disabled",bg=WHITE,fg=INK,font=("Consolas",10),relief="flat",wrap="word",padx=12,pady=10)
        log_scroll = ttk.Scrollbar(logs_tab,command=self.log_text.yview)
        log_scroll.pack(side="right",fill="y")
        self.log_text.pack(fill="both",expand=True)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.root.after(200,lambda:self.main.sashpos(0,int(self.main.winfo_height()*0.54)))

    def _tree(self,parent,columns,headings):
        parent.rowconfigure(0,weight=1)
        parent.columnconfigure(0,weight=1)
        tree = ttk.Treeview(parent,columns=columns,show="headings",selectmode="extended")
        for key,(label,width) in zip(columns,headings):
            tree.heading(key,text=label)
            tree.column(key,width=width,minwidth=40,stretch=key in ("name","status","hash"))
        tree.grid(row=0,column=0,sticky="nsew")
        y = ttk.Scrollbar(parent,orient="vertical",command=tree.yview)
        y.grid(row=0,column=1,sticky="ns")
        x = ttk.Scrollbar(parent,orient="horizontal",command=tree.xview)
        x.grid(row=1,column=0,sticky="ew")
        tree.configure(yscrollcommand=y.set,xscrollcommand=x.set)
        return tree

    def log(self,text):
        stamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end",f"[{stamp}] {text}\n")
        if int(self.log_text.index("end-1c").split(".")[0])>1000:
            self.log_text.delete("1.0","200.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")
        self.status_var.set(text)

    def choose_profile(self):
        path = filedialog.askopenfilename(parent=self.root,title="选择客户端证书配置",initialdir=BASE/"runtime",filetypes=[("JSON configuration","*.json")])
        if path:
            self.profile_var.set(path)

    def connect_profile(self,profile=None):
        if self.connecting or (self.client and self.client.connected):
            return
        if profile is not None:
            self.profile_var.set(str(profile))
        profile = self.profile_var.get()
        self.connecting = True
        self.connect_button.configure(state="disabled")
        self.profile_button.configure(state="disabled")
        self.profile_entry.configure(state="disabled")
        self.connection_badge.configure(text="CONNECTING  ·  双向认证中")
        self.log("正在校验服务器证书与主机名，建立持久 TLS 连接池…")
        def work():
            client = None
            try:
                client = SecureClient(profile,pool_size=4).connect()
                if self.closing:
                    client.close()
                else:
                    self.events.put(("connected",client))
            except Exception as exc:
                if client:
                    client.close()
                self.events.put(("connect_error",str(exc)))
        self.executor.submit(work)

    def disconnect(self):
        client,self.client = self.client,None
        for job in self.jobs.values():
            if job.status in ("排队中","传输中"):
                job.cancel.set()
        if client:
            self.executor.submit(client.close)
        self._set_disconnected()
        self.log("已断开连接；未完成任务保留断点，重新连接后可继续")

    def _set_disconnected(self):
        self.connecting = False
        self.connect_button.configure(state="normal")
        self.profile_button.configure(state="normal")
        self.profile_entry.configure(state="normal")
        self.disconnect_button.configure(state="disabled")
        self.connection_badge.configure(text="DISCONNECTED  ·  未连接")
        self.remote_path_var.set("认证用户独立目录 · 尚未连接")
        self.connection_info.set("双向证书认证 · 服务器主机名校验 · 持久连接池 · SHA-256 完整性校验")
        self.channel_label.configure(text="连接 0  ·  心跳 0")
        self.remote_files = {}
        self.remote_tree.delete(*self.remote_tree.get_children())

    def choose_local(self):
        path = filedialog.askdirectory(parent=self.root,title="选择本地目录",initialdir=self.local_directory if self.local_directory.exists() else BASE)
        if path:
            self.local_directory = Path(path)
            self.refresh_local()

    def refresh_local(self):
        self.local_path_var.set(str(self.local_directory))
        self.local_tree.delete(*self.local_tree.get_children())
        self.local_files = {}
        if not self.local_directory.exists():
            return
        try:
            for i,path in enumerate(sorted(self.local_directory.iterdir(),key=lambda p:p.name.casefold())):
                if path.is_file() and not path.is_symlink():
                    stat = path.stat()
                    ident = str(i)
                    self.local_files[ident] = path
                    self.local_tree.insert("","end",iid=ident,values=(path.name,size_label(stat.st_size),datetime.fromtimestamp(stat.st_mtime).strftime("%m-%d %H:%M:%S")))
        except OSError as exc:
            self.log("本地目录读取失败："+str(exc))

    def refresh_remote(self):
        client = self.client
        if not client or not client.connected:
            self.log("请先连接服务器")
            return
        def work():
            try:
                self.events.put(("remote_files",(client,client.list_files())))
            except Exception as exc:
                self.events.put(("error","远端目录读取失败："+str(exc)))
        self.executor.submit(work)

    def _remote_rows(self,files):
        self.remote_tree.delete(*self.remote_tree.get_children())
        self.remote_files = {}
        for i,info in enumerate(files):
            ident = str(i)
            self.remote_files[ident] = info
            self.remote_tree.insert("","end",iid=ident,values=(info["name"],size_label(info["size"]),
                info["sha256"][:18]+"…" if info.get("sha256") else "下载前协商并校验"))
        self.log(f"远端目录已刷新：{len(files)} 个完整文件")

    def choose_upload(self):
        files = filedialog.askopenfilenames(parent=self.root,title="选择要上传的多个文件",initialdir=self.local_directory if self.local_directory.exists() else BASE)
        for path in files:
            self.queue_upload(path)

    def upload_selected(self):
        for ident in self.local_tree.selection():
            self.queue_upload(self.local_files[ident])

    def choose_download_directory(self):
        path = filedialog.askdirectory(parent=self.root,title="选择下载目录",initialdir=self.download_directory if self.download_directory.exists() else BASE)
        if path:
            self.download_directory = Path(path)
            self.download_label.configure(text=str(self.download_directory))

    def download_selected(self):
        for ident in self.remote_tree.selection():
            name = self.remote_files[ident]["name"]
            self.queue_download(name,self.download_directory/name)

    def queue_upload(self,local,remote=None,reset=False):
        local = Path(local)
        return self._queue_job("上传",local,remote or local.name,reset)

    def queue_download(self,remote,local=None,reset=False):
        return self._queue_job("下载",Path(local or self.download_directory/remote),remote,reset)

    def _queue_job(self,direction,local,remote,reset=False):
        client = self.client
        if not client or not client.connected:
            self.log("请先连接服务器")
            return None
        for job in self.jobs.values():
            if job.status in ("排队中","传输中") and ((direction == "下载" and job.direction == direction and job.local.resolve() == local.resolve()) or
                    (direction == "上传" and job.direction == direction and job.remote == remote)):
                self.log("该目标已有进行中的任务，请等待或暂停后重试")
                return None
        job = Job(self.next_job,direction,local,remote,reset=reset)
        self.next_job += 1
        self.jobs[job.id] = job
        self.job_tree.insert("","end",iid=str(job.id),values=(job.id,direction,remote,"0%","—","—",job.status))
        self.tabs.select(self.jobs_tab)
        self.job_tree.selection_set(str(job.id))
        self.executor.submit(self._run_job,job,client)
        return job

    def _run_job(self,job,client):
        self.events.put(("job_started",job.id))
        job.started = time.monotonic()
        def progress(done,total):
            self.events.put(("progress",(job.id,done,total,time.monotonic())))
        try:
            if job.direction == "上传":
                result = client.upload(job.local,job.remote,progress,job.cancel,job.reset)
            else:
                result = client.download(job.remote,job.local,progress,job.cancel,job.reset)
            self.events.put(("job_finished",(job.id,result)))
        except TransferCancelled as exc:
            self.events.put(("job_paused",(job.id,str(exc))))
        except Exception as exc:
            self.events.put(("job_error",(job.id,str(exc))))

    def pause_selected(self):
        for ident in self.job_tree.selection():
            job = self.jobs[int(ident)]
            if job.status in ("排队中","传输中"):
                job.cancel.set()
                self.log(f"任务 #{job.id} 已请求暂停，将在当前分块完成后保留断点")

    def resume_selected(self,reset=False):
        selected = list(self.job_tree.selection())
        if reset and selected and not messagebox.askyesno("重置暂存","从头重试会重置所选任务的部分传输数据。继续？",parent=self.root):
            return
        for ident in selected:
            old = self.jobs[int(ident)]
            if old.status in ("已暂停","失败"):
                self._queue_job(old.direction,old.local,old.remote,reset)

    def _render_job(self,job):
        fraction = 100 if job.status == "完成" else (job.done/job.total*100 if job.total else 0)
        text = job.status+(" · "+job.error if job.error else "")
        self.job_tree.item(str(job.id),values=(job.id,job.direction,job.remote,f"{fraction:.1f}%",
            f"{size_label(job.done)} / {size_label(job.total)}",size_label(int(job.rate))+"/s" if job.rate else "—",text),tags=(job.status,))

    def _pump(self):
        for _ in range(1000):
            try:
                kind,value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "connected":
                self.connecting = False
                if self.closing:
                    value.close()
                    continue
                self.client = value
                try:
                    profile_path = Path(self.profile_var.get()).resolve()
                    profile_data = json.loads(profile_path.read_text(encoding="utf-8"))
                    if profile_data.get("local_dir"):
                        self.local_directory = (profile_path.parent/profile_data["local_dir"]).resolve()
                        self.refresh_local()
                    if profile_data.get("download_dir"):
                        self.download_directory = (profile_path.parent/profile_data["download_dir"]).resolve()
                        self.download_label.configure(text=str(self.download_directory))
                except (OSError,ValueError):
                    pass
                hello = value.connection_info
                self.disconnect_button.configure(state="normal")
                self.connection_badge.configure(text=f"CONNECTED  ·  {value.user}")
                self.remote_path_var.set(f"/{value.user}/  ·  证书绑定的独立目录")
                rate = hello.get("bandwidth",hello.get("limits",{}).get("bandwidth",0))
                rate_text = size_label(rate)+"/s" if isinstance(rate,(int,float)) and rate else str(rate or "由服务端配置")
                self.connection_info.set(f"{hello.get('tls_version','TLS')} · {hello.get('cipher','')} · 用户 {value.user} · 带宽 {rate_text} · 4 条持久连接")
                self.log(f"双向 TLS 认证成功：{value.user}；连接 ID：{', '.join(str(x)[:12] for x in hello['session_ids'])}")
                self.refresh_remote()
            elif kind == "connect_error":
                self._set_disconnected()
                self.log("连接失败："+value)
            elif kind == "remote_files":
                client,files = value
                if client is self.client:
                    self._remote_rows(files)
            elif kind == "error":
                self.log(value)
            elif kind == "job_started":
                job = self.jobs[value]
                job.status = "传输中"
                self._render_job(job)
                self.log(f"任务 #{job.id} {job.direction}：{job.remote}")
            elif kind == "progress":
                ident,done,total,now = value
                job = self.jobs[ident]
                if job.initial_offset is None:
                    job.initial_offset = done
                job.done,job.total = done,total
                job.rate = max(0,done-job.initial_offset)/max(0.01,now-job.started)
                self._render_job(job)
            elif kind in ("job_finished","job_paused","job_error"):
                ident,detail = value
                job = self.jobs[ident]
                if kind == "job_finished":
                    job.status,job.result = "完成",detail
                    job.done = job.total = detail.get("size",job.total)
                    self.log(f"任务 #{ident} 完成；续传起点 {detail.get('resume_offset',0)} B；SHA-256 {detail.get('sha256','')[:20]}…")
                    if job.direction == "上传":
                        self.refresh_remote()
                    self.refresh_local()
                else:
                    job.status = "已暂停" if kind == "job_paused" else "失败"
                    job.error = detail
                    self.log(f"任务 #{ident} {job.status}：{detail}")
                self._render_job(job)
        if self.client and time.monotonic()-self.last_stats_update>1:
            stats = self.client.stats
            self.channel_label.configure(text=f"连接 {stats['connections']}  ·  心跳 {stats['heartbeat_count']}")
            if stats["connections"] < self.client.pool_size:
                self.connection_badge.configure(text="RECONNECT  ·  部分连接中断")
                self.status_var.set("连接中断：请断开并重新连接；文件任务的断点将保留")
            self.last_stats_update = time.monotonic()
        if not self.closing:
            self.root.after(80,self._pump)

    def close(self):
        if self.closing:
            return
        self.closing = True
        for job in self.jobs.values():
            job.cancel.set()
        if self.client:
            self.client.close()
        self.executor.shutdown(wait=False,cancel_futures=True)
        self.root.destroy()


def enable_dpi():
    if os.name == "nt":
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError,OSError):
            pass


def launch(profile=None):
    enable_dpi()
    root = tk.Tk()
    root.tk.call("tk","scaling",1.333333)
    app = TransferApp(root,profile)
    root.mainloop()


App = TransferApp
