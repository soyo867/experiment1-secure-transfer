"""Record actual build, local deployment, tests and the real Tk/TLS application."""
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk

BASE=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(BASE))
from securetransfer.gui import TransferApp, enable_dpi
from securetransfer.server import Server


def main():
    import imageio_ffmpeg
    evidence=BASE/'evidence'; evidence.mkdir(exist_ok=True)
    runtime=BASE/'runtime'/('video_'+time.strftime('%Y%m%d_%H%M%S'))
    enable_dpi()
    root=tk.Tk(); root.tk.call('tk','scaling',1.333333)
    app=TransferApp(root,runtime/'alice.json')
    root.title('SecureBridge Experiment 1B Demo'); root.geometry('1420x880+25+20')
    root.deiconify();root.lift();root.attributes('-topmost',True)
    caption=tk.Label(root,text='01  构建、部署与测试全过程',font=('Microsoft YaHei UI',13,'bold'),bg='#d9eeed',fg='#153148',pady=10)
    caption.pack(side='top',fill='x',before=root.winfo_children()[0])
    cover=tk.Frame(root,bg='#edf2f6'); cover.place(x=0,y=44,relwidth=1,relheight=.95)
    tk.Label(cover,text='SecureBridge  /  实验 1B',font=('Segoe UI',25,'bold'),bg='#edf2f6',fg='#153148').pack(anchor='w',padx=30,pady=(22,12))
    tk.Label(cover,text='真实执行：依赖检查 → Python 编译检查 → 证书与目录部署 → 单元及 TLS 集成测试',font=('Microsoft YaHei UI',12),bg='#edf2f6',fg='#536b80').pack(anchor='w',padx=30,pady=10)
    output=tk.Text(cover,bg='#132c40',fg='#d7f2eb',font=('Consolas',11),wrap='word',padx=18,pady=15)
    output.pack(fill='both',expand=True,padx=30,pady=15)
    events=queue.Queue(); errors=[]; result={}; server=None; encoder=None
    log=(evidence/'video_ffmpeg.log').open('w',encoding='utf-8')
    root.report_callback_exception=lambda *args:errors.append(str(args))
    def emit(text): events.put(text)
    def pipeline():
        try:
            commands=[
                [sys.executable,'-m','pip','show','cryptography'],
                [sys.executable,'-m','compileall','-q','securetransfer','run.py'],
                [sys.executable,'tools/setup_demo.py','--out',str(runtime),'--port','0'],
                [sys.executable,'-m','unittest','discover','-s','tests','-p','test_server_unit.py','-v'],
                [sys.executable,'tools/verify_integration.py'],
            ]
            for command in commands:
                emit('\n> '+subprocess.list2cmdline(command)+'\n')
                proc=subprocess.Popen(command,cwd=BASE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace',creationflags=subprocess.CREATE_NO_WINDOW,env={**os.environ,'PYTHONIOENCODING':'utf-8'})
                for line in proc.stdout: emit(line)
                if proc.wait()!=0: raise RuntimeError('Build/test command failed')
            result['build_passed']=True
            emit('\nBUILD / DEPLOY / TEST: PASS\n即将打开真实 GUI 并连接本地 mTLS 服务端。\n')
        except Exception as exc:
            errors.append(str(exc));emit('\nERROR: '+str(exc)+'\n')
        finally: result['pipeline_finished']=True
    def pump():
        while not events.empty():
            output.insert('end',events.get());output.see('end')
        if root.winfo_exists():root.after(100,pump)
    pump()
    def banner(text): caption.configure(text=text)
    def shot(name):
        from PIL import ImageGrab
        root.update_idletasks()
        ImageGrab.grab(bbox=(root.winfo_rootx(),root.winfo_rooty(),root.winfo_rootx()+root.winfo_width(),root.winfo_rooty()+root.winfo_height())).save(evidence/name)
    def after(seconds,fn):root.after(int(seconds*1000),fn)
    def require(condition,message):
        if not condition: raise RuntimeError(message)
    def run_gui():
        nonlocal server
        if not result.get('pipeline_finished'):
            after(1,run_gui);return
        require(result.get('build_passed'),'Build/deployment/test stage failed')
        config=json.loads((runtime/'server.json').read_text())
        config['users']['alice']['bandwidth']=262144
        server=Server(config,base_dir=runtime);port=server.start(port=0)
        for user in ('alice','bob'):
            profile=runtime/(user+'.json');data=json.loads(profile.read_text());data['port']=port;profile.write_text(json.dumps(data),encoding='utf-8')
        (runtime/'client_files/dataset.bin').write_bytes(bytes(range(256))*8192)
        (runtime/'client_files/parallel.bin').write_bytes(bytes(range(256))*2048)
        shot('build_deploy.png');cover.destroy()
        banner('02  双向证书认证；建立 4 条持久 TLS 通道')
        app.connect_profile()
        after(7,start_uploads)
    def start_uploads():
        require(app.client and app.client.connected,'GUI connection failed')
        result['session_ids_before']=app.client.connection_info['session_ids']
        banner('03  多文件并发上传；同一用户共享 256 KiB/s 带宽')
        result['upload_job']=app.queue_upload(runtime/'client_files/dataset.bin').id
        app.queue_upload(runtime/'client_files/parallel.bin')
        app.queue_upload(runtime/'client_files/empty.bin')
        after(3,pause_upload)
    def pause_upload():
        app.job_tree.selection_set(str(result['upload_job']));app.pause_selected()
        banner('04  暂停上传，服务端保留已接收偏移与完整性元数据')
        after(5,resume_upload)
    def resume_upload():
        require(app.jobs[result['upload_job']].status=='已暂停','Upload pause was not observed')
        app.job_tree.selection_set(str(result['upload_job']));app.resume_selected()
        banner('05  从确认偏移继续上传；同时下载 welcome.txt')
        app.queue_download('welcome.txt',runtime/'downloads/alice/welcome.txt')
        shot('gui_transfer.png')
        after(17,start_downloads)
    def start_downloads():
        done=[j for j in app.jobs.values() if j.status=='完成' and j.direction=='上传']
        require(any(j.remote=='dataset.bin' for j in done),'Resumed upload not complete')
        result['upload_resume_offset']=next(j.result['resume_offset'] for j in done if j.remote=='dataset.bin')
        banner('06  同时下载两个文件；上传完成后仍复用同一组连接')
        result['download_job']=app.queue_download('dataset.bin',runtime/'downloads/alice/dataset.bin').id
        app.queue_download('parallel.bin',runtime/'downloads/alice/parallel.bin')
        after(3,pause_download)
    def pause_download():
        app.job_tree.selection_set(str(result['download_job']));app.pause_selected()
        banner('07  暂停下载；本地 .sft-part 保存断点')
        after(5,resume_download)
    def resume_download():
        require(app.jobs[result['download_job']].status=='已暂停','Download pause was not observed')
        app.job_tree.selection_set(str(result['download_job']));app.resume_selected()
        banner('08  下载续传完成后校验 SHA-256，再发布最终文件')
        after(17,completed)
    def completed():
        completed_jobs=[j for j in app.jobs.values() if j.status=='完成']
        down=next(j for j in completed_jobs if j.direction=='下载' and j.remote=='dataset.bin')
        result['download_resume_offset']=down.result['resume_offset']
        result['session_ids_after']=app.client.connection_info['session_ids'];result['client_stats']=app.client.stats
        result['hashes']={}
        for name in ('dataset.bin','parallel.bin'):
            a=hashlib.sha256((runtime/'client_files'/name).read_bytes()).hexdigest()
            b=hashlib.sha256((runtime/'downloads/alice'/name).read_bytes()).hexdigest()
            require(a==b,'Downloaded digest differs');result['hashes'][name]=a
        require(result['session_ids_before']==result['session_ids_after'],'Session IDs changed')
        require(result['upload_resume_offset']>0 and result['download_resume_offset']>0,'Resume evidence absent')
        require(not any(j.status=='失败' for j in app.jobs.values()),'GUI task failed')
        result['completed_jobs']=len(completed_jobs)
        banner('09  完整性验证通过；心跳持续增长，4 条会话 ID 保持不变')
        shot('gui_complete.png')
        app.log('录像核验：双向断点 > 0；两个文件 SHA-256 一致；连接 ID 全程不变。')
        after(8,show_logs)
    def show_logs():
        app.tabs.select(1);banner('10  查看真实操作日志：认证、续传偏移、文件摘要与持久连接')
        after(.5,lambda:shot('gui_complete.png'))
        after(8,disconnect)
    def disconnect():
        app.disconnect();banner('11  用户主动断开连接；服务端继续维护其他用户会话')
        after(6,finish)
    def finish():
        nonlocal encoder
        try:
            if encoder:
                encoder.stdin.write(b'q\n');encoder.stdin.flush();encoder.wait(timeout=20)
                require(encoder.returncode==0,'ffmpeg failed')
        finally:
            if server:server.stop()
            log.close();app.close()
        result['errors']=errors;result['result']='PASS' if not errors else 'FAIL'
        (evidence/'video_verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    def begin():
        nonlocal encoder
        root.lift();root.focus_force();root.update_idletasks()
        encoder=subprocess.Popen([imageio_ffmpeg.get_ffmpeg_exe(),'-hide_banner','-y','-f','gdigrab','-framerate','12','-draw_mouse','0','-i','title=SecureBridge Experiment 1B Demo','-vf','scale=1440:-2','-c:v','libx264','-preset','veryfast','-crf','20','-pix_fmt','yuv420p','-movflags','+faststart',str(evidence/'ex1B_play.mp4')],stdin=subprocess.PIPE,stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW,env={**os.environ,'__COMPAT_LAYER':'HIGHDPIAWARE'})
        after(3,lambda:threading.Thread(target=pipeline,daemon=True).start())
        after(45,run_gui)
    after(30,begin)
    # A hard timeout closes only this demo and records the failure.
    def timeout():
        if root.winfo_exists():errors.append('Demo watchdog expired');finish()
    after(230,timeout)
    root.mainloop()
    if errors:raise RuntimeError(errors)
    print('Recorded:',evidence/'ex1B_play.mp4')


if __name__=='__main__':main()
