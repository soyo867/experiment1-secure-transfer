"""Build the lecture-named source/video/report ZIP without runtime secrets."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

from build_report import build

BASE=Path(__file__).resolve().parent.parent


def component(text):
    if not text or re.search(r'[<>:"/\\|?*\x00-\x1f]',text) or text.endswith(('.', ' ')):
        raise ValueError('Invalid submission name or student ID')
    return text


def pack(destination=None):
    meta=json.loads((BASE/'docs/submission.json').read_text(encoding='utf-8'))
    prefix=component(meta['name'])+'_'+component(meta['student_id'])
    dest=Path(destination or BASE/'deliverables');dest.mkdir(exist_ok=True,parents=True)
    if (dest/(prefix+'_EX1B')).exists():
        dest=dest/('rebuild_'+datetime.now().strftime('%Y%m%d_%H%M%S'));dest.mkdir()
    folder=dest/(prefix+'_EX1B');folder.mkdir()
    source=folder/(prefix+'_ex1B_src');source.mkdir()
    for name in ('run.py','requirements.txt','requirements-dev.txt','LICENSE.txt','.gitignore','.gitattributes',
                 '准备演示环境.bat','启动服务端.bat','启动客户端.bat','启动普通用户客户端.bat'):
        shutil.copy2(BASE/name,source/name)
    for name in ('securetransfer','tests','tools','docs'):
        shutil.copytree(BASE/name,source/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc','*.pdf'))
    evidence=source/'evidence';evidence.mkdir()
    for path in (BASE/'evidence').iterdir():
        if path.is_file() and path.suffix in ('.json','.txt','.png'):
            shutil.copy2(path,evidence/path.name)
    build(folder/(prefix+'_ex1B_report.pdf'))
    video=BASE/'evidence/ex1B_play.mp4'
    if not video.is_file() or not video.stat().st_size:raise RuntimeError('Missing demo video')
    shutil.copy2(video,folder/(prefix+'_ex1B_play.mp4'))
    proc=subprocess.run(['git','rev-parse','--show-toplevel'],cwd=BASE,capture_output=True,text=True,encoding='utf-8')
    if proc.returncode==0 and Path(proc.stdout.strip()).resolve()==BASE.resolve():
        subprocess.run(['git','bundle','create',str(source/'history.bundle'),'--all'],cwd=BASE,check=True)
    elif (BASE/'history.bundle').is_file():shutil.copy2(BASE/'history.bundle',source/'history.bundle')
    else:raise RuntimeError('Missing Git history')
    files=sorted(p for p in folder.rglob('*') if p.is_file())
    assert not any(p.suffix in ('.key','.part') or 'runtime' in p.relative_to(folder).parts for p in files)
    archive=dest/(prefix+'_EX1B.zip')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for path in files:z.write(path,path.relative_to(dest).as_posix())
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        assert all(not x.flag_bits&1 for x in z.infolist())
    manifest={'format':'ZIP (unencrypted)','submitted':False,'submission_identity_deferred_by_user':True,
        'personal_fields_pending':any('待填写' in str(meta[k]) for k in ('name','student_id','repository_url')),
        'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
        'files':[{'path':p.relative_to(folder).as_posix(),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]}
    (dest/'package_manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    print(archive)
    return archive


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--destination');args=parser.parse_args()
    pack(args.destination)
