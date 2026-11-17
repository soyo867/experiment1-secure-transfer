"""Extract a submission into an isolated folder and test its delivered source."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
import zipfile

BASE=Path(__file__).resolve().parent.parent


def verify(archive):
    target=BASE/'runtime'/('package_check_'+time.strftime('%Y%m%d_%H%M%S'))
    target.mkdir(parents=True,exist_ok=False)
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for item in z.infolist():
            assert not item.flag_bits&1
            resolved=(target/item.filename).resolve()
            assert resolved.is_relative_to(target.resolve())
            assert not resolved.suffix=='.key'
            assert 'runtime' not in Path(item.filename).parts
            assert not resolved.name.lower().startswith('readme')
        z.extractall(target)
    root=next(p for p in target.iterdir() if p.is_dir())
    children=list(root.iterdir());assert len(children)==3
    source=next(p for p in children if p.is_dir() and p.name.endswith('_ex1B_src'))
    assert any(p.suffix=='.pdf' for p in children) and any(p.suffix=='.mp4' for p in children)
    git=subprocess.run(['git','bundle','list-heads',str(source/'history.bundle')],capture_output=True,text=True,encoding='utf-8',check=True)
    subprocess.run([sys.executable,'tools/setup_demo.py','--port','18443'],cwd=source,check=True,capture_output=True)
    code='''import hashlib,json
from pathlib import Path
from securetransfer.server import Server
from securetransfer.client import SecureClient
root=Path('runtime').resolve()
server=Server(root/'server.json');port=server.start(port=0)
try:
    profile=root/'alice.json';data=json.loads(profile.read_text());data['port']=port;profile.write_text(json.dumps(data))
    with SecureClient(profile) as client:
        before=client.connection_info['session_ids']
        for name in ('实验说明.txt','empty.bin','parallel.bin'):
            source=root/'client_files'/name
            client.upload(source)
            output=root/'downloads/alice'/name
            client.download(name,output)
            assert hashlib.sha256(source.read_bytes()).digest()==hashlib.sha256(output.read_bytes()).digest()
        assert before==client.connection_info['session_ids']
        assert len(client.list_files())==4
    print('PASS: extracted source, fresh mTLS deployment, Unicode/empty/binary roundtrips, persistent sessions')
finally:server.stop()
'''
    result=subprocess.run([sys.executable,'-c',code],cwd=source,capture_output=True,text=True,encoding='utf-8',errors='replace')
    if result.returncode:raise RuntimeError(result.stdout+'\n'+result.stderr)
    evidence={'result':'PASS','archive':str(Path(archive).resolve()),'structure':'source folder + report PDF + MP4',
              'crc_passed':True,'unencrypted':True,'runtime_private_keys_excluded':True,'bundle_heads':git.stdout.strip().splitlines(),
              'fresh_extraction_smoke':result.stdout.strip()}
    (BASE/'evidence/package_verification.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(evidence,ensure_ascii=False,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('archive');args=parser.parse_args()
    verify(args.archive)
