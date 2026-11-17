"""Generate fresh local laboratory identities, data roots and profiles.

No private key is shipped in source/submission. This CA is local to the lab and
is never installed into an OS/browser trust store. Run only once per runtime.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

BASE = Path(__file__).resolve().parent.parent


def provision(destination, port=18443):
    root = Path(destination).resolve()
    if (root/'server.json').exists():
        print('Existing deployment preserved:', root)
        return root
    if root.exists() and any(root.iterdir()):
        raise ValueError('Choose an empty directory; partially provisioned data will not be overwritten')
    root.mkdir(parents=True,exist_ok=True)
    certs = root/'certs'
    certs.mkdir(mode=0o700)
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537,key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SecureHarbor Local Lab CA')])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
          .not_valid_after(now+timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True,path_length=0),True)
          .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),False)
          .sign(ca_key,hashes.SHA256()))
    (certs/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    fingerprints = {}
    for identity in ('server','alice','bob'):
        key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost' if identity=='server' else identity)])
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca.subject).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
                   .not_valid_after(now+timedelta(days=90)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
                   .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if identity=='server' else ExtendedKeyUsageOID.CLIENT_AUTH]),False)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),False))
        if identity=='server':
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False)
        cert = builder.sign(ca_key,hashes.SHA256())
        (certs/f'{identity}.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        keypath = certs/f'{identity}.key'
        fd = os.open(keypath,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        fingerprints[identity] = cert.fingerprint(hashes.SHA256()).hex()
    # CA private key is discarded, not persisted: reprovision identities to rotate trust.
    users = {}
    for user,bandwidth,role in [('alice',4194304,'VIP'),('bob',1048576,'standard')]:
        (root/'data'/user).mkdir(parents=True,mode=0o700)
        (root/'data'/user/'welcome.txt').write_text(f'Welcome {user}. SecureHarbor mTLS private storage.\n',encoding='utf-8')
        (root/'downloads'/user).mkdir(parents=True)
        users[user] = {'root':user,'bandwidth':bandwidth,'quota':67108864,'role':role,'certificate_sha256':fingerprints[user]}
        profile = {'host':'127.0.0.1','port':port,'server_hostname':'localhost','ca':'certs/ca.pem',
                   'cert':f'certs/{user}.pem','key':f'certs/{user}.key','local_dir':'client_files',
                   'download_dir':f'downloads/{user}','pool_size':4,'heartbeat_interval':5}
        (root/f'{user}.json').write_text(json.dumps(profile,indent=2),encoding='utf-8')
    config = {'host':'127.0.0.1','port':port,'tls':{'ca':'certs/ca.pem','cert':'certs/server.pem','key':'certs/server.key'},
              'storage_root':'data','users':users,'limits':{'max_connections':32,'max_connections_per_ip':16,
              'max_connections_per_user':8,'max_file_size':33554432,'handshake_timeout':5,'frame_timeout':30,
              'requests_per_second':100,'request_burst':200}}
    (root/'server.json').write_text(json.dumps(config,indent=2),encoding='utf-8')
    local = root/'client_files'
    local.mkdir()
    (local/'实验说明.txt').write_text('实验 1B：安全文件传输\n双向TLS、长连接、断点续传、SHA-256。\n',encoding='utf-8')
    (local/'empty.bin').write_bytes(b'')
    (local/'dataset.bin').write_bytes(bytes(range(256))*8192)
    (local/'parallel.bin').write_bytes(bytes(reversed(range(256)))*4096)
    manifest = {'created_utc':now.isoformat(),'certificates_sha256':fingerprints,'ca_key_persisted':False,
                'sample_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in local.iterdir()}}
    (root/'deployment.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Provisioned:',root)
    print('mTLS identities: alice (VIP 4 MiB/s), bob (standard 1 MiB/s)')
    print('CA trust is confined to application profiles; no system trust changes.')
    return root


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',default=str(BASE/'runtime'))
    parser.add_argument('--port',type=int,default=18443)
    args=parser.parse_args()
    provision(args.out,args.port)
