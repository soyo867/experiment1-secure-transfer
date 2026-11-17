"""Render the requirement-mapped report; measurements are loaded from evidence."""
import json
from pathlib import Path
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak,Image
from reportlab.graphics.shapes import Drawing,Rect,String,Line,Polygon

BASE=Path(__file__).resolve().parent.parent
W=A4[0]-88
INK=colors.HexColor('#153148'); TEAL=colors.HexColor('#087f8c'); LIGHT=colors.HexColor('#edf4f6'); GRAY=colors.HexColor('#536b80')


def build(output=None):
    meta=json.loads((BASE/'docs/submission.json').read_text(encoding='utf-8'))
    evidence_path=BASE/'evidence/integration_tests.json'
    results=json.loads(evidence_path.read_text(encoding='utf-8')) if evidence_path.exists() else {}
    metrics=results.get('metrics',{})
    unit_path=BASE/'evidence/server_unit_tests.json'
    units=json.loads(unit_path.read_text(encoding='utf-8')) if unit_path.exists() else {}
    gui_path=BASE/'evidence/gui_verification.json'
    gui=json.loads(gui_path.read_text(encoding='utf-8')) if gui_path.exists() else {}
    acl_path=BASE/'evidence/acl_verification.json'
    acl=json.loads(acl_path.read_text(encoding='utf-8-sig')) if acl_path.exists() else {}
    video_path=BASE/'evidence/video_verification.json'
    video=json.loads(video_path.read_text(encoding='utf-8')) if video_path.exists() else {}
    quality_path=BASE/'evidence/video_quality.json'
    quality=json.loads(quality_path.read_text(encoding='utf-8')) if quality_path.exists() else {}
    pdfmetrics.registerFont(TTFont('CN','C:/Windows/Fonts/msyh.ttc',subfontIndex=0))
    pdfmetrics.registerFont(TTFont('CB','C:/Windows/Fonts/msyhbd.ttc',subfontIndex=0))
    styles={k:ParagraphStyle(k,fontName='CB' if k in ('title','h') else 'CN',fontSize=size,leading=lead,textColor=INK,spaceAfter=gap,wordWrap='CJK')
            for k,size,lead,gap in [('title',21,29,18),('h',12,20,9),('body',10,17,10),('small',8,12,7),('cell',8.5,13,0)]}
    story=[]
    def p(text,style='body'): story.append(Paragraph(text,styles[style]))
    def page(title):
        if story: story.append(PageBreak())
        p(title,'title')
    def h(text): p(text,'h')
    def code(text):
        t=Table([[Paragraph(escape(text).replace('\n','<br/>'),styles['small'])]],colWidths=[W]);t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),LIGHT),('BOX',(0,0),(-1,-1),.4,TEAL),('TOPPADDING',(0,0),(-1,-1),10),('BOTTOMPADDING',(0,0),(-1,-1),10)]));story.extend([t,Spacer(1,12)])
    def table(head,rows,widths):
        data=[[Paragraph(escape(str(c)),styles['cell']) for c in row] for row in [head]+rows]
        t=Table(data,colWidths=widths,repeatRows=1);t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#cee4e7')),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,LIGHT]),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9),('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8)]));story.extend([t,Spacer(1,12)])
    def seq(title,steps):
        h(title)
        height=55+len(steps)*33
        d=Drawing(W,height); left,right=70,W-70
        for x,label in [(left,'Client'),(right,'Server')]:
            d.add(Rect(x-40,height-28,80,25,fillColor=LIGHT,strokeColor=None));d.add(String(x,height-20,label,fontName='CB',fontSize=10,textAnchor='middle',fillColor=INK))
            d.add(Line(x,10,x,height-32,strokeColor=GRAY,strokeDashArray=[3,3]))
        for i,(direction,label) in enumerate(steps):
            y=height-52-i*33; a,b=(left,right) if direction=='>' else (right,left);sign=1 if b>a else -1
            if direction=='.':
                d.add(Line(left,y+3,left+20,y+3,strokeColor=GRAY))
                d.add(Line(left+20,y+3,left+20,y-6,strokeColor=GRAY))
                d.add(Line(left+20,y-6,left,y-6,strokeColor=GRAY))
                d.add(Polygon([left,y-6,left+6,y-3,left+6,y-9],fillColor=GRAY,strokeColor=None))
                d.add(String(left+29,y+1,label,fontName='CN',fontSize=8.4,fillColor=INK))
                continue
            d.add(Line(a,y,b,y,strokeColor=TEAL,strokeWidth=1.2));d.add(Polygon([b,y,b-sign*6,y+3,b-sign*6,y-3],fillColor=TEAL,strokeColor=None))
            d.add(String(W/2,y+6,label,fontName='CN',fontSize=8.4,textAnchor='middle',fillColor=INK))
        story.append(d)
    def shot(filename,caption):
        path=BASE/'evidence'/filename
        if path.exists():
            im=Image(str(path));r=min(W/im.imageWidth,290/im.imageHeight);im.drawWidth=im.imageWidth*r;im.drawHeight=im.imageHeight*r;story.append(im);p(caption,'small')
    page('SecureBridge\n实验 1B：安全文件传输')
    p('《软件与系统安全》 · 设计、实现、攻击面分析与测试报告','h')
    git=escape(meta['repository_url'])
    if meta['repository_url'].startswith(('https://','http://')):
        git=f'<link href="{escape(meta["repository_url"], {chr(34): "&quot;"})}" color="#087f8c">{git}</link>'
    p(f"姓名：{escape(meta['name'])}　学号：{escape(meta['student_id'])}<br/>日期：{meta['date']}<br/>Git：{git}")
    p('本项目实现 Windows 原生 GUI 与自定义 SFT/1 应用层协议。客户端使用双向 TLS 建立一组持续连接，在文件传输完成后继续复用连接；服务端按证书身份划分目录、磁盘配额和带宽。上传与下载均支持断点恢复，完成时通过长度与 SHA-256 确认完整性。')
    table(['讲义要求','交付实现'],[
        ['第33页：安全、多用户、完整传输','mTLS、并发连接、长度声明、SHA-256、显式提交确认'],
        ['第36–37页：长连接、协议说明及图','SO_KEEPALIVE、后台心跳、连接池；协议头图与各模块时序图'],
        ['第40页：四项加分','上传/下载续传、公钥认证、GUI并发多文件、按身份聚合限速'],
        ['第45页：服务端目录ACL','独立用户根目录、严格文件名、链接拒绝；Windows/Linux ACL脚本'],
        ['第2–3页：提交物与Git','源码、MP4全过程演示、PDF、无加密ZIP、本地Git历史；远程URL待真实填写']
    ],[190,W-190])
    p('验收方式：真实 TCP/TLS 集成测试覆盖多用户、长连接、恢复与攻击输入；GUI测试覆盖交互并发；所有结果保存在 evidence/，报告数据依据本次实测。本阶段完成技术作业，按当前要求暂不提交；姓名、学号与远程仓库在提交前填写。','small')

    page('01  需求与系统架构')
    p('文件传输同时包含机密性、对端身份、边界划分、完整接收与访问控制。TCP 本身只提供有序字节流，不提供文件边界，也不验证文件属于哪位用户。因此系统分成 TLS 安全通道、SFT/1 帧层、传输状态层和文件权限层。')
    table(['层 / 模块','职责'],[
        ['GUI / gui.py','本地与远端浏览、多文件队列、进度、暂停续传、连接状态和日志'],
        ['client.py','mTLS连接池、心跳、序号匹配、SHA-256、局部文件和续传元数据'],
        ['protocol.py','20字节头 + UTF-8 JSON + 二进制，精确读取与有界解析'],
        ['server.py','认证用户、RPC分派、上传状态、下载块、连接与请求上限'],
        ['security.py','目录约束、输入校验、无跟随打开、配额和身份共享带宽预算'],
        ['tools/setup_demo.py','独立实验CA、客户端/服务端证书、两用户配置和测试文件'],
        ['tests / tools','协议/安全测试、GUI检查、演示录制、报告与打包']
    ],[160,W-160])
    h('并发模型')
    p('服务端对允许的连接分配工作线程，握手与帧读取都有截止时间。客户端连接池在一次连接动作中建立多个通道；每通道通过互斥锁保持一问一答，任务跨通道并行。池中连接不会因单次上传/下载完成而关闭，后台线程在空闲时发送心跳，直到用户断开或关闭客户端。')
    h('信任与数据流')
    code('本地文件 → 分块与哈希 → SFT/1 → TLS 加密 → TCP\nTCP → TLS 验证/解密 → SFT/1边界校验 → 用户ACL → 暂存文件\nPUT_COMMIT → 大小与SHA-256验证 → 原子发布 → 完成确认\nGUI ← 任务队列状态 / 已确认偏移 / 连接标识 / 错误事件')
    p('演示默认仅监听 127.0.0.1:18443。部署到远程主机时需为实际 DNS/IP 重新签发带 SAN 的服务端证书，再更改客户端 host/server_hostname；不得通过关闭证书校验来连接。')

    page('02  SFT/1 协议头与消息格式')
    d=Drawing(W,215)
    rows=[[(0,32,'Bytes 0-3: Magic = SFT1 (32 bits)')],
          [(0,8,'Byte 4: Version'),(8,16,'Byte 5: Type'),(16,32,'Bytes 6-7: Flags (16 bits)')],
          [(0,32,'Bytes 8-11: Request ID (32 bits)')],
          [(0,32,'Bytes 12-15: JSON length (32 bits)')],
          [(0,32,'Bytes 16-19: Payload length (32 bits)')],
          [(0,32,'JSON metadata: 2..16384 bytes (variable)')],
          [(0,32,'Binary payload: 0..65536 bytes (variable)')]]
    for i,row in enumerate(rows):
        for a,b,label in row:
            x=a/32*W;y=180-i*29;w=(b-a)/32*W
            d.add(Rect(x,y,w,27,fillColor=LIGHT if i<5 else colors.white,strokeColor=GRAY,strokeWidth=.5));d.add(String(x+w/2,y+10,label,fontName='CN',fontSize=8,textAnchor='middle',fillColor=INK))
    story.append(d)
    p('固定头为 struct.Struct("!4sBBHIII")，使用网络大端字节序。图中前五行共有七个字段：Magic、Version、Type、Flags、Request ID、JSON length、Payload length，长度为 4+1+1+2+4+4+4=20 字节。JSON 与 payload 随后紧密排列。Type=1 请求、2 响应；Flags=0；Request ID 为非零 uint32，响应与请求一致。')
    table(['字段/约束','处理规则'],[
        ['JSON length','2..16384字节；UTF-8对象；拒绝重复key、非有限数和过深/非法JSON'],
        ['Payload length','0..65536字节；声明长度验证后才读取/分配'],
        ['Command','JSON中的op：HELLO/PING/LIST/PUT_BEGIN/PUT_CHUNK/PUT_COMMIT/GET_BEGIN/GET_CHUNK/CANCEL/BYE'],
        ['Response','ok=true + 返回字段；失败ok=false + code/error；请求ID保持一致'],
        ['TCP拆包/粘包','_exact循环到足够字节；sendall处理部分发送；绝不假设一次recv等于一帧'],
        ['抗慢速输入','整帧使用绝对截止时间；持续发送零星字节不能无限延长占用']
    ],[115,W-115])
    code('{"op":"PUT_BEGIN","name":"dataset.bin","size":2097152,"sha256":"<64 hex>"}\n{"op":"PUT_CHUNK","transfer_id":"<id>","offset":65536} + binary block\n{"op":"PUT_COMMIT","transfer_id":"<id>"}')

    page('03  认证、心跳与目录查询')
    seq('模块 A · 建立连接与身份绑定',[('>','TCP connect + TLS ClientHello / server_hostname'),('<','服务端证书链、SAN；客户端验证CA、有效期和主机名'),('>','客户端证书与私钥签名；服务端验证CA及用户指纹'),('>','HELLO（SFT/1 request ID）'),('<','user / role / bandwidth / connection_id / protocol')])
    seq('模块 B · 长连接守护',[('>','SO_KEEPALIVE 已启用；空闲后台发送 PING'),('<','PING 响应，同一 connection_id'),('>','下一次 LIST / 上传 / 下载继续使用同一通道')])
    seq('模块 C · 用户目录查询',[('>','LIST（已认证的持久通道）'),('<','仅返回当前用户根目录下可见的普通文件'),('>','请求后继续心跳，保持连接')])
    p('身份来自 TLS 证书而非任意 JSON 用户名。CN 必须存在于服务端用户表，DER 证书 SHA-256 指纹必须精确匹配。用户带宽、配额、目录和角色均由服务端配置决定，客户端不能自报 VIP。','small')

    page('04  上传、断点恢复与提交')
    seq('模块 D · 上传文件',[('>','PUT_BEGIN(name, total size, sha256)'),('<','transfer_id / confirmed offset / prefix_sha256'),('.','客户端校验本地前缀 SHA-256'),('>','PUT_CHUNK(offset) + payload'),('<','校验顺序、配额；写入暂存；返回 next offset'),('>','重复传输剩余块；PUT_COMMIT(transfer_id)'),('<','验证大小和完整SHA-256；原子发布；ok=true')])
    seq('模块 E · 暂停/断线后的上传恢复',[('>','CANCEL(transfer_id) 或连接中断'),('<','保留已确认的用户私有暂存数据'),('>','重连认证后 PUT_BEGIN(同名/大小/hash)'),('<','返回已持久化offset和前缀SHA-256'),('>','前缀一致才从offset继续；不一致须明确reset')])
    p('最终文件仅在 COMMIT 校验成功后出现，错误哈希或不完整上传不能发布。块偏移必须连续，暂存状态绑定用户与文件内容，写入租约绑定当前连接。CANCEL 或断线释放租约但保留状态；新连接经认证后才能继续。服务器对每块 flush/fsync 后确认偏移。协议以长度、偏移和确认终止文件传输，连接仍可立即承载下一次请求。')
    p('同名已有文件不被覆盖；不同内容或续传前缀冲突返回错误。同内容、同长度的重复上传直接确认已完成。提交使用同一文件系统内 os.link 原子创建最终名字，成功后删除临时链接；已有目标使操作失败。客户端不能指定任意暂存路径。','small')

    page('05  下载、恢复、错误与退出')
    seq('模块 F · 下载与恢复',[('>','GET_BEGIN(name)'),('<','size / sha256（服务端元数据）'),('>','本地part对照元数据后，GET_CHUNK(offset,length)'),('<','返回二进制块；循环到size，受用户共享带宽限制'),('.','客户端校验完整 SHA-256 并原子发布'),('>','后续命令仍在同一通道；文件完成不关闭TCP')])
    seq('模块 G · 错误与取消',[('>','非法路径/偏移/大小/权限请求'),('<','ok=false，明确错误码；不执行危险文件操作'),('>','取消任务，停止新增块；保留可恢复部分文件')])
    seq('模块 H · 用户手动断开',[('>','停止任务派发与后台心跳；对池通道发送 BYE'),('<','返回确认，释放句柄并关闭连接'),('>','用户再次连接时重新执行完整TLS认证')])
    p('下载只在大小与SHA-256都一致时发布最终文件。断点元数据绑定服务端地址、端口、用户、文件名、大小与hash；片段被修改时最终hash校验失败，需显式从头重试。客户端对同一目标的并发任务互斥，使用os.link发布且不覆盖已有文件；目标文件系统需支持硬链接。网络异常向用户反馈，由重新连接与继续任务恢复。','small')

    page('06  安全设计与服务端 ACL')
    table(['威胁','实现防护','验证方式'],[
        ['中间人/伪造服务端','TLS>=1.2；可信CA、SAN/hostname验证；无明文回退','错误CA、主机名、无证书/不可信客户端均拒绝'],
        ['客户端冒名/旧证书','mTLS+用户证书指纹白名单；替换/撤销后拒绝旧指纹','同CA但未授权指纹测试'],
        ['目录穿越/任意文件','平坦文件名；拒绝路径分隔符、..、ADS、设备名、控制字符','../、绝对路径、NUL、符号链接/重解析点用例'],
        ['跨用户访问','证书身份映射唯一私有根；不接受远程用户参数','alice上传，bob查询不可见；他人transfer_id无效'],
        ['SQL注入/命令注入','业务没有SQL数据库，也不把远程字段拼入shell','注入样式字符串作为非法参数或普通名字处理'],
        ['磁盘与内存耗尽','帧/文件/磁盘配额、暂存数量/列表边界、并发连接上限','超长声明、超配额及饱和连接测试']
    ],[90,240,W-330])
    h('明确的目录配置')
    code('server.json中的storage_root: data（相对于runtime/）\nusers.alice.root: alice\nusers.bob.root: bob\n客户端只可操作自己的平坦文件名，不能提交任意相对/绝对路径。\n部署时将runtime写权限授予专用服务账户；源码、证书和数据分开管理。')
    p('tools/acl_windows.ps1 提供部署目录显式 NTFS ACL：指定服务账户 Modify，SYSTEM/Administrators FullControl，移除继承；tools/acl_linux.sh 提供现有服务账户的 owner/group/default mask 配置。两个脚本均要求明确的实验runtime绝对路径，拒绝盘根。它们属于部署步骤，不能把应用层路径校验误称为进程沙箱。')
    p('双向认证下的客户端不能创建目录或链接；目录外本机恶意进程属于另一个信任边界。专用低权限服务账户、只读源码、独立数据卷可进一步缩小服务进程失陷后的影响。容器/chroot 可以增强文件系统隔离，但仍需资源限制与正确挂载权限。','small')
    code('Windows: powershell -File tools/acl_windows.ps1 -RuntimePath <runtime绝对路径> -ServiceAccount <现有服务账户>\nLinux: sudo sh tools/acl_linux.sh /absolute/path/runtime <现有服务账户>\n脚本执行后检查输出ACL；用该账户启动服务端。')
    if acl.get('result')=='PASS':
        p('Windows ACL脚本已在新建的独立实验runtime目录实际执行并核验：根目录关闭继承，仅当前执行账户具有Modify/Synchronize，SYSTEM与Administrators具有FullControl，权限可向子目录与文件继承。证据见evidence/acl_verification.json。验证使用现有执行账户，未创建用户、未改变全局权限，也未进行另一账户登录后的拒绝访问测试。','small')

    page('07  资源耗尽防护与身份限速')
    table(['控制','演示配置'],[
        ['全局 / 每IP / 每用户并发','32 / 16 / 8，超过上限拒绝'],
        ['TLS握手 / 整帧截止','5秒 / 30秒；握手占用也计入连接上限'],
        ['请求频率','每身份100请求/秒，burst200；限额与会话身份绑定'],
        ['单文件 / 用户磁盘','32 MiB / 64 MiB；暂存和预留一同计入约束'],
        ['帧内容','JSON≤16 KiB，payload≤64 KiB，固定头先检查再读取'],
        ['带宽等级','alice / VIP：4 MiB/s；bob / standard：1 MiB/s'],
        ['聚合口径','同一用户的所有连接共享上传+下载预算，不能通过多开连接倍增带宽']
    ],[175,W-175])
    h('限速算法')
    p('每个用户维护一个带锁的带宽预算时间线。处理N字节时，预留结束时间=max(当前时刻,已预留结束)+N/rate，释放锁后等待。不同连接共享同一预算，上传和下载都记账。等待可以由服务端停止事件打断，不在持有共享锁时睡眠。')
    h('DDoS 防护范围')
    p('本程序针对应用层资源耗尽：连接洪泛、TLS握手占用、慢速帧、过大长度、过量请求和磁盘填满。测试验证限额触发后资源能够回收、合法连接能继续服务。容量型分布式攻击若先耗尽上行链路，应用程序无法单独阻止；公网部署还需网关限流、网络侧防护与监控。报告按实际措施与验证范围陈述，不以“绝对防DDoS”代替证据。')
    h('证书生命周期')
    p('setup_demo 在本地生成实验CA与新私钥，服务端证书带 localhost / 127.0.0.1 SAN，客户端仅有 clientAuth EKU。CA 私钥仅在生成期间存于内存，生成后不落盘；端点私钥不进入Git或ZIP。撤销用户时移除用户配置或替换指纹并重启服务，现有连接随重启断开。重新部署完整证书集用于实验轮换。')

    page('08  实验结果与复现证据')
    if results:
        p(f"真实 TLS 集成测试：{results['tests']} 项，{results['result']}，失败 {results['failures']}，错误 {results['errors']}，跳过 {len(results['skipped'])}；耗时 {results['seconds']} 秒。环境：Python {results['python']} / {results['platform']}。结果读取自 evidence/integration_tests.json，逐项记录见同名 .txt。")
        table(['测试类别','实际观察与判据'],[
            ['文件边界与完整性','0字节、262400字节二进制及8 MiB文件上传/下载，逐字节和SHA-256一致；错误offset、提前提交及错误hash被拒绝'],
            ['持久连接','LIST/上传/下载后session IDs不变；SO_KEEPALIVE=1；后台心跳实测 '+str(metrics.get('heartbeat_count','待测'))+' 次'],
            ['多用户并发','alice、bob各自持久连接池，同时完成 '+str(metrics.get('concurrent_transfers','待测'))+' 项上传/下载；目录与transfer_id相互隔离'],
            ['双向断点与重启','上传恢复 '+str(metrics.get('upload_resume_offset','待测'))+' 字节，下载恢复 '+str(metrics.get('download_resume_offset','待测'))+' 字节；服务端重启后双向仍从131072字节恢复'],
            ['损坏断点','修改上传part触发前缀hash拒绝；修改下载part触发完整hash拒绝；均未发布错误文件，显式reset后成功'],
            ['TLS身份负例','错hostname、不可信服务端CA、不可信客户端证书、无证书、已撤销指纹均被拒绝'],
            ['输入与权限','路径穿越、绝对路径、Windows设备名/ADS、符号链接拒绝；SQL元字符仅作为名字数据'],
            ['资源限制','超长帧不等待body；畸形输入只关闭其连接；连接/请求上限、握手/整帧超时、文件/磁盘配额均触发']
        ],[105,W-105])
    else:
        p('集成测试结果仍待生成；完成测试后重建报告。')
    p('测试为每套实验独立生成CA/证书，并为每个测试隔离存储目录。所测攻击输入仅发往本机临时端口。Windows符号链接用例实际执行，未因权限不足而跳过。','small')

    page('09  带宽、GUI与协议单元验证')
    speed=metrics.get('bandwidth_test',{})
    aggregate=metrics.get('aggregate_bandwidth',{})
    table(['配置 / 测量','本次证据'],[
        ['普通身份测量','524288字节，限制131072 B/s，耗时 '+str(speed.get('slow_seconds','待测'))+' 秒'],
        ['高速身份测量','524288字节，限制1048576 B/s，耗时 '+str(speed.get('fast_seconds','待测'))+' 秒'],
        ['同身份跨连接聚合','2个连接，共524288字节，限制131072 B/s，耗时 '+str(aggregate.get('seconds','待测'))+' 秒；判据大于3.5秒，无法翻倍速率'],
        ['GUI交互验证',str(gui.get('result','待生成'))+'；4持久通道、'+str(gui.get('upload_count','待测'))+'个上传、'+str(gui.get('download_count','待测'))+'个下载；同时双向传输、暂停/续传、手动断开；callback错误 '+str(len(gui.get('tk_callback_errors',[])))+' 项'],
        ['协议/存储单元测试',str(units.get('tests','待测'))+' 项，'+str(units.get('result','待测'))+'；拆包/粘包、头/JSON、EOF/超时、配额/租约、提交崩溃恢复、Windows大小写、目录分页与停止竞态'],
        ['证据文件','integration_tests.json/.txt；gui_verification.json；server_unit_tests.json/.txt（均在evidence目录）']
    ],[145,W-145])
    p('带宽计时包含TLS、文件I/O和调度开销，用于检查速率下界及身份差异，不作为网络峰值吞吐benchmark。同身份上传和下载共用一个调度预算；并发测试证明多开连接不能绕过该预算。测试使用可快速复现的低速参数，演示默认VIP/普通等级仍为4/1 MiB/s。')
    if video.get('result')=='PASS' and quality.get('result')=='PASS':
        h('全过程演示证据')
        p('独立MP4时长 '+str(quality['seconds'])+' 秒，完整解码通过。录像依次显示依赖检查、compileall编译检查、全新证书与配置初始化、测试执行、GUI多文件传输、双向暂停续传、长连接心跳和手动断开。录像运行另记录 '+str(video['completed_jobs'])+' 个完成任务；上传从 '+str(video['upload_resume_offset'])+' 字节恢复，下载从 '+str(video['download_resume_offset'])+' 字节恢复；'+str(video['client_stats']['heartbeat_count'])+' 次心跳后4个session ID保持不变。过程见evidence/ex1B_play.mp4，结构化证据见video_verification.json与video_quality.json。','small')
    h('正确性论证')
    p('消息边界由固定头及两段长度确定；循环精确读取抵抗TCP拆包/粘包。请求ID关联响应防止错配；每通道串行RPC避免交叉读取。上传总长提前声明，块偏移校验防跳写；最终哈希与原子发布保证完整文件才可见。下载依据服务端声明的长度终止，哈希校验后才发布。认证在业务命令之前完成，文件定位只使用被认证用户的服务端根目录。')

    page('10  GUI 与操作流程')
    shot('gui_transfer.png','图 1　实际 Windows GUI：本地/远端文件、并发队列、确认偏移与连接状态。')
    shot('gui_complete.png','图 2　续传完成事件日志、SHA-256验证及持续心跳；传输结束后4条连接仍然保持。')
    p('选择 alice 或 bob 配置并连接。左侧选择多个本地文件上传；右侧选择多个远端文件下载，可同时执行两种方向的任务。任务取消后保留断点，续传时校验已有状态；连接信息显示用户角色、TLS和通道标识。用户断开/退出时释放持久连接。','small')

    page('11  需求映射与代码定位')
    table(['讲义页 / 要求','实现入口与报告位置'],[
        ['p33 安全协议、多用户、完整文件','protocol.recv_frame/send_frame；Server._connection/_dispatch；UserStore.begin/chunk/commit/read；报告01-08'],
        ['p36-37 持久TCP与keep alive','protocol.keep_alive；Channel.rpc/close；SecureClient._heartbeat_loop；报告03、08'],
        ['p36-37,46,48 协议图及原理','20字节头图；认证、心跳、列表、上传、恢复、下载、错误、退出8个模块时序图；报告02-05、09'],
        ['p40 断点续传加分','UserStore持久化records/part；SecureClient.upload/_download；报告04-05、08'],
        ['p40 公钥认证加分','TLS CA + 客户端/服务端证书；Server._connection的CN映射和DER指纹；报告03、06-07'],
        ['p40 GUI并发加分','gui.py任务队列与ThreadPoolExecutor；SecureClient连接池；tools/verify_gui.py；报告09-10'],
        ['p40 用户带宽加分','security.BandwidthLimiter；每UserStore共享limiter；Server._dispatch双向计费；报告07、09'],
        ['p45 目录ACL配置','security.file_name/confined/no_link/secure_open；每用户root；tools/acl_windows.ps1与acl_linux.sh；报告06'],
        ['p33 运行过程视频','源码编译检查、证书初始化、服务端部署、GUI操作、测试输出；视频作为独立MP4交付'],
        ['p2-3 格式与Git记录','源码、MP4、PDF及无加密ZIP；本地Git完整历史；个人命名与远程推送按用户要求推迟到提交前']
    ],[135,W-135])
    p('完整逐条矩阵见docs/requirements.json，区分已验证技术要求与提交前信息。源代码引用均相对于源码根目录的securetransfer/，函数名用于定位实际校验逻辑；测试函数名与完整结果保存在evidence日志。','small')

    page('12  构建、部署、测试与提交')
    p('最低环境：Python 3.10+、Tk、OpenSSL支持的ssl模块。服务端/客户端运行仅用标准库；首次生成证书需要cryptography。演示在Windows本机运行，视频包含源码编译检查、证书与配置初始化、服务部署、GUI传输以及测试结果。')
    code('python -m pip install -r requirements.txt\npython -m compileall -q securetransfer tools run.py\npython tools/setup_demo.py\npython run.py server --config runtime/server.json\n# 第二个终端\npython run.py gui --profile runtime/alice.json\npython tools/verify_integration.py\npython -m unittest discover -s tests -v')
    p('私钥和用户文件不随源码发布。评阅者运行setup_demo即可生成独立实验身份；runtime已有server.json时脚本保留现有部署，避免意外替换证书和数据。要重新初始化，指定新的空目录。Windows/Linux ACL脚本的参数与操作范围写在脚本头部。')
    h('提交格式与版本历史')
    code('姓名_学号_EX1B/\n  姓名_学号_ex1B_src/\n  姓名_学号_ex1B_play.mp4\n  姓名_学号_ex1B_report.pdf')
    p('按讲义使用无加密ZIP，无README，说明集中在本报告。提交截止：2026年11月24日23:55。源码采用MIT许可，本地Git记录与history.bundle保存开发历史。用户当前要求暂不提交，因此保留姓名、学号和远程URL占位；正式提交前填写docs/submission.json、推送到真实GitHub/Gitee/GitLab仓库，再重建报告与ZIP。本地bundle保存历史，远程仓库完成后才满足讲义开源要求。')
    code('git remote add origin <实际仓库URL>\ngit push -u origin <当前分支>\n# 填写 docs/submission.json 后；Windows报告构建需微软雅黑\npython -m pip install -r requirements-dev.txt\npython tools/build_report.py\npython tools/pack_submission.py --destination <新的输出目录>')
    h('参考资料与学习记录')
    for label,url in [('Python ssl：TLS上下文、证书与主机名验证','https://docs.python.org/3/library/ssl.html'),('cryptography：X.509证书生成与CA层次','https://cryptography.io/en/latest/x509/tutorial/')]:
        p(f'<link href="{url}" color="#087f8c">{label}</link>','small')
    p('主要实验依据：刘鹏，《实验1讲解2026》，第2–3、33–46、49–60、65页。实现、测试与报告由AI辅助；提交者应阅读protocol、client、server和security模块，对照时序图解释keep alive、消息边界、证书信任和断点恢复规则。','small')
    out=Path(output or BASE/'docs/实验1B_安全文件传输报告.pdf');out.parent.mkdir(parents=True,exist_ok=True)
    def footer(c,doc):
        c.setStrokeColor(GRAY);c.line(44,35,A4[0]-44,35);c.setFillColor(GRAY);c.setFont('CN',8);c.drawString(44,23,'SECUREBRIDGE / SOFTWARE & SYSTEM SECURITY / EX1B');c.drawRightString(A4[0]-44,23,str(doc.page))
    SimpleDocTemplate(str(out),pagesize=A4,leftMargin=44,rightMargin=44,topMargin=42,bottomMargin=45,title='实验1B 安全文件传输',author=meta['name']).build(story,onFirstPage=footer,onLaterPages=footer)
    print(out)
    return out


if __name__=='__main__':build()
