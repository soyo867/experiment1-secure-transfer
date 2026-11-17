"""Decode recorded MP4, inspect spaced frames, and create a visual QA sheet."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

import imageio_ffmpeg
from PIL import Image, ImageDraw, ImageFont, ImageStat

BASE=Path(__file__).resolve().parent.parent


def main():
    video=BASE/'evidence/ex1B_play.mp4';ffmpeg=imageio_ffmpeg.get_ffmpeg_exe()
    probe=subprocess.run([ffmpeg,'-hide_banner','-i',str(video)],capture_output=True,text=True,encoding='utf-8',errors='replace')
    match=re.search(r'Duration: (\d+):(\d+):(\d+\.\d+)',probe.stderr)
    if not match:raise RuntimeError('Cannot probe video duration')
    hours,minutes,seconds=map(float,match.groups());duration=hours*3600+minutes*60+seconds
    assert duration>100,'Video is unexpectedly short'
    validate=subprocess.run([ffmpeg,'-v','error','-i',str(video),'-f','null','-'],capture_output=True,text=True)
    assert validate.returncode==0 and not validate.stderr.strip(),validate.stderr
    frames=[];hashes=[];times=[5+(duration-10)*i/5 for i in range(6)]
    with tempfile.TemporaryDirectory(prefix='sft_video_') as temp:
        for i,timestamp in enumerate(times):
            file=Path(temp)/(str(i)+'.png')
            subprocess.run([ffmpeg,'-hide_banner','-loglevel','error','-ss',str(timestamp),'-i',str(video),'-frames:v','1','-vf','scale=680:-2',str(file)],check=True)
            frame=Image.open(file).convert('RGB');frame.load()
            assert max(ImageStat.Stat(frame).stddev)>15,'Blank video frame'
            frames.append(frame);hashes.append(hashlib.sha256(frame.tobytes()).hexdigest())
    assert len(set(hashes))>=5,'Video appears static'
    height=frames[0].height+32
    sheet=Image.new('RGB',(1360,height*3),'#e5edf0');draw=ImageDraw.Draw(sheet)
    font=ImageFont.truetype('C:/Windows/Fonts/msyh.ttc',16)
    for i,(frame,timestamp) in enumerate(zip(frames,times)):
        x=(i%2)*680;y=(i//2)*height
        sheet.paste(frame,(x,y+32));draw.text((x+12,y+6),f'{timestamp:.1f}s · 实际运行画面',font=font,fill='#153148')
    sheet.save(BASE/'evidence/video_contact_sheet.png')
    result={'result':'PASS','seconds':round(duration,2),'bytes':video.stat().st_size,'full_decode_passed':True,'distinct_sampled_frames':len(set(hashes)),
            'sample_times':times,'sha256':hashlib.sha256(video.read_bytes()).hexdigest()}
    (BASE/'evidence/video_quality.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
