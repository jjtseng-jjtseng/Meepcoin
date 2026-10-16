"""Observe the public HTTPS route without exposing the invitation capability."""
import argparse,json,os,signal,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--private',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
p.add_argument('--seconds',type=int,default=4200);a=p.parse_args();assert 60<=a.seconds<=4200
os.umask(0o077);private=json.loads(a.private.read_text());url=private['url'];parsed=urllib.parse.urlsplit(url)
assert parsed.scheme=='https' and parsed.netloc=='mine.meepcoin.me'
token=urllib.parse.parse_qs(parsed.fragment)['session'][0]
stop=False
def interrupted(*_):
 global stop;stop=True
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
start=time.monotonic();previous=None;maxGap=0;count=0;statuses={}
with a.output.open('x',encoding='utf-8') as stream:
 while time.monotonic()-start<a.seconds and not stop:
  tick=time.monotonic();gap=0 if previous is None else tick-previous;previous=tick;maxGap=max(maxGap,gap)
  row={'utc':time.time(),'gapSeconds':gap,'tlsValidationEnabled':True,'verifiedPublicTls':False}
  request=urllib.request.Request('https://mine.meepcoin.me/readyz',headers={'X-Meep-Session':token,
   'Origin':'https://mine.meepcoin.me',
   'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36'})
  try:
   try:response=urllib.request.urlopen(request,timeout=3)
   except urllib.error.HTTPError as error:response=error
   with response:
    row.update(status=response.status,verifiedPublicTls=True)
    payload=response.read(65536)
    try:row['body']=json.loads(payload)
    except ValueError:row['nonJsonResponse']=True
  except (OSError,ValueError):row.update(unavailable=True)
  row['latencySeconds']=time.monotonic()-tick;key=str(row.get('status','unavailable'));statuses[key]=statuses.get(key,0)+1
  stream.write(json.dumps(row)+'\n');stream.flush();os.fsync(stream.fileno());count+=1
  time.sleep(max(.05,5-(time.monotonic()-tick)))
with a.output.with_suffix('.summary.json').open('x',encoding='utf-8') as stream:
 json.dump({'samples':count,'durationSeconds':time.monotonic()-start,'maxGapSeconds':maxGap,'statuses':statuses,
  'continuousGapBoundSatisfied':maxGap<=15,'capabilityExported':False},stream,indent=2)
