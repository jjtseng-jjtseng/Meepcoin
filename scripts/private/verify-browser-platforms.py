"""Real-browser KAT and resource observation. No installed user profiles or network mining."""
import argparse,hashlib,http.server,json,os,platform,resource,signal,subprocess,threading,time,uuid
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--product',type=Path,required=True);p.add_argument('--run-dir',type=Path,required=True)
p.add_argument('--browser',action='append',required=True);p.add_argument('--max-rss-mib',type=int,default=1024);a=p.parse_args()
assert 256<=a.max_rss_mib<=4096
product=a.product.resolve(strict=True);out=a.run_dir.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
artifacts={name:(product/'meepow/wasm'/name).read_bytes() for name in ['meepow.mjs','meepow.wasm']}
os.umask(0o077);secret=uuid.uuid4().hex;report=None;children=[];receipts=[];started=time.monotonic();requests=[]
vectors=[x.split() for x in (product/'meepow/vectors/vectors_v2.txt').read_text().strip().splitlines()]
page="""<!doctype html><meta charset="utf-8"><title>MeepCoin platform qualification</title><p id="status">Running frozen v2 vectors</p><script type="module">
try {
 const stage=async value=>fetch('/stage',{method:'POST',headers:{'Content-Type':'application/json','X-Probe':SECRET},body:JSON.stringify({stage:value})});
 await stage('before-module');const {default:createModule}=await import('/meepow.mjs');await stage('module-imported');
 const module=await createModule(),vectors=VECTORS;
 await stage('module-ready');
 const ptr=module._malloc(vectors.length*32);module.ccall('meep_v2_hashes',null,['number','number','number'],[4,vectors.length,ptr]);
 await stage('hashes-complete');
 const rows=vectors.map(v=>({nonce:Number(v[2]),expected:v[3],actual:[...module.HEAPU8.slice(ptr+Number(v[2])*32,ptr+Number(v[2])*32+32)].map(x=>x.toString(16).padStart(2,'0')).join('')}));
 module._free(ptr);const perHashMs=module.ccall('meep_v2_bench','number',['number','number'],[4,50]);
 const result={status:rows.every(r=>r.expected===r.actual)?'BROWSER_NATIVE_V2_KAT_PASS':'FAIL',rows,perHashMs,wasmHeapBytes:module.HEAPU8.length,userAgent:navigator.userAgent,hardwareConcurrency:navigator.hardwareConcurrency};
 await fetch('/report',{method:'POST',headers:{'Content-Type':'application/json','X-Probe':SECRET},body:JSON.stringify(result)});document.getElementById('status').textContent=result.status;
}catch(e){await fetch('/report',{method:'POST',headers:{'Content-Type':'application/json','X-Probe':SECRET},body:JSON.stringify({status:'FAIL',error:String(e)})});}
</script>""".replace('VECTORS',json.dumps(vectors)).replace('SECRET',json.dumps(secret)).encode()
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  requests.append({'method':'GET','path':self.path,'elapsed':time.monotonic()-started})
  routes={'/':(page,'text/html'),'/meepow.mjs':(artifacts['meepow.mjs'],'text/javascript'),
   '/meepow.wasm':(artifacts['meepow.wasm'],'application/wasm')}
  if self.path not in routes:self.send_error(404);return
  data,kind=routes[self.path];self.send_response(200);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
 def do_POST(self):
  global report
  if self.path not in ['/report','/stage'] or self.headers.get('X-Probe')!=secret:self.send_error(403);return
  n=int(self.headers.get('Content-Length','0'))
  if not 0<n<=65536:self.send_error(413);return
  data=json.loads(self.rfile.read(n));requests.append({'method':'POST','path':self.path,'data':data if self.path=='/stage' else {'status':data.get('status')},'elapsed':time.monotonic()-started})
  if self.path=='/report':report=data
  self.send_response(204);self.end_headers()
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
def limits():
 # Browsers reserve large virtual arenas; physical usage is bounded by the owned-group RSS watchdog.
 os.nice(10);resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(128*1024**2,128*1024**2))
def group(pid):
 if platform.system()=='Darwin':
  # ps reports KiB RSS on macOS. Filter the newly created process group; never
  # address the user's existing browser instance or profile.
  rows=subprocess.check_output(['ps','-axo','pid=,pgid=,rss='],text=True)
  return [(int(p),int(rss)*1024) for p,pgid,rss in (line.split() for line in rows.splitlines()) if int(pgid)==pid]
 values=[]
 for path in Path('/proc').iterdir():
  if not path.name.isdigit():continue
  try:
   text=(path/'stat').read_text();fields=text[text.rfind(')')+2:].split()
   if int(fields[2])!=pid:continue
   status=(path/'status').read_text();rss=next((int(x.split()[1])*1024 for x in status.splitlines() if x.startswith('VmRSS:')),0)
   values.append((int(path.name),rss))
  except (OSError,ValueError):pass
 return values
def stop(sig,frame):raise KeyboardInterrupt()
for sig in [signal.SIGTERM,signal.SIGINT,signal.SIGHUP,signal.SIGALRM]:signal.signal(sig,stop)
signal.alarm(180*len(a.browser))
results=[]
try:
 for index,browser in enumerate(a.browser):
  report=None;profile=out/('profile-'+str(index));profile.mkdir();log=(out/('browser-'+str(index)+'.log')).open('xb')
  kind='firefox' if 'firefox' in browser else 'chromium'
  if kind=='firefox':
   (profile/'user.js').write_text('user_pref("browser.shell.checkDefaultBrowser", false);\nuser_pref("browser.aboutwelcome.enabled", false);\nuser_pref("browser.startup.homepage_override.mstone", "ignore");\nuser_pref("datareporting.policy.dataSubmissionEnabled", false);\nuser_pref("network.proxy.type", 0);\n')
  flags=['--headless','--no-remote','--new-instance','--profile',str(profile)] if kind=='firefox' else ['--headless=new','--disable-gpu','--disable-extensions','--no-proxy-server','--no-first-run','--disable-background-networking','--disable-component-update','--disable-sync','--user-data-dir='+str(profile)]
  process=subprocess.Popen([browser,*flags,'http://127.0.0.1:'+str(server.server_port)+'/'],cwd=out,env={**os.environ,'MOZ_CRASHREPORTER_DISABLE':'1'},stdout=log,stderr=subprocess.STDOUT,start_new_session=True,preexec_fn=limits)
  children.append(process);deadline=time.monotonic()+150;peak=0
  try:
   while time.monotonic()<deadline and report is None:
    rss=sum(x[1] for x in group(process.pid));peak=max(peak,rss)
    assert rss<=a.max_rss_mib*1024**2,'Owned browser group exceeded RSS budget'
    assert process.poll() is None,'Browser exited before reporting'
    time.sleep(.2)
   assert report is not None,'Browser report deadline exceeded'
   assert report['status']=='BROWSER_NATIVE_V2_KAT_PASS',report
   result={**report,'browser':browser,'peakOwnedGroupRssBytes':peak,'hashes':len(vectors)}
   results.append(result);(out/(kind+'-RESULT.json')).open('x').write(json.dumps(result,indent=2)+'\n')
  finally:
   try:os.killpg(process.pid,signal.SIGTERM)
   except ProcessLookupError:pass
   try:process.wait(timeout=15)
   except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=10)
   until=time.monotonic()+10
   while group(process.pid) and time.monotonic()<until:time.sleep(.1)
   receipts.append({'pid':process.pid,'browser':browser,'exitCode':process.returncode,'ownedGroupEmpty':not group(process.pid)})
   log.close()
 result={'status':'REAL_BROWSER_PLATFORM_KATS_PASS','results':results,'wasmSha256':hashlib.sha256((product/'meepow/wasm/meepow.wasm').read_bytes()).hexdigest(),
  'rssBudgetMiB':a.max_rss_mib,'limits':['Frozen v2 API KAT; does not replace real daemon block acceptance','Short bounded browser resource observation; not a thermal, battery or mobile qualification']}
 (out/'RESULT.json').open('x').write(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'browsers':len(results)}),flush=True)
finally:
 signal.alarm(0);server.shutdown();server.server_close();thread.join(timeout=5)
 (out/'CLEANUP.json').open('x').write(json.dumps({'processes':receipts,'elapsedSeconds':time.monotonic()-started},indent=2)+'\n')
 (out/'REQUESTS.json').open('x').write(json.dumps(requests,indent=2)+'\n')
 assert all(x['ownedGroupEmpty'] for x in receipts),'Owned browser group cleanup incomplete'
