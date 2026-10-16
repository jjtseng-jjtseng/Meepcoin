"""Own the finite browser and UI driver through two live-pipe guardians."""
import argparse,json,os,signal,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
import guarded
p=argparse.ArgumentParser(description=__doc__)
for label in ('output','data','node','browser','playwright-module'):p.add_argument('--'+label,type=Path,required=True)
p.add_argument('--wallet-name',default='rehearsal-original',help='Unique disposable wallet; never overwrite an earlier failed attempt')
a=p.parse_args();os.umask(0o077);root=a.output.resolve(strict=True);profile=root/'fresh-browser-profile';profile.mkdir(mode=0o700)
children=[];logs=[]
def spawn(label,argv):
 log=(root/(label+'.log')).open('xb');logs.append(log)
 child=guarded.Child(argv,output=log,receipt=root/(label+'-GUARD_STOPPED.json'),seconds=4200);children.append(child);return child
def stop(*_):raise KeyboardInterrupt()
for signum in (signal.SIGTERM,signal.SIGINT):signal.signal(signum,stop)
passed=False
try:
 browser=spawn('browser',[str(a.browser.resolve(strict=True)),'--headless=new','--no-first-run','--disable-background-networking',
  '--disable-component-update','--disable-sync','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0','--user-data-dir='+str(profile),'about:blank'])
 end=time.monotonic()+30;active=profile/'DevToolsActivePort'
 while not active.exists():assert browser.poll() is None and time.monotonic()<end;time.sleep(.1)
 port=int(active.read_text().splitlines()[0]);assert 1024<=port<=65535
 cdp=root/'CDP_PRIVATE.json';cdp.write_text(json.dumps({'endpoint':'http://127.0.0.1:'+str(port)}))
 driver=spawn('driver',[str(a.node.resolve(strict=True)),str(Path(__file__).with_suffix('.mjs')),'--output',str(root),'--data',str(a.data.resolve(strict=True)),
  '--cdp-file',str(cdp),'--playwright-module',str(a.playwright_module.resolve(strict=True)),'--wallet-name',a.wallet_name])
 end=time.monotonic()+4100
 while driver.poll() is None:
  assert browser.poll() is None and time.monotonic()<end,'Owned browser exited or finite deadline elapsed';time.sleep(.2)
 assert driver.returncode==0,'Browser UI driver failed; inspect sanitized receipt';passed=True
except KeyboardInterrupt:pass
finally:
 for signum in (signal.SIGTERM,signal.SIGINT):signal.signal(signum,signal.SIG_IGN)
 outcomes=[]
 for child in reversed(children):
  outcome={'receipt':child.receipt.name,'ownedGroupDrained':False}
  try:
   if child.poll() is None:child.terminate()
   outcome['nativeExitCode']=child.wait(timeout=45)
   receipt=json.loads(child.receipt.read_text())
   outcome['ownedGroupDrained']=receipt.get('ownedGroupDrained') is True and receipt.get('error') is None
  except Exception as error:outcome['cleanupError']=type(error).__name__
  outcomes.append(outcome)
 for log in logs:
  try:log.close()
  except OSError:pass
 drained=all(item['ownedGroupDrained'] for item in outcomes) and bool(outcomes)
 result={'status':'BROWSER_OWNERSHIP_DRAIN_PASS' if drained else 'BROWSER_OWNERSHIP_DRAIN_FAILED',
  'uiDriverPassed':passed,'browserAndDriverGroupsDrained':drained,'children':outcomes,'sandboxDisabled':False}
 with (root/'BROWSER_OWNERSHIP_STOPPED.json').open('x') as out:json.dump(result,out,indent=2);out.write('\n')
 if not drained:raise RuntimeError('Owned browser group did not establish its drain')
