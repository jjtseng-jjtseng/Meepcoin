"""Build the actual candidate Blockchain object against pinned qualified libraries; no old source or library mutation."""
import argparse,hashlib,json,os,resource,shlex,signal,subprocess,random
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--reuse-blockchain',type=Path);a=p.parse_args()
build=a.build.resolve(strict=True);src=a.input.resolve(strict=True);out=a.output.resolve();out.mkdir(mode=0o700,exist_ok=False);(out/'include/cryptonote_basic').mkdir(parents=True)
for n in ['blockchain.cpp','native-asert.cpp']:(out/n).write_bytes((src/n).read_bytes())
(out/'include/cryptonote_basic/meepcoin_asert.h').write_bytes((src/'meepcoin_asert.h').read_bytes())
flags=(build/'src/cryptonote_core/CMakeFiles/cryptonote_core.dir/flags.make').read_text()
home=Path(next(x.split('=',1)[1] for x in (build/'CMakeCache.txt').read_text().splitlines() if x.startswith('CMAKE_HOME_DIRECTORY:INTERNAL=')))
def line(prefix):return shlex.split(next(x.split(' = ',1)[1] for x in flags.splitlines() if x.startswith(prefix+' = ')))
def limits():
 os.nice(10);resource.setrlimit(resource.RLIMIT_AS,(4*1024**3,4*1024**3));resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(256*1024**2,256*1024**2))
receipts=[]
def run(name,cmd,cwd=None,stdin=None,seconds=300):
 with (out/(name+'.stdout')).open('xb') as log,(out/(name+'.stderr')).open('xb') as err:
  child=subprocess.Popen(cmd,cwd=cwd,stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,stdout=log,stderr=err,start_new_session=True,preexec_fn=limits)
  timedout=False
  try:child.communicate(stdin,timeout=seconds);code=child.returncode
  except subprocess.TimeoutExpired:timedout=True;os.killpg(child.pid,signal.SIGKILL);child.wait();code=child.returncode
  try:os.killpg(child.pid,0);empty=False
  except ProcessLookupError:empty=True
  receipts.append({'name':name,'pid':child.pid,'argv':cmd,'exitCode':code,'timeout':timedout,'ownedGroupEmpty':empty})
  (out/'CLEANUP.json').write_text(json.dumps(receipts,indent=2)+'\n')
  assert code==0 and not timedout and empty, name+' failed'
for name in ['blockchain','native-asert']:
 if name=='blockchain' and a.reuse_blockchain:
  previous=a.reuse_blockchain.resolve(strict=True)
  assert (previous/'blockchain.cpp').read_bytes()==(out/'blockchain.cpp').read_bytes()
  assert (previous/'include/cryptonote_basic/meepcoin_asert.h').read_bytes()==(out/'include/cryptonote_basic/meepcoin_asert.h').read_bytes()
  qualified=json.loads((previous/'CLEANUP.json').read_text())[0];assert qualified['name']=='compile-blockchain' and qualified['exitCode']==0 and qualified['ownedGroupEmpty']
  (out/'blockchain.o').write_bytes((previous/'blockchain.o').read_bytes());(out/'REUSED_OBJECT.json').write_text(json.dumps({'path':str(previous/'blockchain.o'),'sha256':hashlib.sha256((out/'blockchain.o').read_bytes()).hexdigest(),'originalReceipt':qualified},indent=2)+'\n');continue
 run('compile-'+name,['/usr/bin/c++',*line('CXX_DEFINES'),'-I'+str(out/'include'),'-I'+str(home/'src/cryptonote_core'),*line('CXX_INCLUDES'),*line('CXX_FLAGS'),'-c',str(out/(name+'.cpp')),'-o',str(out/(name+'.o'))],build,seconds=480)
link=shlex.split((build/'src/daemon/CMakeFiles/daemon.dir/link.txt').read_text());start=next(i for i,x in enumerate(link) if x.startswith('CMakeFiles/daemon.dir/') and x.endswith('.o'));end=link.index('-o');link[start:end]=[str(out/'native-asert.o'),str(out/'blockchain.o'),'-Wl,--wrap=time'];link[link.index('-o')+1]=str(out/'native-asert')
run('link',link,build/'src/daemon',seconds=120)
rng=random.Random(0x4d45455041534552);queries=[];expected=[]
for i in range(100000):
 h=rng.choice([0,1,2**64-1,rng.randrange(100000)]);t=rng.choice([0,2**64-1,rng.randrange(2**32)]);g=rng.choice([0,t,2**64-1,rng.randrange(2**32)])
 queries.append(f'{h} {t} {g}');n=(h*60-(t-g))*65536;e=(abs(n)//900)*(-1 if n<0 else 1)
 if e<=-145*65536:d=20
 elif e>=128*65536:d=2**128-1
 else:
  shifts,f=divmod(e,65536);factor=65536+((195766423245049*f+971821376*f*f+5127*f*f*f+2**47)>>48);v=20*factor;v=v<<shifts if shifts>=0 else v>>-shifts;d=max(20,min(2**128-1,v>>16))
 expected.append(d)
raw=('\n'.join(queries)+'\n').encode();(out/'INPUT.txt').write_bytes(raw)
run('integer-oracle',[str(out/'native-asert'),'arithmetic'],stdin=raw,seconds=120);actual=[int(x) for x in (out/'integer-oracle.stdout').read_text().splitlines()];assert actual==expected
run('lifecycle',[str(out/'native-asert'),str(out/'chains')],seconds=480)
rows=[]
for x in (out/'lifecycle.stdout').read_text().splitlines():
 try:r=json.loads(x)
 except ValueError:continue
 if isinstance(r,dict):rows.append(r)
assert rows[-1]['status']=='UNACTIVATED_V17_REAL_NATIVE_LIFECYCLE_PASS'
result={'status':rows[-1]['status'],'integerOracleCases':len(actual),'rows':rows,'sources':{n:hashlib.sha256((out/n).read_bytes()).hexdigest() for n in ['blockchain.cpp','native-asert.cpp','include/cryptonote_basic/meepcoin_asert.h']},'binarySha256':hashlib.sha256((out/'native-asert').read_bytes()).hexdigest(),'limits':['Real Blockchain/LMDB and production PoW with FAKECHAIN v17 test schedule','Only time() is wrapped for exact local-clock replay','Every shipped network remains v16; no public network activated']}
(out/'RESULT.json').open('x').write(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'integerCases':len(actual),'rows':len(rows)}),flush=True)
