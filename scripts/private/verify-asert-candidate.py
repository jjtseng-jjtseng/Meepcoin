"""Independent 100k-case integer oracle and bounded 1000-seed candidate study."""
import argparse,hashlib,json,os,random,resource,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--include',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
source=Path(__file__).parent;out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
def limits():
 os.nice(10);resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def run(label,argv,stdin=None):
 with (out/(label+'.stdout')).open('xb') as stdout,(out/(label+'.stderr')).open('xb') as stderr:
  r=subprocess.run(argv,input=stdin,stdout=stdout,stderr=stderr,timeout=180,preexec_fn=limits)
 r.check_returncode();return (out/(label+'.stdout')).read_text()
binary=out/'asert-study'
run('build',['g++','-std=c++14','-O2','-I'+str(a.include.resolve(strict=True)),str(source/'asert-study.cpp'),'-o',str(binary)])
rng=random.Random(0x4153455254);queries=[];expected=[]
maximum=2**128-1
for i in range(100000):
 anchor=[1,1000,maximum,maximum//2][i%4] if i<100 else rng.randrange(1,maximum+1)
 h=rng.choice([0,1,2**64-1,rng.randrange(1000000)])
 elapsed=rng.choice([-2**63,2**63-1,rng.randrange(-10000000,10000000)])
 half=rng.choice([1,900,1800,3600,7200,2**32-1])
 queries.append(f'{anchor} {h} {elapsed} {half}')
 numerator=(h*60-elapsed)*65536;exponent=(abs(numerator)//half)*(-1 if numerator<0 else 1)
 if exponent<=-145*65536:d=1
 elif exponent>=128*65536:d=maximum
 else:
  shifts,frac=divmod(exponent,65536)
  factor=65536+((195766423245049*frac+971821376*frac**2+5127*frac**3+2**47)>>48)
  scaled=anchor*factor;scaled=scaled<<shifts if shifts>=0 else scaled>>-shifts
  d=max(1,min(maximum,scaled>>16))
 expected.append(d)
raw=('\n'.join(queries)+'\n').encode();(out/'INPUT.txt').open('xb').write(raw)
actual=[int(x) for x in run('oracle',[str(binary)],raw).splitlines()];assert actual==expected
rows=[json.loads(x) for x in run('study',[str(binary),'study']).splitlines()]
result={'status':'UNACTIVATED_ASERT_CANDIDATE_INTEGER_ORACLE_PASS','cases':len(actual),'study':rows,
 'sourceSha256':{name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in ['asert-candidate.hpp','asert-study.cpp']},
 'limits':['No production call sites or activation','Difficulty-polynomial adaptation, not BCH target/nBits consensus equivalence','Poisson honest stable/piecewise-rate model; future bounds/minority timestamps/clockskew/reorg not modeled here','Recovery: expected interval <=90s for 30 consecutive blocks; CI on steady mean uses independent seed means','Parameter choice not promoted by this study']}
(out/'RESULT.json').open('x').write(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
