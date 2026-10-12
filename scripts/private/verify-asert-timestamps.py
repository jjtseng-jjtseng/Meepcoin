"""Bounded candidate-only timestamp study; no native production rule changes."""
import argparse,hashlib,json,os,resource,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--include',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
source=Path(__file__).parent;out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
def limits():
 os.nice(10);resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def run(label,argv,seconds):
 with (out/(label+'.stdout')).open('xb') as stdout,(out/(label+'.stderr')).open('xb') as stderr:
  subprocess.run(argv,stdout=stdout,stderr=stderr,timeout=seconds,preexec_fn=limits,check=True)
binary=out/'timestamp-study'
run('build',['g++','-std=c++14','-O2','-I'+str(a.include.resolve(strict=True)),str(source/'asert-timestamps.cpp'),'-o',str(binary)],120)
run('study',[str(binary)],240)
rows=[json.loads(x) for x in (out/'study.stdout').read_text().splitlines()];assert len(rows)==48
result={'status':'UNACTIVATED_TIMESTAMP_SENSITIVITY_STUDY_COMPLETE','rows':rows,
 'sourceSha256':{name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in ['asert-candidate.hpp','asert-timestamps.cpp']},
 'limits':['All miners publish immediately; no withholding or variable hash power','Single reference clock; +/- peer clock skew and network reachability not modeled',
 'Fixed trusted anchor at height/time zero with difficulty 1000; not launch or activation behavior','Wilson bound covers the stated finite model, not real network attack probability',
 'Any one-year gap or int64 clock overflow stops that seed and counts as failure; partial steady mean is invalid when horizonFailures>0','No native production call sites or promotion']}
(out/'RESULT.json').open('x').write(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'rows':len(rows)}),flush=True)
