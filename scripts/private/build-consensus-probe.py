"""Link the study against an already qualified build; no native source mutation."""
import argparse,hashlib,json,os,resource,shlex,shutil,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();build=a.build.resolve(strict=True);out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
source=Path(__file__).with_name('consensus-probe.cpp').resolve(strict=True)
shutil.copyfile(source,out/'consensus-probe.cpp')
shutil.copyfile(__file__,out/'build-consensus-probe.py')
flags=(build/'src/cryptonote_basic/CMakeFiles/cryptonote_basic.dir/flags.make').read_text()
def line(prefix):return shlex.split(next(x.split(' = ',1)[1] for x in flags.splitlines() if x.startswith(prefix+' = ')))
def limits():
 os.nice(10);resource.setrlimit(resource.RLIMIT_AS,(4*1024**3,4*1024**3));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
commands=[]
def run(args,cwd,seconds):
 with (out/('command-'+str(len(commands))+'.log')).open('xb') as log:
  result=subprocess.run(args,cwd=cwd,stdout=log,stderr=subprocess.STDOUT,timeout=seconds,preexec_fn=limits)
 commands.append({'argv':args,'cwd':str(cwd),'exitCode':result.returncode});result.check_returncode()
obj=out/'consensus-probe.o'
run(['/usr/bin/c++',*line('CXX_DEFINES'),*line('CXX_INCLUDES'),*line('CXX_FLAGS'),'-c',str(source),'-o',str(obj)],build,120)
link=shlex.split((build/'src/daemon/CMakeFiles/daemon.dir/link.txt').read_text())
start=next(i for i,x in enumerate(link) if x.startswith('CMakeFiles/daemon.dir/') and x.endswith('.o'))
end=link.index('-o');link[start:end]=[str(obj)];link[link.index('-o')+1]=str(out/'consensus-probe')
run(link,build/'src/daemon',120)
receipt={'status':'PRODUCTION_LIBRARY_PROBE_LINKED','sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),'binarySha256':hashlib.sha256((out/'consensus-probe').read_bytes()).hexdigest(),'commands':commands,'limits':'Arithmetic/policy probe, not daemon acceptance or full integration'}
(out/'BUILD.json').open('x').write(json.dumps(receipt,indent=2)+'\n')
print(receipt['status'],flush=True)
