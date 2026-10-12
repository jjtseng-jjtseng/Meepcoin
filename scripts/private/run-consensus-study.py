"""Bounded production-function study with independent integer arithmetic checks."""
import argparse,hashlib,json,os,random,resource,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--probe',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();binary=a.probe.resolve(strict=True);out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
def limits():
 os.nice(10);resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def run(label,args,stdin=None):
 with (out/(label+'.stdout')).open('xb') as stdout,(out/(label+'.stderr')).open('xb') as stderr:
  r=subprocess.run([str(binary),*args],input=stdin,stdout=stdout,stderr=stderr,timeout=180,preexec_fn=limits)
 r.check_returncode();return (out/(label+'.stdout')).read_text()
rng=random.Random(0x4d454550);queries=[];expected=[]
for index in range(2048):
 n=[0,1,2,59,60,599,600,601,719,720,721,734,735][index%13]
 timestamps=[];work=[];t=rng.randrange(1790000000,1791000000);c=rng.randrange(1,2**80)
 for _ in range(n):
  t+=rng.randrange(0,121);c+=rng.randrange(1,10**12);timestamps.append(t);work.append(c)
 if index%3==0:rng.shuffle(timestamps)
 if index%17==0 and n:timestamps=[timestamps[0]]*n
 queries.append('difficulty '+str(n)+' '+' '.join(str(t)+' '+str(c) for t,c in zip(timestamps,work)))
 ts=sorted(timestamps[:720]);cw=work[:720];length=len(ts)
 if length<=1:expected.append(1);continue
 begin=0 if length<=600 else (length-600+1)//2;end=length if length<=600 else begin+600
 span=max(1,ts[end-1]-ts[begin]);total=cw[end-1]-cw[begin]
 expected.append((total*60+span-1)//span)
text='\n'.join(queries)+'\n';(out/'difficulty-input.txt').open('x').write(text)
got=[int(x) for x in run('difficulty',[],text.encode()).splitlines()]
assert got==expected,'native difficulty differs from independent integer oracle'
monetary=json.loads(run('monetary',['monetary']))
supply=2500000000000000000;tail=12500000000
for row in monetary['rewards']:
 generated=int(row['generated']);weight=row['weight'];base=max(0 if generated>=supply else (supply-generated)>>21,tail)
 assert row['accepted']==(weight<=600000)
 if row['accepted']:assert int(row['reward'])==base*weight*(600000-weight)//(300000**2) if weight>300000 else int(row['reward'])==base
valid={'0':0,'0.00000000001':1,'1':100000000000,'1.00000000000':100000000000,'184467440.73709551615':2**64-1}
for row in monetary['amounts']:
 assert row['accepted']==(row['input'] in valid)
 if row['accepted']:assert int(row['atomic'])==valid[row['input']]
# Independent main-emission iteration; after the floor starts, skip ahead algebraically.
g=0;h=0;total=0;tail_height=None;checkpoints={x['height']:x for x in monetary['emission']}
while True:
 h+=1;reward=(supply-g)>>21
 if reward<=tail:tail_height=h;break
 g+=reward;total+=reward
 if h in checkpoints:assert int(checkpoints[h]['totalAtomic'])==total
assert monetary['firstTailHeight']==tail_height
cross=h+(supply-total+tail-1)//tail-1
assert monetary['supplyParameterReachedHeight']==cross
for height,row in checkpoints.items():
 if height>=h:assert int(row['totalAtomic'])==total+(height-h+1)*tail
policy=[json.loads(x) for x in run('policy',['policy']).splitlines()]
stable=next(x for x in policy if x['scenario']=='stable-mature')
drop=next(x for x in policy if x['scenario']=='ninety-percent-departure')
criteria={'stableMean45To90':45<=stable['meanSeconds']<=90,
 'departureObservedHourGapFrequencyBelowOnePercent':drop['runsWithHourGap']/drop['seeds']<0.01,
 'departureAllSeedsRecoverWithin180Blocks':drop['recoveredWithin180']==drop['seeds']}
result={'schema':'meepcoin-native-policy-study/1','status':'POLICY_CRITERIA_PASS_EXPLORATORY' if all(criteria.values()) else 'CURRENT_POLICY_PUBLIC_TESTNET_CRITERIA_FAILED',
 'nativeDifficultyOracleCases':len(got),'nativeMonetaryBoundaryCases':len(monetary['rewards'])+len(monetary['amounts']),
 'criteria':criteria,'monetary':monetary,'policy':policy,'probeSha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
 'limits':['Production-linked functions, not daemon or network acceptance','Poisson hash-arrival model with piecewise constant rate; no measured-browser availability distribution','32 deterministic seeds estimate observed frequencies, not a population bound below 1 percent','Median compression assumes all modeled timestamps controlled; it does not establish a minority attack','Model halts above one-year single gap or difficulty 1e12; this is reported, not passed']}
(out/'RESULT.json').open('x').write(json.dumps(result,indent=2)+'\n')
print(json.dumps({'status':result['status'],'criteria':criteria,'difficultyCases':len(got),'tailHeight':tail_height,'supplyParameterHeight':cross}),flush=True)
