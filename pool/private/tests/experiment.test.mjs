import test from 'node:test';
import assert from 'node:assert/strict';
import {experimentWindow} from '../experiment.mjs';

const genesisUtcUnix=1791810000;
const experiment={genesisUtcUnix,startsUtcUnix:genesisUtcUnix+10,endsUtcUnix:genesisUtcUnix+3610};
test('Persisted experiment rejects stale, future, expired and overlong launches',()=>{
  for(const e of [{...experiment,startsUtcUnix:genesisUtcUnix+3601},
    {...experiment,endsUtcUnix:experiment.endsUtcUnix+1},
    {...experiment,endsUtcUnix:experiment.startsUtcUnix},
    {...experiment,genesisUtcUnix:NaN}])
    assert.throws(()=>experimentWindow(e,()=>experiment.startsUtcUnix*1000,()=>0));
  assert.throws(()=>experimentWindow(experiment,()=>experiment.startsUtcUnix*1000-1,()=>0),/not active/);
  assert.throws(()=>experimentWindow(experiment,()=>experiment.endsUtcUnix*1000,()=>0),/not active/);
  const lateRestart=experimentWindow(experiment,()=>(genesisUtcUnix+3601)*1000,()=>0);
  assert.equal(lateRestart.deadline,9000,'An active saved epoch can restart after the genesis launch deadline');
});
test('Restart preserves the absolute end; rotation cannot grant a new duration',()=>{
  let wall=experiment.startsUtcUnix*1000,mono=100;
  const first=experimentWindow(experiment,()=>wall,()=>mono);
  wall+=100000;mono+=100000;
  const second=experimentWindow(JSON.parse(JSON.stringify(experiment)),()=>wall,()=>0);
  assert.equal(first.deadline-mono,second.deadline);
  wall=experiment.endsUtcUnix*1000;
  assert.equal(first.open(),false);assert.equal(second.open(),false);
});
test('Wall rollback cannot extend the monotonic cap; expiry remains latched',()=>{
  let wall=experiment.startsUtcUnix*1000,mono=0;
  const epoch=experimentWindow(experiment,()=>wall,()=>mono);
  wall-=60000;mono=3600000;assert.equal(epoch.open(),false);
  wall=experiment.startsUtcUnix*1000;mono=0;assert.equal(epoch.open(),false);
  const forward=experimentWindow(experiment,()=>wall,()=>mono);
  wall=experiment.endsUtcUnix*1000;assert.equal(forward.open(),false);
  wall=experiment.startsUtcUnix*1000;assert.equal(forward.open(),false);
});
