import test from 'node:test';
import assert from 'node:assert/strict';
import {progressPolicy} from '../availability.mjs';
const genesis='a'.repeat(64),startedUtcUnix=1700000000;
test('quiet chain closes at ten minutes, remains closed after progress and restart',()=>{
 let now=startedUtcUnix*1000;const wallNow=()=>now;
 const p=progressPolicy({genesis,startedUtcUnix,wallNow});p.observe(1,genesis);
 now+=120000;assert.equal(p.snapshot().lastBlockAgeSeconds,120);assert.equal(p.snapshot().closed,false);
 p.observe(1,genesis);now+=479999;assert.equal(p.snapshot().closed,false);
 now++;assert.equal(p.snapshot().closed,true);assert.equal(p.snapshot().reason,'chain_stalled');
 p.observe(2,'b'.repeat(64));assert.equal(p.snapshot().closed,true);
 const restarted=progressPolicy({genesis,startedUtcUnix,wallNow,restored:p.snapshot()});assert.equal(restarted.snapshot().closed,true);
});
test('real canonical change refreshes age; wrong state or regressed clock fails closed',()=>{
 let now=startedUtcUnix*1000;const wallNow=()=>now;
 const p=progressPolicy({genesis,startedUtcUnix,wallNow});p.observe(1,genesis);now+=180000;
 assert.equal(p.observe(2,'b'.repeat(64)).lastBlockAgeSeconds,0);now--;
 assert.equal(p.snapshot().reason,'clock_regressed');
 assert.throws(()=>progressPolicy({genesis,startedUtcUnix,restored:{...p.snapshot(),genesis:'c'.repeat(64)},wallNow}));
});

test('quiet-interval rollback and restart cannot renew admission; frozen wall uses monotonic age',()=>{
 let wall=startedUtcUnix*1000,mono=0;
 const args={genesis,startedUtcUnix,wallNow:()=>wall,monotonicNow:()=>mono};
 const p=progressPolicy(args);p.observe(1,genesis);
 wall+=500000;mono+=500000;const saved=p.snapshot();assert.equal(saved.closed,false);
 wall-=400000;assert.equal(p.snapshot().reason,'clock_regressed');
 assert.equal(progressPolicy({...args,restored:saved}).snapshot().reason,'clock_regressed');
 wall=startedUtcUnix*1000;mono=0;const frozen=progressPolicy(args);frozen.observe(1,genesis);
 mono=600000;assert.equal(frozen.snapshot().reason,'chain_stalled');
});
