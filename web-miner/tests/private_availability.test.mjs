import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('../private/app.js',import.meta.url),'utf8');
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const reply=(body,ok=true)=>({ok,json:async()=>body});
async function fixture(){
 const elements=new Map();let timer,gen=0,nextStatus,nextStop,initial=true;
 const document={hidden:false,addEventListener(){},getElementById(id){if(!elements.has(id))elements.set(id,{textContent:'',disabled:false,classList:{add(){},remove(){}}});return elements.get(id);}};
 const context=vm.createContext({document,location:{hash:'#session='+'a'.repeat(64)},URLSearchParams,AbortSignal,
  window:{addEventListener(){}},setInterval(fn){timer=fn;return 1;},clearInterval(){},
  Worker:class{postMessage(){}terminate(){this.terminated=true;}},
  async fetch(path){
   if(path==='/api/start')return reply({runGeneration:++gen,height:'1',networkDifficulty:'20'});
   if(path==='/api/stop'){if(nextStop){const held=nextStop;nextStop=null;return held.promise;}return reply({});}
   if(initial){initial=false;return reply({generation:0,running:false,payoutAddress:'public'});}
   assert(nextStatus,'Test must supply status response');return nextStatus.promise;
  }});
 vm.runInContext(source,context);await new Promise(ok=>setImmediate(ok));
 return {context,elements,poll(){nextStatus=deferred();timer();return nextStatus;},holdStop(){nextStop=deferred();return nextStop;},
  async start(){await vm.runInContext('start()',context);vm.runInContext("worker.onmessage({data:{ev:'ready',gen:generation}})",context);},
  async stop(){await vm.runInContext('stop()',context);},
  async settled(){await new Promise(ok=>setImmediate(ok));},
  workers(){return context.window.meepPrivate.workerCount;}};
}
for(const outcome of ['failure','non-ok','not-ready','stale-generation'])test('Old availability '+outcome+' cannot stop a newer explicit run',async()=>{
 const f=await fixture();await f.start();const old=f.poll();await f.stop();await f.start();
 if(outcome==='failure')old.reject(Error('old timeout'));
 else old.resolve(reply({running:false,generation:1,availability:{ready:outcome==='stale-generation',reason:'daemon_unavailable'}},outcome!=='non-ok'));
 await f.settled();assert.equal(f.workers(),1);assert.equal(f.elements.get('state').textContent,'Mining');
});
test('Current canceled native generation stops its browser worker without automatic restart',async()=>{
 const f=await fixture();await f.start();f.poll().resolve(reply({running:false,generation:1,availability:{ready:true}}));
 await f.settled();assert.equal(f.workers(),0);assert.equal(f.elements.get('state').textContent,'Run canceled');
 f.poll().resolve(reply({running:false,generation:1,availability:{ready:true}}));await f.settled();assert.equal(f.workers(),0);
});
test('Availability does not discard a canonical candidate response already in Checking',async()=>{
 const f=await fixture();await f.start();vm.runInContext("terminate();state('Checking','pending canonical response')",f.context);
 f.poll().resolve(reply({running:false,generation:1,availability:{ready:true}}));await f.settled();
 assert.equal(f.elements.get('state').textContent,'Checking');assert.equal(f.workers(),0);
});
test('An old canceled poll cannot stop a new run while its stop acknowledgement is pending',async()=>{
 const f=await fixture();await f.start();const ack=f.holdStop();
 f.poll().resolve(reply({running:false,generation:1,availability:{ready:false,reason:'daemon_unavailable'}}));await f.settled();
 assert.equal(f.workers(),0);await f.start();ack.resolve(reply({}));await f.settled();
 assert.equal(f.workers(),1);assert.equal(f.elements.get('state').textContent,'Mining');
});
