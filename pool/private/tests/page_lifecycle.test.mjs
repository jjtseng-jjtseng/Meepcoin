import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
const code=await readFile(new URL('../../../web-miner/private/app.js',import.meta.url),'utf8');
const flush=async()=>{for(let i=0;i<4;i++)await new Promise(ok=>setImmediate(ok));};
function page(){
 const elements=new Map();const listeners={},winListeners={},requests=[],workers=[];
 const document={hidden:false,getElementById(id){if(!elements.has(id))elements.set(id,{textContent:'',disabled:false,classList:{add(){},remove(){}}});return elements.get(id);},addEventListener:(n,f)=>listeners[n]=f};
 const window={addEventListener:(n,f)=>winListeners[n]=f};
 class Worker{constructor(){this.messages=[];this.terminated=false;workers.push(this);}postMessage(m){this.messages.push(m);}terminate(){this.terminated=true;}}
 const fetch=(url,options)=>{if(url==='/api/status')return Promise.resolve({ok:true,json:async()=>({payoutAddress:'test',running:false,generation:0})});
  const req={path:url.split('/').pop(),data:JSON.parse(options.body),options};requests.push(req);
  if(req.path==='stop')return Promise.resolve({ok:true,json:async()=>({})});
  return new Promise(ok=>{req.resolve=data=>ok({ok:true,json:async()=>data});});};
 vm.runInNewContext(code,{document,window,fetch,Worker,URLSearchParams,location:{hash:'#session=test'}});
 return {window,document,workers,requests,click:id=>document.getElementById(id).onclick(),
  hidden(value){document.hidden=value;listeners.visibilitychange();},hide(){winListeners.pagehide();},
  element:id=>document.getElementById(id)};
}
const job=gen=>({runGeneration:gen,height:'4',networkDifficulty:'20',jobId:'job-'+gen,nonceStart:0,nonceRange:8192});
test('Idle page does not create a worker or mining request',async()=>{const p=page();await flush();assert.equal(p.workers.length,0);assert.equal(p.requests.length,0);});
test('Out-of-order old start cannot overwrite the live generation used by Stop',async()=>{
 const p=page();await flush();p.click('start');const a=p.requests.at(-1);p.click('stop');p.click('start');const b=p.requests.at(-1);
 b.resolve(job(2));await flush();assert.equal(p.workers.length,1);
 a.resolve(job(1));await flush();assert.equal(p.requests.at(-1).data.generation,1);
 p.click('stop');await flush();assert.equal(p.requests.at(-1).data.generation,2);assert.equal(p.workers[0].terminated,true);assert.equal(p.window.meepPrivate.workerCount,0);
});
test('Pagehide invalidates a pending start before its response can create a worker',async()=>{
 const p=page();await flush();p.click('start');const pending=p.requests.at(-1);p.hide();pending.resolve(job(1));await flush();
 assert.equal(p.workers.length,0);assert.equal(p.requests.at(-1).data.generation,1);
});
test('Hidden tab stops locally and returning never rearms mining',async()=>{
 const p=page();await flush();p.click('start');p.requests.at(-1).resolve(job(1));await flush();
 p.hidden(true);await flush();assert.equal(p.window.meepPrivate.workerCount,0);assert.equal(p.requests.at(-1).data.generation,1);
 const count=p.requests.length;p.hidden(false);await flush();assert.equal(p.requests.length,count);assert.equal(p.workers.length,1);
});
test('Wrong-generation worker messages cannot start search or submit candidates',async()=>{
 const p=page();await flush();p.click('start');p.requests.at(-1).resolve(job(7));await flush();const w=p.workers[0];
 await w.onmessage({data:{ev:'ready',gen:6}});await w.onmessage({data:{ev:'found',gen:6,nonce:0}});
 assert.equal(w.messages.length,1);assert.equal(p.requests.filter(r=>r.path==='candidate').length,0);
});
test('Late candidate from stopped run remains tagged and cannot overwrite new run display',async()=>{
 const p=page();await flush();p.click('start');p.requests.at(-1).resolve(job(1));await flush();
 const promise=p.workers[0].onmessage({data:{ev:'found',gen:1,nonce:3}});const candidate=p.requests.at(-1);
 assert.equal(p.element('hashes').textContent,'4');p.click('stop');p.click('start');p.requests.at(-1).resolve(job(2));await flush();
 candidate.resolve({reason:'verified_complete'});await promise;await flush();
 assert.equal(p.element('result').textContent,'');assert.equal(p.window.meepPrivate.state,'Preparing');
 assert.equal(p.window.meepPrivate.events.find(e=>e.type==='candidate_result').generation,1);
});
