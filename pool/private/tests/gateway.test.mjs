import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {readFileSync} from 'node:fs';
import {createPrivateGateway} from '../server.mjs';
const vector=JSON.parse(readFileSync(new URL('../../../meepow/vectors/block_vectors_v16_devnet.json',import.meta.url))).vectors[1];
async function fixture(t, majorVersion=16) {
 let calls=0,release;
 const server=http.createServer(async(req,res)=>{
  let text='';for await(const c of req)text+=c;
  const request=JSON.parse(text);calls++;
  await new Promise(ok=>{release=ok; if(request.params?.wallet_address!=='2'.repeat(95))ok();});
  res.end(JSON.stringify({jsonrpc:'2.0',id:request.id,result:{status:'OK',height:vector.height,
   wide_difficulty:'0x1',seed_hash:vector.epoch_key,seed_height:0,prev_hash:'a'.repeat(64),reserved_offset:0,
   blocktemplate_blob:majorVersion.toString(16).padStart(2,'0')+vector.full_block_blob.slice(2),blockhashing_blob:majorVersion.toString(16).padStart(2,'0')+vector.block_hashing_blob.slice(2)}}));
 });
 await new Promise(ok=>server.listen(0,'127.0.0.1',ok));
 t.after(async()=>{release?.();server.closeAllConnections();await new Promise(ok=>server.close(ok));});
 const gateway=await createPrivateGateway({endpoint:'http://127.0.0.1:'+server.address().port+'/json_rpc',
  walletAddress:'2'.repeat(95),maxJobs:1,nativeFactory:()=>({hashOne:()=>{throw Error('unexpected native hash');}})});
 t.after(async()=>{release?.();await gateway.close();});
 const page=await fetch(gateway.origin);const cookie='unused';await page.text();
 const post=(path,data,extra={})=>fetch(gateway.origin+'/api/'+path,{method:'POST',
  headers:{'X-Meep-Session':gateway.sessionToken,Origin:gateway.origin,'Content-Type':'application/json',...extra},body:JSON.stringify(data)});
 return {gateway,cookie,post,calls:()=>calls,release:()=>release?.()};
}
test('Unauthenticated and cross-origin mining are refused before any RPC or hash',async t=>{
 const f=await fixture(t);
 let r=await fetch(f.gateway.origin+'/api/start',{method:'POST',headers:{Origin:f.gateway.origin,'Content-Type':'application/json'},body:'{}'});
 assert.equal(r.status,403);
 r=await f.post('start',{}, {Origin:'https://other.example'});assert.equal(r.status,403);
 r=await f.post('start',{}, {'Content-Type':'text/plain'});assert.equal(r.status,415);
 assert.equal(f.calls(),0);assert.equal(f.gateway.snapshot().serverHashCalls,0);
});
test('Stop during outstanding template load revokes startup; old generation cannot stop another run',async t=>{
 const f=await fixture(t);const pending=f.post('start',{});
 while(f.calls()===0)await new Promise(ok=>setTimeout(ok,5));
 assert.equal(f.gateway.snapshot().generation,1);
 assert.equal((await f.post('stop',{generation:0})).status,409);
 assert.equal((await f.post('stop',{generation:1})).status,200);
 f.release();const response=await pending;assert.equal(response.status,409);
 assert.equal(f.gateway.snapshot().running,false);assert.equal(f.gateway.snapshot().serverHashCalls,0);
 assert.equal((await f.post('start',{})).status,409); // finite attempted-job budget is spent
});
test('Schema/body limits and reload preserve idle intent',async t=>{
 const f=await fixture(t);
 assert.equal((await f.post('start',{target:'forged'})).status,400);
 const r=await f.post('start',{x:'a'.repeat(3000)});assert.equal(r.status,413);
 const page=await fetch(f.gateway.origin,{headers:{Cookie:f.cookie}});assert.equal(page.status,200);await page.text();
 assert.equal(f.calls(),0);assert.equal(f.gateway.snapshot().running,false);
});

test('Shutdown fences a start whose body finishes after close begins',async t=>{
 const f=await fixture(t);const u=new URL(f.gateway.origin);
 const request=http.request({hostname:u.hostname,port:u.port,path:'/api/start',method:'POST',headers:{
  Origin:f.gateway.origin,'X-Meep-Session':f.gateway.sessionToken,'Content-Type':'application/json','Content-Length':2}});
 const response=new Promise((ok,bad)=>{request.on('response',r=>{r.resume();r.on('end',()=>ok(r.statusCode));});request.on('error',bad);});
 request.flushHeaders();request.write('{');await new Promise(ok=>setTimeout(ok,20));
 const closing=f.gateway.close();request.end('}');assert.equal(await response,503);await closing;
 assert.equal(f.calls(),0);assert.equal(f.gateway.snapshot().running,false);assert.equal(f.gateway.snapshot().serverHashCalls,0);
});
test('Loopback cookies and first page visits cannot obtain API authorization',async t=>{
 const f=await fixture(t);
 const page=await fetch(f.gateway.origin);assert.equal(page.status,200);assert.equal(page.headers.get('set-cookie'),null);await page.text();
 const r=await fetch(f.gateway.origin+'/api/start',{method:'POST',headers:{Origin:f.gateway.origin,
  Cookie:'meep_session=stolen','Content-Type':'application/json'},body:'{}'});
 assert.equal(r.status,403);assert.equal(f.calls(),0);
});

test('MeepHash v17 candidate templates are admitted; unknown v18 templates fail closed',async t=>{
 const candidate=await fixture(t,17); const task=candidate.post('start',{});while(candidate.calls()===0)await new Promise(ok=>setTimeout(ok,5));candidate.release();const accepted=await task;assert.equal(accepted.status,200);
 const unknown=await fixture(t,18);const task2=unknown.post('start',{});while(unknown.calls()===0)await new Promise(ok=>setTimeout(ok,5));unknown.release();const rejected=await task2;assert.notEqual(rejected.status,200);
 assert.equal(unknown.gateway.snapshot().running,false);assert.equal(unknown.gateway.snapshot().serverHashCalls,0);
});
