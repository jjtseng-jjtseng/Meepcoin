// Real TLS, Wasm client, Wasm server, native CLI and actual daemon canonical readback.
// The Python controller owns fresh daemon/wallet processes and a 300-second outer deadline.
import {readFile,writeFile} from 'node:fs/promises';
import https from 'node:https';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createTestnetService} from '../../pool/private/testnet_service.mjs';
import createModule from '../../meepow/wasm/meepow.mjs';
import {createV2HasherForContext} from '../../web-miner/lib/shared/wasm_hasher.js';
const config=JSON.parse(await readFile(process.argv[2],'utf8'));
const tls={key:await readFile(config.keyFile),cert:await readFile(config.certFile)};
const advertisedOrigin=config.listenPort?'https://localhost:'+config.listenPort:'https://localhost';
const tokens=config.addresses.map(()=>randomBytes(32).toString('hex'));
const service=await createTestnetService({endpoint:config.endpoint,nativeCommand:[config.nativeHash],tls,origin:advertisedOrigin,port:config.listenPort??0,
 expectedNetwork:config.network??'fakechain',expectedGenesisHash:config.genesisHash,expectedVersion:config.version,
 dataDirectory:config.dataDirectory,sessions:config.addresses.map((walletAddress,i)=>({walletAddress,token:tokens[i]})),maxJobs:config.blockCount?32:4,startsPerMinute:config.blockCount?32:6,requestsPerMinute:config.blockCount?600:120});
const rows=[];let clientModule;const createClient=()=>clientModule??=createModule();
function request(path,token,method='GET',data) {
 return new Promise((ok,bad)=>{
  const body=data===undefined?null:Buffer.from(JSON.stringify(data));
  const q=https.request({hostname:'127.0.0.1',port:service.port,servername:'localhost',ca:tls.cert,agent:false,path,method,
   headers:{Host:new URL(advertisedOrigin).host,Origin:advertisedOrigin,'X-Meep-Session':token,...(body?{'Content-Type':'application/json','Content-Length':body.length}:{})}},r=>{
   let chunks=[],bytes=0;r.on('data',b=>{bytes+=b.length;if(bytes>2*1024**2)q.destroy(Error('reply limit'));else chunks.push(b);});
   r.on('error',bad);r.on('end',()=>ok({status:r.statusCode,body:JSON.parse(Buffer.concat(chunks).toString())}));
  });q.on('error',bad);q.setTimeout(25000,()=>q.destroy(Error('TLS request deadline')));q.end(body);
 });
}
try {
 let readiness=await request('/readyz',tokens[0]);
 for(let retry=0;readiness.status!==200&&retry<20;retry++){await new Promise(ok=>setTimeout(ok,250));readiness=await request('/readyz',tokens[0]);}
 assert.equal(readiness.status,200,JSON.stringify(readiness.body));
 assert.equal((await request('/api/start','0'.repeat(64),'POST',{})).status,403);
 for(let sequence=0;sequence<(config.blockCount??tokens.length);sequence++) {
  const i=config.singleFirstSession!==undefined?(sequence===0?config.singleFirstSession:(sequence-1)%(tokens.length-1)):sequence%tokens.length;
  if(config.pauseAfter===sequence){await writeFile(config.miningReady,JSON.stringify({height:sequence+1})+'\n',{flag:'wx'});const end=Date.now()+120000;while(Date.now()<end){try{await readFile(config.transferReady);break;}catch{await new Promise(ok=>setTimeout(ok,100));}}assert(Date.now()<end,'transfer checkpoint timeout');}
  const started=await request('/api/start',tokens[i],'POST',{});assert.equal(started.status,200,JSON.stringify(started.body));
  const job=started.body;const client=await createV2HasherForContext(createClient,{
   epochKey:Buffer.from(job.epochKeyHex,'hex'),seedHash:Buffer.from(job.seedHashHex,'hex'),
   height:job.height,template:Buffer.from(job.hashingTemplateHex,'hex')});
  let nonce=null,hash;
  try {
   const deadline=Date.now()+60000;
   for(let n=job.nonceStart;n<job.nonceStart+job.nonceRange&&Date.now()<deadline;n++) {
    const h=client.hashOne(n);const value=BigInt('0x'+Buffer.from(h).reverse().toString('hex'));
    if(value*BigInt(job.networkDifficulty)<(1n<<256n)){nonce=n;hash=Buffer.from(h).toString('hex');break;}
   }
  }finally{client.free();}
  assert.notEqual(nonce,null,'No candidate within bounded window');
  const candidate=await request('/api/candidate',tokens[i],'POST',{jobId:job.jobId,issuanceId:job.issuanceId,
   workerId:job.workerId,runGeneration:job.runGeneration,nonce});
  assert.equal(candidate.status,200,JSON.stringify(candidate.body));assert.equal(candidate.body.reason,'verified_complete',JSON.stringify(candidate.body));
  const state=(await request('/api/status',tokens[i])).body;
  assert.equal(state.payoutAddress,config.addresses[i]);assert(state.events.some(x=>x.type==='block_accepted'));
  rows.push({session:i,majorVersion:job.majorVersion,height:job.height,difficulty:job.networkDifficulty,nonceStart:job.nonceStart,nonce,hash,
   result:candidate.body,serverHashCalls:state.serverHashCalls});
 }
 assert.notEqual(rows[0].nonceStart,rows[1].nonceStart);
 if(config.browserReady){await writeFile(config.browserReady,JSON.stringify({port:service.port,tokens,origin:advertisedOrigin})+'\n',{flag:'wx'});const end=Date.now()+180000;while(Date.now()<end){try{await readFile(config.browserDone);break;}catch{await new Promise(ok=>setTimeout(ok,100));}}assert(Date.now()<end,'browser checkpoint timeout');}
 const newToken=await service.rotate(tokens[0]);
 assert.equal((await request('/api/status',tokens[0])).status,403);
 assert.equal((await request('/api/status',newToken)).body.running,false);
 const result={status:'REAL_TLS_NATIVE_CANONICAL_MINING_PASS',rows,certificateValidated:true,distinctNonceRanges:true,
  rotatedCapabilityRejected:true,limits:[config.network==='testnet'?'Private loopback v17 testnet with natural difficulty':'Private fakechain fixed difficulty 20','Node Wasm client; actual browser acceptance covered separately','No public deployment or DNS/TLS issuance']};
 await writeFile(config.output,JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify({status:result.status,blocks:rows.length}));
}finally{await service.close();}
