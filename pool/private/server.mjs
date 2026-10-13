// One-user localhost mining gateway. The operator owns the daemon and native executable separately.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import { createDaemonRpc } from '../dev/daemon_rpc.mjs';
import { createLoopbackTransport } from '../dev/loopback_transport.mjs';
import { createRealTemplateJob, toClientJobMessage, hashingContextFor } from '../dev/real_template.mjs';
import { createBlockRun, createRunIntent } from '../dev/block_run.mjs';
import { createFatalLatch, createTemplateAuthority } from '../dev/run_guard.mjs';
import { verifyWasmIdentity, verifiedArtifactSnapshots, WASM_MJS_PATH } from '../dev/identity.mjs';
import { createStaticHandler, securityHeaders } from '../dev/static.mjs';
import { createV2HasherForContext } from '../../web-miner/lib/shared/wasm_hasher.js';
import { createNativeCli } from './native_cli.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const pageRoutes = new Map([
  ['/', [resolve(here, '../../web-miner/private/index.html'), 'text/html; charset=utf-8']],
  ['/private/app.js', [resolve(here, '../../web-miner/private/app.js'), 'text/javascript; charset=utf-8']],
  ['/private/style.css', [resolve(here, '../../web-miner/private/style.css'), 'text/css; charset=utf-8']],
]);
function fail(code, status=400) { const e = new Error(code); e.code=code; e.status=status; throw e; }
async function body(req) {
  if (req.headers['content-type'] !== 'application/json') fail('json_required',415);
  if(Number(req.headers['content-length']??0)>2048)fail('body_too_large',413);
  let bytes=0, chunks=[];
  for await (const chunk of req) {
    bytes+=chunk.length; if (bytes>2048) fail('body_too_large',413);
    chunks.push(chunk);
  }
  try { const x=JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!x || typeof x!=='object' || Array.isArray(x)) fail('bad_json');
    return x;
  } catch { fail('bad_json'); }
}
export async function createPrivateGateway({
  endpoint, walletAddress, nativeCommand, port=0, maxJobs=8, onEvent=()=>{},
  allocateNonceRange=()=>0,
  authorizeStart=()=>true,
  acquireCandidate=()=>()=>{},
  // Tests can replace native execution, but daemon transport and Wasm identity still use real modules.
  nativeFactory=job=>createNativeCli(nativeCommand,job),
}={}) {
  if (typeof walletAddress!=='string' || !/^[1-9A-HJ-NP-Za-km-z]{90,110}$/.test(walletAddress))
    throw new TypeError('a public mining address is required');
  if (!Number.isInteger(maxJobs) || maxJobs<1 || maxJobs>32) throw new TypeError('maxJobs 1..32');
  const identity=verifyWasmIdentity();
  const artifacts=verifiedArtifactSnapshots();
  const wasmBinary=identity.bytes.get('meepow/wasm/meepow.wasm');
  const transport=createLoopbackTransport({endpoint});
  const daemon=createDaemonRpc({endpoint,transport:transport.transport,limits:{timeoutMs:10000}});
  const latch=createFatalLatch();
  const authority=createTemplateAuthority({maxClaims:maxJobs});
  const intent=createRunIntent();
  const sessionToken=randomBytes(32).toString('hex');
  let origin, active=null, starting=false, candidateBusy=false, jobCount=0, hashCount=0;
  let candidateAttempts=0;
  let events=[], closing=false, startTask=null, lease=null, closeTask=null, issuedJobs=0,modulePromise;
  const record=ev=>{
    const clean=JSON.parse(JSON.stringify(ev,(_,v)=>typeof v==='bigint'?v.toString():v));
    events.push(clean); if(events.length>64)events.shift(); try { Promise.resolve(onEvent(clean)).catch(()=>{}); } catch { /* Observers cannot alter mining decisions. */ }
  };
  function snapshot() { return {mode:'private_localhost', running:intent.active, starting,
    generation:intent.generation, attemptedStarts:jobCount, jobsIssued:issuedJobs, serverHashCalls:hashCount, verifierFault:latch.code,
    payoutAddress:walletAddress, events:[...events]}; }
  async function release() {
    if (!active) return;
    const old=active; active=null;
    old.run.dispose(); await old.run.whenIdle(); old.wasm.free();
  }
  const staticHandler=createStaticHandler({wsOrigin:'',artifacts});
  const server=http.createServer(async(req,res)=>{
    function send(status,data,extra={}) {
      if(res.destroyed)return;
      if(res.headersSent){res.destroy();return;}
      const text=typeof data==='string'?data:JSON.stringify(data);
      res.writeHead(status,{...securityHeaders(''), 'Content-Type':'application/json',
        'Content-Length':Buffer.byteLength(text), ...extra}); res.end(text);
    }
    try {
      if(closing)fail('closing',503);
      if(req.headers.host !== new URL(origin).host)fail('bad_host',403);
      const path=new URL(req.url,origin).pathname;
      if(req.method==='GET' && path==='/') {
        const [file,type]=pageRoutes.get('/');
        return send(200,await readFile(file,'utf8'),{'Content-Type':type});
      }
      if(path.startsWith('/api/')) {
        if(req.headers['x-meep-session']!==sessionToken)fail('unauthorized',403);
        if(req.method==='GET' && path==='/api/status')return send(200,snapshot());
        if(req.method!=='POST')fail('method',405);
        if(req.headers.origin!==origin)fail('bad_origin',403);
        const data=await body(req);
        if(closing)fail('closing',503);
        if(path==='/api/stop') {
          if(Object.keys(data).join(',')!=='generation')fail('bad_schema');
          if(data.generation!==intent.generation)fail('stale_generation',409);
          intent.revokeCurrent('user_stop');
          record({type:'stopped',generation:intent.generation,
            disposition:active?.run.describeRevocation()??{state:'prevented'}});
          return send(200,snapshot());
        }
        if(path==='/api/start') {
          if(Object.keys(data).length)fail('bad_schema');
          if(!authorizeStart(req.headers['x-meep-revision']))fail('invitation_revoked',403);
          if(starting || candidateBusy || intent.active)fail('busy',409);
          if(jobCount>=maxJobs)fail('run_limit',409);
          latch.assertUsable();
          starting=true;jobCount++;candidateAttempts=0;
          const gen=intent.start();
          clearTimeout(lease);
          lease=setTimeout(()=>{if(intent.isLive(gen)){intent.revoke(gen,'lease_expired');record({type:'expired',generation:gen});}},120000);
          lease.unref();
          res.once('close',()=>{if(!res.writableEnded)intent.revoke(gen,'client_disconnected');});
          startTask=(async()=>{
            await release();
            if(closing || !intent.isLive(gen))fail('cancelled',409);
            const t=await daemon.getBlockTemplate({walletAddress});
            if(!intent.isLive(gen))fail('cancelled',409);
            const nonceStart=allocateNonceRange();
            if(!Number.isSafeInteger(nonceStart) || nonceStart<0 || nonceStart>0x100000000-8192)
              fail('nonce_space_exhausted',409);
            const job=createRealTemplateJob({
              height:t.height,wideDifficulty:t.wideDifficulty,seedHashHex:t.seedHashHex,
              blockhashingBlobHex:t.blockhashingBlobHex,blocktemplateBlobHex:t.blocktemplateBlobHex,
              ...(t.seedHeight===null?{}:{seedHeight:t.seedHeight}),nonceStart,nonceRange:8192,ttlMs:120000,
            });
            if(![16,17].includes(job.majorVersion))fail('requires_meep_hash_v16_or_v17',409);
            if(closing || !intent.isLive(gen))fail('cancelled',409);
            authority.publish(job);
            const {default:createModule}=await import(pathToFileURL(WASM_MJS_PATH));
            // Each gateway has one live context; reuse its module after release().
            // Repeated starts must not accumulate Wasm virtual-memory reservations.
            modulePromise??=createModule({wasmBinary});
            const wasm=await createV2HasherForContext(
              ()=>modulePromise,hashingContextFor(job));
            if(!intent.isLive(gen)) { wasm.free(); fail('cancelled',409); }
            let run;
            try {
              run=createBlockRun({job,intent,wasmVerifier:{hashOne:n=>{hashCount++;return wasm.hashOne(n);}},
                nativeVerifier:nativeFactory(job), daemon,latch,authority,workerId:'private-browser',
                canonical:{prevHashHex:t.prevHashHex},emit:record});
              active={job,run,wasm}; run.begin();issuedJobs++;
              record({type:'job_issued',height:job.height.toString(),difficulty:job.difficulty.toString(),
                generation:gen});
              return {...toClientJobMessage(job),networkDifficulty:job.difficulty.toString(),runGeneration:gen,workerId:'private-browser',maxSearchMs:120000};
            } catch(e) { if(!active)wasm.free(); throw e; }
          })();
          try {return send(200,await startTask);}
          catch(e){intent.revoke(gen,'start_failed');throw e;}
          finally {starting=false;startTask=null;}
        }
        if(path==='/api/candidate') {
          if(candidateBusy)fail('candidate_busy',409);
          if(!active || !intent.active)fail('not_running',409);
          const keys=Object.keys(data).sort().join(',');
          if(keys!=='issuanceId,jobId,nonce,runGeneration,workerId')fail('bad_schema');
          if(candidateAttempts>=8)fail('candidate_limit',429);
          const releaseCandidate=acquireCandidate();
          if(typeof releaseCandidate!=='function')fail('server_busy',429);
          candidateAttempts++;candidateBusy=true;
          try {
            const result=await active.run.submitCandidate(data);
            if(result.terminal)intent.revoke(data.runGeneration,'settled');
            return send(200,result);
          } finally {candidateBusy=false;releaseCandidate();}
        }
        fail('not_found',404);
      }
      if(req.method==='GET' && pageRoutes.has(path)) {
        const [file,type]=pageRoutes.get(path);
        return send(200,await readFile(file,'utf8'),{'Content-Type':type});
      }
      if(path==='/' || path==='/index.html' || path==='/app.js' || path==='/styles.css')fail('not_found',404);
      if(path!=='/worker.js' && !path.startsWith('/lib/') && !path.startsWith('/wasm/'))fail('not_found',404);
      return await staticHandler(req,res);
    } catch(e) {send(e.status??500,{error:e.code??'operation_failed'});}
  });
  server.requestTimeout=10000;server.headersTimeout=10000;server.maxConnections=12;
  await new Promise((ok,bad)=>{server.once('error',bad);server.listen(port,'127.0.0.1',ok);});
  origin='http://127.0.0.1:'+server.address().port;
  return {origin,url:origin+'/#session='+sessionToken,sessionToken,snapshot,
    cancel(){intent.revokeCurrent('service_revoked');return snapshot();}, close() {
    if(closeTask)return closeTask;
    closing=true;clearTimeout(lease);intent.revokeCurrent('shutdown');
    closeTask=(async()=>{
      try {await startTask?.catch(()=>{});await release();}
      finally {server.closeIdleConnections();await new Promise(ok=>server.close(ok));}
    })();
    return closeTask;
  }};
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const config=JSON.parse(await readFile(process.argv[2],'utf8'));
  const gateway=await createPrivateGateway({...config,onEvent:ev=>console.log(JSON.stringify(ev))});
  console.log(JSON.stringify({type:'listening',url:gateway.url}));
  let stopping=false;
  for(const signal of ['SIGINT','SIGTERM'])process.on(signal,async()=>{
    if(stopping){process.exitCode=130;return;}stopping=true;await gateway.close();
  });
}
