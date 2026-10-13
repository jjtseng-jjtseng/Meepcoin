const sessionToken=new URLSearchParams(location.hash.slice(1)).get('session')??'';
const $=id=>document.getElementById(id);
let worker=null, generation=0, ticket=0, running=false, hashes=0;
window.meepPrivate={events:[],workerCount:0,state:'idle'};
function event(type,data={}){window.meepPrivate.events.push({type,...data});if(window.meepPrivate.events.length>64)window.meepPrivate.events.shift();}
function state(name,detail){$('state').textContent=name;$('detail').textContent=detail;window.meepPrivate.state=name;}
async function post(path,data){
  const r=await fetch('/api/'+path,{method:'POST',headers:{'Content-Type':'application/json','X-Meep-Session':sessionToken},body:JSON.stringify(data)});
  const result=await r.json();if(!r.ok)throw new Error(result.error??'Request failed');return result;
}
function terminate(){$('light').classList.remove('active');if(worker){worker.terminate();worker=null;}window.meepPrivate.workerCount=0;}
async function stop(reason='Stopped'){
  const previous=generation;generation=0;ticket++;running=false;terminate();$('stop').disabled=true;$('start').disabled=false;
  state(reason,'Hashing is stopped. A request already sent to the node may still complete.');
  event('stop',{generation:previous});
  if(previous)try{await post('stop',{generation:previous});}catch{}
}
async function start(){
  const myTicket=++ticket;running=true;$('start').disabled=true;$('stop').disabled=false;hashes=0;$('hashes').textContent='0';
  state('Preparing','Loading a fresh template from your private node.');event('start');
  try{
    const job=await post('start',{});const gen=job.runGeneration;
    if(myTicket!==ticket || !running || document.hidden){
      await post('stop',{generation:gen}).catch(()=>{});
      if(myTicket===ticket)void stop('Stopped');
      return;
    }
    generation=gen;
    $('height').textContent=job.height;
    // The actual difficulty is sent as an exact decimal string by the server.
    $('difficulty').textContent=job.networkDifficulty;
    const own=new Worker('/worker.js',{type:'module'});worker=own;window.meepPrivate.workerCount=1;
    own.onerror=()=>{if(myTicket===ticket){event('worker_error');void stop('Worker failed');}};
    own.onmessage=async({data:m})=>{
      const kind=m.ev;
      if(m.gen!==gen || myTicket!==ticket || !running || own!==worker)return;
      event(kind,{generation:gen,hashes:m.hashes??null});
      if(kind==='ready'){state('Mining','One worker is searching this block template.');$('light').classList.add('active');own.postMessage({cmd:'search',gen,jobId:job.jobId});}
      if(kind==='progress'){$('hashes').textContent=String(m.hashes);hashes=m.hashes;}
      if(kind==='found'){
        hashes=m.nonce-job.nonceStart+1;$('hashes').textContent=String(hashes);
        terminate();state('Checking','The server and node are checking the candidate.');
        try{
          const result=await post('candidate',{jobId:job.jobId,issuanceId:job.issuanceId,
            workerId:job.workerId,runGeneration:gen,nonce:m.nonce});
          event('candidate_result',{generation:gen,result});
          if(myTicket!==ticket)return;
          $('result').textContent=JSON.stringify(result,null,2);
          running=false;$('start').disabled=false;$('stop').disabled=true;$('light').classList.remove('active');
          state(result.reason==='verified_complete'?'Block observed':'Run settled',
            result.reason==='verified_complete'?'Your block was read back from the canonical chain. Rewards unlock after the required confirmations.':'Check the node result below for the exact outcome.');
        }catch(e){if(myTicket===ticket){event('candidate_error',{code:e.message});void stop('Outcome unknown');}}
      }
      if(kind==='finished' && !m.found){$('hashes').textContent=String(m.hashes);void stop(m.timedOut?'Time limit reached':'Window searched');}
      if(kind==='error' || kind==='command_refused'){event('worker_refused');void stop('Worker stopped');}
    };
    own.postMessage({cmd:'init_search',gen,jobId:job.jobId,sequenceTotal:1,pacingMs:100,
      context:{epochKeyHex:job.epochKeyHex,seedHashHex:job.seedHashHex,height:job.height,hashingTemplateHex:job.hashingTemplateHex},
      window:{nonceStart:job.nonceStart,nonceRange:job.nonceRange,maxSearchMs:job.maxSearchMs,targetHexLE:job.targetHexLE}});
  }catch(e){if(myTicket===ticket){event('start_error',{code:e.message});await stop('Unable to start');$('result').textContent=e.message;}}
}
$('start').onclick=()=>void start();$('stop').onclick=()=>void stop();
document.addEventListener('visibilitychange',()=>{if(document.hidden && running)void stop('Tab hidden');});
window.addEventListener('pagehide',()=>{if(running){const previous=generation;generation=0;ticket++;running=false;terminate();fetch('/api/stop',{method:'POST',keepalive:true,
  headers:{'Content-Type':'application/json','X-Meep-Session':sessionToken},body:JSON.stringify({generation:previous})}).catch(()=>{});}});
$('start').disabled=true;
fetch('/api/status',{headers:{'X-Meep-Session':sessionToken}}).then(async r=>{if(!r.ok)throw new Error('unauthorized');return r.json();}).then(s=>{$('address').textContent=s.payoutAddress;generation=s.generation;
  // Reload is idle, and also revokes a leftover server intent.
  if(s.running && generation)void stop('Idle');else $('start').disabled=false;
}).catch(()=>state('Disconnected','The private gateway is unavailable.'));
