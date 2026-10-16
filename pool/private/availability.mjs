// Operational admission rule, not consensus or a guarantee about block time.
export function progressPolicy({genesis,startedUtcUnix,restored,wallNow=Date.now,monotonicNow=()=>performance.now(),stallMs=600000}={}) {
 if(!/^[a-f0-9]{64}$/.test(genesis??'')||!Number.isSafeInteger(startedUtcUnix)||stallMs!==600000)
  throw TypeError('Pinned genesis, start and ten-minute admission policy required');
 let state=restored??{schema:'meepcoin-progress/1',genesis,height:0,tip:null,lastProgressMs:startedUtcUnix*1000,closed:false};
 if(state.schema!=='meepcoin-progress/1'||state.genesis!==genesis||!Number.isSafeInteger(state.height)||state.height<0
  ||!Number.isFinite(state.lastProgressMs)||state.lastProgressMs<startedUtcUnix*1000
  ||typeof state.closed!=='boolean'||(state.tip!==null&&!/^[a-f0-9]{64}$/.test(state.tip)))throw TypeError('Invalid saved progress; admission refused');
 state={...state,maxObservedMs:state.maxObservedMs??state.lastProgressMs};
 if(!Number.isFinite(state.maxObservedMs)||state.maxObservedMs<state.lastProgressMs)throw TypeError('Invalid saved progress clock');
 let monoBase=monotonicNow(),ageAtLoad=Math.max(0,wallNow()-state.lastProgressMs);
 function snapshot(){
  const wall=wallNow(),mono=monotonicNow();
  if(!Number.isFinite(wall)||!Number.isFinite(mono)||mono<monoBase||wall<state.maxObservedMs)
   state={...state,closed:true,reason:'clock_regressed'};
  if(Number.isFinite(wall))state={...state,maxObservedMs:Math.max(state.maxObservedMs,wall)};
  const age=Math.max(0,wall-state.lastProgressMs,ageAtLoad+mono-monoBase);
  if(age>=stallMs)state={...state,closed:true,reason:'chain_stalled'};
  return {...state,lastBlockAgeSeconds:Math.floor(age/1000),stallAfterSeconds:stallMs/1000};
 }
 return {snapshot,close(reason){state={...state,closed:true,reason};return snapshot();},observe(height,tip){
  if(!Number.isSafeInteger(height)||height<1||(tip!==undefined&&!/^[a-f0-9]{64}$/.test(tip)))throw TypeError('Invalid canonical progress');
  // Latch a crossed deadline before considering new progress; restart is not renewal.
  snapshot();
  if(!state.closed&&(height!==state.height||(tip!==undefined&&tip!==state.tip))){
   state={...state,height,tip:tip??null,lastProgressMs:wallNow()};
   monoBase=monotonicNow();ageAtLoad=0;
  }
  return snapshot();
 }};
}
