// Persisted absolute end plus a monotonic cap for the running process.
// Across restarts this assumes a synchronized wall clock. New epochs need new config.
export function experimentWindow(experiment, wallNow=Date.now, monotonicNow=()=>performance.now()) {
  if(!experiment||typeof experiment!=='object')throw new TypeError('persisted experiment required');
  const {genesisUtcUnix,startsUtcUnix,endsUtcUnix}=experiment;
  if(![genesisUtcUnix,startsUtcUnix,endsUtcUnix].every(Number.isSafeInteger)
    ||genesisUtcUnix<1000000000||genesisUtcUnix>2999999999
    ||startsUtcUnix<genesisUtcUnix||startsUtcUnix-genesisUtcUnix>3600
    ||endsUtcUnix<=startsUtcUnix||endsUtcUnix-startsUtcUnix>3600)
    throw new TypeError('experiment requires fresh genesis and at most one hour');
  const wall=wallNow(),mono=monotonicNow();
  if(!Number.isFinite(wall)||!Number.isFinite(mono)||wall<startsUtcUnix*1000||wall>=endsUtcUnix*1000)
    throw new TypeError('experiment not active');
  // Freshness applies to the saved first start, not subsequent process restarts.
  const deadline=mono+(endsUtcUnix*1000-wall);let closed=false;
  return {genesisUtcUnix,deadline,
    open(){
      const wall=wallNow(),mono=monotonicNow();
      if(!Number.isFinite(wall)||!Number.isFinite(mono)||wall>=endsUtcUnix*1000||mono>=deadline)closed=true;
      return !closed;
    }};
}
