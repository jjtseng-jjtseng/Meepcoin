// The terminal release predicate of the local-daemon runner, as a pure function.
//
// It used to be an inline boolean expression, which meant the one thing that has now been wrong
// twice -- whether a `--keep-chain` retention failure actually reaches the exit code -- could not be
// tested without starting a daemon. It is the same predicate, moved so it can be proved: released
// false makes createRunLifecycle exit RELEASE_UNCONFIRMED after the normal cleanup.
//
// Pure: no command, no process, no daemon, no chain.

import { retentionSatisfied } from './retained_chain.mjs';

/**
 * @param {object} o
 * @param {object} o.cleanup      the observations collected after the pool closed
 * @param {boolean} o.keepChain   whether --keep-chain was requested
 * @returns {{released:boolean, blockers:string[]}}
 */
export function evaluateRelease({ cleanup, keepChain = false } = {}) {
  const c = cleanup ?? {};
  const blockers = [];
  if (c.browserExited === false) blockers.push('browser still running');
  if (c.daemonContainerGone === false) blockers.push('daemon container still present');
  if (c.daemonPidGone === false) blockers.push('daemon pid still present');
  if (c.helperPidGone === false) blockers.push('native helper pid still present');
  if (!c.daemonPortsFree) blockers.push('daemon ports not free');
  if (c.profileRemoved === false) blockers.push('browser profile not removed');
  if (!Array.isArray(c.containersMountingRunDir)) blockers.push('containers mounting the run dir unknown');
  else if (c.containersMountingRunDir.length > 0) blockers.push(`containers still mounting the run dir: ${c.containersMountingRunDir.join(',')}`);
  if (!retentionSatisfied({ keepChain, record: c.daemonDataKept ?? null })) blockers.push('retained chain not confirmed');
  return { released: blockers.length === 0, blockers };
}
