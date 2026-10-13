// Trusted operator command, never supplied by a browser. Only hex/decimal context arguments follow it.
import { execFile } from 'node:child_process';
export function createNativeCli(command, job) {
  if (!Array.isArray(command) || !command.length || command.some(x => typeof x !== 'string' || !x || x.includes('\0')))
    throw new TypeError('nativeCommand must be a nonempty argv array');
  if (!/^[0-9a-f]{64}$/.test(job.epochKeyHex) || !/^[0-9a-f]{64}$/.test(job.seedHashHex)
      || !/^[0-9a-f]+$/.test(job.hashingTemplateHex) || job.hashingTemplateHex.length > 8192)
    throw new TypeError('native CLI context is invalid or too large');
  return {
    hashOne(nonce) {
      if (!Number.isInteger(nonce) || nonce < 0 || nonce > 0xffffffff) throw new TypeError('nonce');
      return new Promise((resolve, reject) => {
        execFile(command[0], [...command.slice(1), job.epochKeyHex, job.seedHashHex, job.height.toString(),
          job.hashingTemplateHex, String(nonce)], {shell:false, windowsHide:true, timeout:25000, maxBuffer:4096},
        (error, stdout) => {
          if (error || !/^[0-9a-f]{64}\r?\n$/.test(stdout)) return reject(new Error('native_hash_failed'));
          resolve(new Uint8Array(Buffer.from(stdout.trim(), 'hex')));
        });
      });
    },
  };
}
