import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const root=new URL('../../',import.meta.url);
const toolchain=JSON.parse(await readFile(new URL('scripts/private/wasm-toolchain.json',root),'utf8'));
const identity=JSON.parse(await readFile(new URL('pool/dev/wasm_identity.json',root),'utf8'));
assert.deepEqual(toolchain.artifacts,identity.artifacts);
for(const [path,expected] of Object.entries(toolchain.artifacts)) {
 const bytes=await readFile(new URL(path,root));
 assert.equal(createHash('sha256').update(bytes).digest('hex'),expected,path);
 console.log(path+' verified');
}
