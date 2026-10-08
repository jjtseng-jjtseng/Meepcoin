// Build a generic gold coin, without a branded mark, downloads or graphics dependency.
import { deflateSync } from 'node:zlib';
import { mkdir, writeFile } from 'node:fs/promises';
const size = 256, rgba = Buffer.alloc(size * size * 4);
const mark = [[151,90],[113,90],[102,101],[102,114],[114,128],[142,128],[154,141],[154,154],[143,166],[105,166]];
function stroke(x,y,a,b) { const dx=b[0]-a[0],dy=b[1]-a[1],t=Math.max(0,Math.min(1,((x-a[0])*dx+(y-a[1])*dy)/(dx*dx+dy*dy)));return Math.hypot(x-a[0]-t*dx,y-a[1]-t*dy)<=6; }
for(let y=0;y<size;y++)for(let x=0;x<size;x++){
  const i=(y*size+x)*4,r=Math.hypot(x-128,y-128);
  if(r>112)continue;
  let color=r>105?[156,109,24]:Math.abs(r-82)<=3.5?[190,139,36]:[238,190,67];
  if(stroke(x,y,[128,76],[128,180])||mark.slice(1).some((b,j)=>stroke(x,y,mark[j],b)))color=[136,90,19];
  rgba[i]=color[0];rgba[i+1]=color[1];rgba[i+2]=color[2];rgba[i+3]=255;
}
const crcTable=Array.from({length:256},(_,i)=>{for(let j=0;j<8;j++)i=i&1?0xedb88320^(i>>>1):i>>>1;return i>>>0;});
function chunk(type,data){const t=Buffer.from(type),b=Buffer.alloc(data.length+12);b.writeUInt32BE(data.length);t.copy(b,4);data.copy(b,8);let c=0xffffffff;for(const v of Buffer.concat([t,data]))c=crcTable[(c^v)&255]^(c>>>8);b.writeUInt32BE((c^0xffffffff)>>>0,b.length-4);return b;}
const head=Buffer.alloc(13);head.writeUInt32BE(size);head.writeUInt32BE(size,4);head[8]=8;head[9]=6;
const raw=Buffer.alloc((size*4+1)*size);for(let y=0;y<size;y++)rgba.copy(raw,y*(size*4+1)+1,y*size*4,(y+1)*size*4);
const png=Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',head),chunk('IDAT',deflateSync(raw)),chunk('IEND',Buffer.alloc(0))]);
const ico=Buffer.alloc(22);ico.writeUInt16LE(1,2);ico.writeUInt16LE(1,4);ico[8]=0;ico.writeUInt16LE(1,10);ico.writeUInt16LE(32,12);ico.writeUInt32LE(png.length,14);ico.writeUInt32LE(22,18);
await mkdir(new URL('../assets/',import.meta.url),{recursive:true});await writeFile(new URL('../assets/icon.png',import.meta.url),png);await writeFile(new URL('../assets/icon.ico',import.meta.url),Buffer.concat([ico,png]));
console.log('Generated Local Lab icon.png and icon.ico');
