# xxh3-ts 1.0.7 (WIP)

WARNING: Changes from 0.7.0 to 0.8.2 are being ported. TODO list:
* Detailed test coverage for sub-routines
* XXH3_len_9to16_128b
* XXH3_len_4to8_128b
* XXH3_len_1to3_128b
* XXH3_len_0to16_128b
* XXH3_len_17to128_128b
* XXH3_len_129to240_128b
* XXH3_avalanche

xxhash-ts implements XXH64 and XXH3-128 in pure typescript using tc39 bigint.
These algorithms require Node.js >=12.x, due to `Buffer::readBigUInt64LE`.

## Usage:
```ts
import { XXH3-128 } from 'xxh3-ts';
import { Buffer } from 'buffer';

let hash: bigint = XXH3-128(Buffer.from(JSON.stringify(v)))
```

If you need the raw buffer, consider the [bigint-buffer](https://www.npmjs.com/package/bigint-buffer) package.

Or just use the following snippet:
```ts
function toBufferBE(num: bigint): Buffer {
  const hex = num.toString(16);
  // Padding *is* needed otherwise the last nibble will be dropped in an edge case
  return Buffer.from(hex.padStart(Math.ceil(hex.length/2) * 2, '0'), 'hex');
}
```

## Porting Notes

Between xxhash 0.7.0 and 0.8.2, many low-level optimizations were added.
This port aims to retain the elegance of the xxhash algorithm with a minimum amount of fuss.
It is not as highly-optimized, but runs on any JS environment (including vite).

If you want a faster implementation, you should look at a native port.

XXH64 and XXH3-128 were derived from the specifications at https://github.com/Cyan4973/xxHash/blob/v0.8.2/doc/xxhash_spec.md and the source at https://github.com/Cyan4973/xxHash/blob/v0.8.2/xxh3.h.
