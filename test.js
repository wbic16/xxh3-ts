require('buffer');
var imports = require('./xxh3.ts');
var n = function (n) { return BigInt(n); };
var data = Buffer.from('example');
var key64 = Buffer.from('0000');
var seed = n(0);
var result = imports.XXH3_len_9to16_128b(data, key64, seed);
console.log(result);
