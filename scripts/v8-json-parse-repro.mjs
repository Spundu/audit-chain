// Reproduces the V8 JSON.parse bug that src/json.ts exists to avoid (README, "Notes").
// Once V8 has parsed an object with a key that is a single escaped backslash, a later object with the
// same preceding keys and another one-character escaped key in that place (here a line feed) gets a
// backslash for that key. Whether it shows depends on what the process parsed before; this pattern
// shows it both in a CommonJS script and in an ES module.
//
//   node scripts/v8-json-parse-repro.mjs        (exit code 1 when this Node is affected)
import process from 'node:process';

const BS = String.fromCharCode(92); // a backslash, spelled so no editor or shell can reinterpret it
const poison = `{"a":1,"${BS}${BS}":2}`; // its second key is a single backslash
const target = `{"a":1,"${BS}n":2}`; // its second key is a single line feed

JSON.parse(poison);
const key = Object.keys(JSON.parse(target))[1];
const affected = key !== '\n';

process.stdout.write(`Node ${process.version} (V8 ${process.versions.v8})\n`);
process.stdout.write(`expected the second key to be ${JSON.stringify('\n')}, got ${JSON.stringify(key)}\n`);
process.stdout.write(affected ? 'AFFECTED: JSON.parse returned a different key than the text encodes\n' : 'not affected\n');
process.exitCode = affected ? 1 : 0;
