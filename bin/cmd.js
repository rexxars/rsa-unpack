#!/usr/bin/env node

var fs = require('fs');
var path = require('path');
var argv = require('optimist').argv;
var unpack = require('../');

var format = argv.format || 'pem';
var encoding = argv.e || argv.encoding || 'hex';

var file = process.argv[2] || '-';
if (file === '-' && format === 'json') {
    var data = '';
    process.stdin.on('data', function (buf) { data += buf });
    process.stdin.on('end', function () {
        var keys = JSON.parse(data);
        console.log(JSON.stringify({
            private : encode(unpack(keys.private)),
            public : encode(unpack(keys.public)),
        }, null, 2));
    });
    process.stdin.resume();
}
else if (file === '-') {
    var data = '';
    process.stdin.on('data', function (buf) { data += buf });
    process.stdin.on('end', function () {
        console.log(JSON.stringify(encode(data), null, 2));
    });
    process.stdin.resume();
}
else if (/\.json$/.test(file) || format === 'json') {
    var keys = require(path.resolve(process.argv[2]));
    console.log(JSON.stringify({
        private : encode(unpack(keys.private)),
        public : encode(unpack(keys.public))
    }, null, 2));
}
else {
    var src = fs.readFileSync(file, 'utf8');
    console.log(JSON.stringify(
        encode(src),
        null, 2
    ));
}

function encode (obj) {
    return Object.keys(obj).reduce(function (acc, key) {
        if (Buffer.isBuffer(obj[key])) {
            acc[key] = obj[key].toString(encoding);
        }
        else acc[key] = obj[key];
        return acc;
    }, {});
}