const crypto = require('crypto');
const dif = require('js-x25519');
const helpers = require('./helpers/helpers.js');


const pub2 = helpers.fromHexString(process.argv[2]);
const msg = 'fuckin message';


let first = crypto.createECDH('secp256k1');
first.generateKeys();
let priv1=first.getPrivateKey();
let pub1=dif.getPublic(priv1);

let secret=helpers.toHexString(dif.getSharedKey(priv1,pub2));

const enc=helpers.encryptText(secret,msg);
console.log(JSON.stringify({Pub:helpers.toHexString(pub1),Encrypt:enc}));

