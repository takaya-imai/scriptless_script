const elliptic = require("elliptic").ec;
const ec = new elliptic("secp256k1");
const pjs = require("paillier-js");
const BN = require('bn.js');
const bigInt = require('big-integer');
const assert = require('assert');





//////////////
//
// setup
//
//////////////

const order = new BN(ec.n);

//
// generating basic keypairs and public key for multisig 
//
const aliceKeyPair = ec.genKeyPair();
const alicePubkey = aliceKeyPair.getPublic();
console.log("alicePubkey: ");
console.log(alicePubkey);

const bobKeyPair = ec.genKeyPair();
const bobPubkey = bobKeyPair.getPublic();
console.log("bobPubkey: ");
console.log(bobPubkey);

console.log();


//////////////
//
// multisig public key
//
//////////////


//
// 1, alice and bob exchange public key with zero knowledge proof and create multi public key
//
// alice and bob send money to multiPubkey
//
const multiPubkey = bobPubkey.mul(aliceKeyPair.getPrivate());
console.log("2-of-2 multisig public key: ");
console.log(multiPubkey);

console.log();



//////////////
//
// alice wants to calculate a signature and spend tx
//
//////////////


//
// 2, setting a message m (sighash in the case of BTC)
//
// alice           bob
//  m      <->      m
//
const m = "Satoshi Nakamoto";
console.log("message: " + m);

// transform m to e by LSB
const mHex = new BN(m, 16);
const delta = mHex.byteLength() * 8 - ec.n.bitLength();
const e = mHex.ushrn(delta > 0 ? delta : 0);

console.log();

//
// 3, generating nonce PrvkeyR respectively to calculate the signature
//
const aliceKeyPairR = ec.genKeyPair();
const alicePrvkeyR = aliceKeyPairR.getPrivate(); // k1
const alicePubkeyR = aliceKeyPairR.getPublic();
console.log("alicePrvkeyR(k1): " + alicePrvkeyR.toString(16));

const bobKeyPairR = ec.genKeyPair();
const bobPrvkeyR = bobKeyPairR.getPrivate(); // k2
const bobPubkeyR = bobKeyPairR.getPublic();
console.log("bobPrvkeyR(k2): " + bobPrvkeyR.toString(16));

console.log();


//
// 4, calculating multisig signature r
//
// alice and bob exchange PubkeyR and zero knowledge proof
//
// alice           bob
//  alicePubkeyR <-> bobPubkeyR
//  r               r
//
const aliceR = bobPubkeyR.mul(aliceKeyPairR.getPrivate());
const bobR = alicePubkeyR.mul(bobKeyPairR.getPrivate());

console.log("same value");
console.log("aliceR.x.umod(order): " + aliceR.x.umod(order).toString(16));
console.log("bobR.x.umod(order): " + bobR.x.umod(order).toString(16));

const r = aliceR.x.umod(order);

console.log();



//
// 5, alice calculates multisig signature s
//

// alice creates Paillier keypair and send cKey to bob
//
// alice           bob
//  prvkeyPjs
//  pubkeyPjs
//
const {publicKey, privateKey} = pjs.generateRandomKeys(2048);
const prvkeyPjs = privateKey;
const pubkeyPjs = publicKey;

// alice           bob
//  cKey    ->
//
const cKey = pubkeyPjs.encrypt(aliceKeyPair.getPrivate().toString());


// alice           bob
//                  c1, c2, c3
//
const pq = new BN(bigInt.rand(1024).value.toString()).mul(order);
const invPrvkeyRBob = bobPrvkeyR.invm(order);
const c1 = pubkeyPjs.encrypt(invPrvkeyRBob.mul(e).umod(order).add(pq).toString());
const c2 = pubkeyPjs.multiply(cKey, new BN(bobKeyPair.getPrivate()).mul(r).mul(invPrvkeyRBob).umod(order).toString());
const c3 = pubkeyPjs.addition(c1, c2);


// alice           bob
//           <-     c3
//  sDash
//
const sDash = prvkeyPjs.decrypt(c3);

// alice           bob
//  s
//
const invPrvkeyRAlice = alicePrvkeyR.invm(order);
const s = new BN(sDash.value.toString()).mul(invPrvkeyRAlice).umod(order);


console.log("signature");
const sig = {"r": r.toString(16), "s": s.toString(16)}; // DER format in the case of BTC
console.log(sig);
console.log();


// alice makes sure that signature is valid
//
console.log("signature is valid?:");
console.log(ec.keyFromPublic(multiPubkey).verify(m, sig));
