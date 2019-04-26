const elliptic = require("elliptic").ec;
const ec = new elliptic("secp256k1");
const pjs = require("paillier-js");
const math = require('mathjs')
const BN = require('bn.js');
const bigInt = require('big-integer');
const assert = require('assert');




//////////////
//
// setup
//
//////////////



// an order of encryption for blockchain is the same for simplicity
const order = new BN(ec.n);

//
// generating basic keypairs(blc1) and public key for multisig (actually it needs one more keypairs on another blockchain)
//
// money on blc2 bob send first is spent by alice later by alpha is revailed
//
const aliceKeyPair = ec.genKeyPair();
const alicePubkey = aliceKeyPair.getPublic();
console.log("alicePubkey(blc1): ");
console.log(alicePubkey);

const bobKeyPair = ec.genKeyPair();
const bobPubkey = bobKeyPair.getPublic();
console.log("bobPubkey(blc1): ");
console.log(bobPubkey);

console.log();


//////////////
//
// multisigg public key(blc1) to do atomic swap
//
//////////////

//
// 1, alice and bob exchange public key with zero knowledge proof and create multi public key
//
// alice and bob send money first to each multiPubkey on different blockchain
//
console.log("multiPubkey(blc1)");
const multiPubkey = bobPubkey.mul(aliceKeyPair.getPrivate());
console.log(multiPubkey);

console.log();



//////////////
//
// bob wants to calculate a signature and spend alice's money as atomic swap
//
// (alice also spends bob's money after alice gets bobAlpha bob generated)
//
//////////////


//
// 2, setting a message mBob (sighash in the case of BTC)
//
// alice           bob
//         <-       mBob
//
// alice makes adaptor signature sDash2(blc1)
//
const mBob = "Bob makes a tx to spend alice's money(blc1) as atomic swap by adaptor signature alice sends to him. "
const mAlice = "Alice spends bob's money(blc2) after she gets alpha(bobAlpha) from the tx bob broadcasted";
console.log("message bob makes: " + mBob);
console.log("message alice makes(not used in this code for simplicity): " + mAlice);

const e = lsb(mBob);

console.log();


//
// 3.1, generating alpha( bobAlpha)
//
// alice           bob
//                  bobAlpha
//
// bob generates it in this code because he broadcast tx first
//
const bobKeyPairAlpha = ec.genKeyPair();
const bobAlpha = bobKeyPairAlpha.getPrivate();
console.log("alpha bob generates: " + bobAlpha.toString(16));

console.log();

//
// 3.2, generating nonce PrvkeyR respectively to calculate the signature
//
// alice           bob
//  alicePrvkeyR    bobPrvkeyR
//                  bobPrvkeyR3
//
const aliceKeyPairR = ec.genKeyPair();
const alicePrvkeyR = aliceKeyPairR.getPrivate();
const alicePubkeyR = aliceKeyPairR.getPublic();
console.log("alicePrvkeyR(k1): " + alicePrvkeyR.toString(16));

const bobKeyPairR = ec.genKeyPair();
const bobPrvkeyR = bobKeyPairR.getPrivate();
const bobPubkeyR = bobKeyPairR.getPublic();
console.log("bobPrvkeyR(k2): " + bobPrvkeyR.toString(16));


const bobPrvkeyR3 = bobAlpha.mul(bobPrvkeyR);
const bobPubkeyR3 = bobPubkeyR.mul(bobAlpha);



//
// 4, calculating multisig signature r
//
// alice and bob exchange PubkeyR and zero knowledge proof
//
// alice           bob
//  alicePubkeyR <-> bobPubkeyR3
//  r               r
//
const aliceR = bobPubkeyR3.mul(alicePrvkeyR);
const bobR = alicePubkeyR.mul(bobPrvkeyR3);
assert(new BN(aliceR.x).umod(order).toString(16) == new BN(bobR.x).umod(order).toString(16));
const r = aliceR.x.umod(order);

console.log();



//
// 5, bob calculates multisig signature s
//

// alice creates Paillier keypair and send cKey to bob
// it needs 2 type of cKey actually, one is for mBob, another is for mAlice. 
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

console.log("alice makes sure whether bob is a scam or not. if so, she does not send sDash2 to bob.");
assert(bobPubkeyR.mul(new BN(sDash.value.toString()).umod(order)).toString(16)
     == multiPubkey.mul(r).add(ec.keyFromPrivate(e).getPublic()).toString(16));

console.log();

// alice           bob
//  sDash2   ->
//
// sDash2 is an adaptor signature
// actually there is one more sDash2 and it is for mAlice. alice get signature from this one more sDash2 for mAlice and alpha.
//
const invPrvkeyRAlice = alicePrvkeyR.invm(order);
const sDash2 = new BN(sDash.value.toString()).mul(invPrvkeyRAlice).umod(order);


// alice           bob
//                  s
//
const invAlpha = bobAlpha.invm(order);
const s = sDash2.mul(invAlpha).umod(order);



console.log("signature");
const sig = {r: r.toString(16), s: s.toString(16)};
console.log(sig);

// bob makes sure that signature is valid and spend alice's money
//
console.log("signature is valid?:");
console.log(ec.keyFromPublic(multiPubkey).verify(mBob, sig));

console.log();

//
// 6, alice calculates multisig signature to spend bob's money
//

// s is revailed by the tx bob broadcasted to spend alice's money
console.log("alice derives alpha from s and sDash2");
const aliceAlpha = s.mul(sDash2.invm(order)).invm(order);
console.log("alpha bob generates first: ");
console.log(bobAlpha);
console.log("alpha alice revails: ");
console.log(aliceAlpha);


// alice gets signature from sDash2 for mAlice and alpha.
// const invAlphaAlice = aliceAlpha.invm(order);
// console.log(sDash2OneMore.mul(invAlphaAlice).umod(order));



function lsb(m){
    // transform m to e by LSB
    let mHex = new BN(m, 16);
    let delta = mHex.byteLength() * 8 - ec.n.bitLength();
    return mHex.ushrn(delta > 0 ? delta : 0);
};
