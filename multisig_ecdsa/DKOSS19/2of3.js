const elliptic = require("elliptic").ec;
const ec = new elliptic("secp256k1");
const BN = require('bn.js');
const bigInt = require('big-integer');
const assert = require('assert');
const randomBytes = require('randombytes');
const sha256 = require("js-sha256");





const order = bigInt(ec.n.toString());

//////////////
//
// Securing DNSSEC Keys via Threshold ECDSA From Generic MPC
//   https://eprint.iacr.org/2019/889
//
// This code is a version without a trusted setup.
//
// setup
//    2-of-3
//
//////////////

console.log("[Each players setups 2-of-3 multisig and send shares to Alice, Bob and Carol each other]\n");


//
// generating dealer secret, dealerPrvkey
//

// Alice            Bob            Carol
//  alicePrvkey      bobPrvkey      carolPrvkey
//
const alicePrvkey = bigInt(randomBytes(32).toString('hex'), 16);
const bobPrvkey = bigInt(randomBytes(32).toString('hex'), 16);
const carolPrvkey = bigInt(randomBytes(32).toString('hex'), 16);


//
// generating shares
//    2-of-3
//
// shares
// creating shares for index [1, 2, 3]
//  it needs VSS(zk) actually
//
// Alice            Bob            Carol
//  aliceCoeff       bobCoeff       carolCoeff
//
//  aliceShare1
//  aliceShare2
//  aliceShare3

//                   bobShare1
//                   bobShare2
//                   bobShare3

//                                  carolShare1
//                                  carolShare2
//                                  carolShare3

//  aliceShare2  ->
//  aliceShare3                 ->

//               <- bobShare1
//                  bobShare3   ->

//               <-                 carolShare1
//                              <-  carolShare2
//
const aliceCoeff = bigInt(randomBytes(32).toString('hex'), 16);
const bobCoeff = bigInt(randomBytes(32).toString('hex'), 16);
const carolCoeff = bigInt(randomBytes(32).toString('hex'), 16);



const aliceShare1 = alicePrvkey.add(aliceCoeff).mod(order); // for 1
const aliceShare2 = alicePrvkey.add(bigInt(2).multiply(aliceCoeff)).mod(order); // for 2
const aliceShare3 = alicePrvkey.add(bigInt(3).multiply(aliceCoeff)).mod(order); // for 3

const bobShare1 = bobPrvkey.add(bobCoeff).mod(order); // for 1
const bobShare2 = bobPrvkey.add(bigInt(2).multiply(bobCoeff)).mod(order); // for 2
const bobShare3 = bobPrvkey.add(bigInt(3).multiply(bobCoeff)).mod(order); // for 3

const carolShare1 = carolPrvkey.add(carolCoeff).mod(order); // for 1
const carolShare2 = carolPrvkey.add(bigInt(2).multiply(carolCoeff)).mod(order); // for 2
const carolShare3 = carolPrvkey.add(bigInt(3).multiply(carolCoeff)).mod(order); // for 3



const aliceShare = aliceShare1.add(bobShare1).add(carolShare1).mod(order);
const bobShare = aliceShare2.add(bobShare2).add(carolShare2).mod(order);
const carolShare = aliceShare3.add(bobShare3).add(carolShare3).mod(order);

console.log("alice share:");
console.log(aliceShare.toString(16));
console.log("bob share:");
console.log(bobShare.toString(16));
console.log("carol share:");
console.log(carolShare.toString(16));

console.log();

//
// multisig public key
//

console.log("[Pay to the multi-sig addr]\n");

// Alice            Bob            Carol
//  alicePubkey ->             ->
//              <-   bobPubkey ->
//              <-             <-   carolPubkey
//
const alicePubkey = ec.keyFromPrivate(alicePrvkey.value.toString(16)).getPublic();
const bobPubkey = ec.keyFromPrivate(bobPrvkey.value.toString(16)).getPublic();
const carolPubkey = ec.keyFromPrivate(carolPrvkey.value.toString(16)).getPublic();

const multiPubkey = alicePubkey.add(bobPubkey).add(carolPubkey);
console.log("multisig publickey:");
console.log(multiPubkey);


// Preprocessing
//
// generating Beaver triples on Fp (Finite group with the same prime order as ec.n)
//
//  Beaver triples are given by hand not Secret Calculation in the first code for simplicity.
//
// Alice            Bob            Carol
//  aliceBeaverA     bobBeaverA
//  aliceBeaverB     bobBeaverB
//  aliceBeaverC     bobBeaverC
//

const aliceBeaverA = bigInt(randomBytes(32).toString('hex'), 16);
const aliceBeaverB = bigInt(randomBytes(32).toString('hex'), 16);
const bobBeaverA = bigInt(randomBytes(32).toString('hex'), 16);
const bobBeaverB = bigInt(randomBytes(32).toString('hex'), 16);

// by hand in the first code
const [aliceBeaverC, bobBeaverC] = mul([aliceBeaverA, bobBeaverA], [aliceBeaverB, bobBeaverB]);

// check that Beaver triple is correct
assert(aliceBeaverC.add(bobBeaverC).mod(order).value = aliceBeaverA.add(bobBeaverA).multiply(aliceBeaverB.add(bobBeaverB)).mod(order).value);


//
// 2, Open beaverC
//
// Alice            Bob            Carol
//  aliceBeaverC ->
//               <-  bobBeaverC
//  beaverC          beaverC
//

const beaverC = aliceBeaverC.add(bobBeaverC).mod(order);



//
// 3, setting each k and calculating secret shared 1/k which is 1/(aliceK + bobK).
//
// Alice            Bob            Carol
//  aliceK
//  aliceKInv
//  aliceR
//
//                   bobK
//                   bobKInv
//                   bobR
//

const aliceK = aliceBeaverA;
const aliceR = ec.keyFromPrivate(aliceK.value.toString(16)).getPublic();

const aliceKInv = beaverC.modInv(order).multiply(aliceBeaverB).mod(order);


const bobK = bobBeaverA;
const bobR = ec.keyFromPrivate(bobK.value.toString(16)).getPublic();

const bobKInv = beaverC.modInv(order).multiply(bobBeaverB).mod(order);

// check that 1/(aliceK + bobK) = aliceKInv + bobKInv
assert(aliceK.add(bobK).modInv(order).value = aliceKInv.add(bobKInv).mod(order).value);


console.log();


//////////////
//
// unlock by alice and bob
//
//////////////

console.log("[unlock by Alice and Bob]\n");

//
// 1, setting a message m (sighash in the case of BTC)
//
// Alice            Bob            Carol
//  m       <->      m
//
const m = "Satoshi Nakamoto";
const e = lsbToInt(m);
console.log("message: " + m);
console.log(e);



//
// 2, calcilating aliceShareDash and bobShareDash
//
//  aliceShareDash and bobShareDash are given by hand not Secret Calculation in the first code for simplicity.
//
// Alice            Bob            Carol
//  aliceShareDash   bobShareDash
//
const aliceLambda = bigInt(2);
const bobLambda = bigInt(1).negate();

const [aliceShareDash, bobShareDash] = mul(
        [aliceKInv, bobKInv],
        [aliceLambda.multiply(aliceShare), bobLambda.multiply(bobShare)]
    );

// check that aliceShareDash and bobShareDash are correct
assert(aliceShareDash.add(bobShareDash).mod(order).value
    = aliceLambda.multiply(aliceShare).add(bobLambda.multiply(bobShare)).multiply(aliceK.add(bobK).modInv(order)).mod(order).value
    );




//
// 3, calculating r and s
//
// Alice            Bob            Carol
//  aliceS           bobS
//

//             <-    (bobR, bobS)
//  R
//  (r, s)
//
const R = aliceR.add(bobR);
const r = bigInt(hDash(R).toString(16), 16).mod(order);

// check that R is correct
assert(R.x = ec.keyFromPrivate(aliceK.add(bobK).value.toString(16)).getPublic().x);


const aliceS = e.multiply(aliceKInv).add(r.multiply(aliceShareDash));
const bobS = e.multiply(bobKInv).add(r.multiply(bobShareDash));

const s = aliceS.add(bobS).mod(order);


//
// 4, signature verification
//

const sig = {r: r.toString(16), s: s.toString(16)}; // DER format in the case of BTC
console.log("signature");
console.log(sig);

console.log();
console.log("signature is valid?");
console.log(ec.keyFromPublic(multiPubkey).verify(lsbToStr(m), sig));


//
// 5, broadcast
//

console.log("Alice broadcasts tx with one '2 of 3' valid signature");





// Beaver triple by hand in the first code
function mul([a1, a2], [b1, b2]){
    let a = a1.add(a2);
    let b = b1.add(b2);

    let c1 = bigInt(randomBytes(32).toString('hex'), 16);
    let c2 = a.multiply(b).add(c1.negate()).add(order).mod(order);

    assert(c1.add(c2).mod(order).value = a.multiply(b).mod(order).value);

    return [c1, c2];
};

function randMul(){
    let a1 = bigInt(randomBytes(32).toString('hex'), 16);
    let a2 = bigInt(randomBytes(32).toString('hex'), 16);
    let b1 = bigInt(randomBytes(32).toString('hex'), 16);
    let b2 = bigInt(randomBytes(32).toString('hex'), 16);

    return mul([a1, a2], [b1, b2]);
};


function hDash(pubkey){
    return pubkey.getX();
};

// transform m to e by LSB
function lsbToStr(m){
    let mHex = new BN(sha256.create().update(m).hex());
    let delta = mHex.byteLength() * 8 - ec.n.bitLength();
    return mHex.ushrn(delta > 0 ? delta : 0).toString(16);
};
function lsbToInt(m){
    let mHex = new BN(sha256.create().update(m).hex());
    let delta = mHex.byteLength() * 8 - ec.n.bitLength();
    return bigInt(mHex.ushrn(delta > 0 ? delta : 0).toString(16), 16);
};
