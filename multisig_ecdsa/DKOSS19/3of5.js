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
// This code is a version without multiparty secret caluculation to genearte Beaver triples
//
// setup
//    3-of-5
//
//////////////

console.log("[Each players setups 3-of-5 multisig and send shares to Alice, Bob and Carol each other]\n");


//
// generating secrets
//

// Alice            Bob            Carol         Dave         Edward
//  alicePrvkey      bobPrvkey      carolPrvkey   davePrvkey   edPrvkey
//
const alicePrvkey = bigInt(randomBytes(32).toString('hex'), 16);
const bobPrvkey = bigInt(randomBytes(32).toString('hex'), 16);
const carolPrvkey = bigInt(randomBytes(32).toString('hex'), 16);
const davePrvkey = bigInt(randomBytes(32).toString('hex'), 16);
const edPrvkey = bigInt(randomBytes(32).toString('hex'), 16);


//
// generating shares
//    3-of-5
//
// shares
// creating shares for index [1, 2, 3, 4, 5]
//  it needs VSS(zk) actually
//
// Alice            Bob            Carol         Dave         Edward
//  aliceCoeff       bobCoeff       carolCoeff    daveCoeff    edCoeff
//
//  aliceShare1
//  aliceShare2
//  aliceShare3
//  aliceShare4
//  aliceShare5

//                   bobShare1
//                   bobShare2
//                   bobShare3
//                   bobShare4
//                   bobShare5

//                                  carolShare1
//                                  carolShare2
//                                  carolShare3
//                                  carolShare4
//                                  carolShare5

//                                                daveShare1
//                                                daveShare2
//                                                daveShare3
//                                                daveShare4
//                                                daveShare5

//                                                             edShare1
//                                                             edShare2
//                                                             edShare3
//                                                             edShare4
//                                                             edShare5

//  aliceShare2  ->
//  aliceShare3                 ->
//  aliceShare4                               ->
//  aliceShare5                                             ->

//               <- bobShare1
//                  bobShare3   ->
//                  bobShare4                 ->
//                  bobShare5                               ->

//               <-                 carolShare1
//                              <-  carolShare2
//                                  carolShare4 ->
//                                  carolShare5             ->

//               <-                               daveShare1
//                              <-                daveShare2
//                                              <-daveShare3
//                                                daveShare5->

//               <-                                            edShare1
//                              <-                             edShare2
//                                              <-             edShare3
//                                                           <-edShare4
//
const aliceCoeff = bigInt(randomBytes(32).toString('hex'), 16);
const bobCoeff = bigInt(randomBytes(32).toString('hex'), 16);
const carolCoeff = bigInt(randomBytes(32).toString('hex'), 16);
const daveCoeff = bigInt(randomBytes(32).toString('hex'), 16);
const edCoeff = bigInt(randomBytes(32).toString('hex'), 16);




const aliceShare1 = alicePrvkey.add(aliceCoeff).mod(order); // for 1
const aliceShare2 = alicePrvkey.add(bigInt(2).multiply(aliceCoeff)).mod(order); // for 2
const aliceShare3 = alicePrvkey.add(bigInt(3).multiply(aliceCoeff)).mod(order); // for 3
const aliceShare4 = alicePrvkey.add(bigInt(4).multiply(aliceCoeff)).mod(order); // for 4
const aliceShare5 = alicePrvkey.add(bigInt(5).multiply(aliceCoeff)).mod(order); // for 5

const bobShare1 = bobPrvkey.add(bobCoeff).mod(order); // for 1
const bobShare2 = bobPrvkey.add(bigInt(2).multiply(bobCoeff)).mod(order); // for 2
const bobShare3 = bobPrvkey.add(bigInt(3).multiply(bobCoeff)).mod(order); // for 3
const bobShare4 = bobPrvkey.add(bigInt(4).multiply(bobCoeff)).mod(order); // for 4
const bobShare5 = bobPrvkey.add(bigInt(5).multiply(bobCoeff)).mod(order); // for 5

const carolShare1 = carolPrvkey.add(carolCoeff).mod(order); // for 1
const carolShare2 = carolPrvkey.add(bigInt(2).multiply(carolCoeff)).mod(order); // for 2
const carolShare3 = carolPrvkey.add(bigInt(3).multiply(carolCoeff)).mod(order); // for 3
const carolShare4 = carolPrvkey.add(bigInt(4).multiply(carolCoeff)).mod(order); // for 4
const carolShare5 = carolPrvkey.add(bigInt(5).multiply(carolCoeff)).mod(order); // for 5

const daveShare1 = davePrvkey.add(daveCoeff).mod(order); // for 1
const daveShare2 = davePrvkey.add(bigInt(2).multiply(daveCoeff)).mod(order); // for 2
const daveShare3 = davePrvkey.add(bigInt(3).multiply(daveCoeff)).mod(order); // for 3
const daveShare4 = davePrvkey.add(bigInt(4).multiply(daveCoeff)).mod(order); // for 4
const daveShare5 = davePrvkey.add(bigInt(5).multiply(daveCoeff)).mod(order); // for 5

const edShare1 = edPrvkey.add(edCoeff).mod(order); // for 1
const edShare2 = edPrvkey.add(bigInt(2).multiply(edCoeff)).mod(order); // for 2
const edShare3 = edPrvkey.add(bigInt(3).multiply(edCoeff)).mod(order); // for 3
const edShare4 = edPrvkey.add(bigInt(4).multiply(edCoeff)).mod(order); // for 4
const edShare5 = edPrvkey.add(bigInt(5).multiply(edCoeff)).mod(order); // for 5




const aliceShare = aliceShare1.add(bobShare1).add(carolShare1).add(daveShare1).add(edShare1).mod(order);
const bobShare = aliceShare2.add(bobShare2).add(carolShare2).add(daveShare2).add(edShare2).mod(order);
const carolShare = aliceShare3.add(bobShare3).add(carolShare3).add(daveShare3).add(edShare3).mod(order);
const daveShare = aliceShare4.add(bobShare4).add(carolShare4).add(daveShare4).add(edShare4).mod(order);
const edShare = aliceShare5.add(bobShare5).add(carolShare5).add(daveShare5).add(edShare5).mod(order);

console.log("alice share:");
console.log(aliceShare.toString(16));
console.log("bob share:");
console.log(bobShare.toString(16));
console.log("carol share:");
console.log(carolShare.toString(16));
console.log("dave share:");
console.log(daveShare.toString(16));
console.log("edward share:");
console.log(edShare.toString(16));

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
const davePubkey = ec.keyFromPrivate(davePrvkey.value.toString(16)).getPublic();
const edPubkey = ec.keyFromPrivate(edPrvkey.value.toString(16)).getPublic();

const multiPubkey = alicePubkey.add(bobPubkey).add(carolPubkey).add(davePubkey).add(edPubkey);
console.log("multisig publickey:");
console.log(multiPubkey);


// Preprocessing
//
// 1, generating Beaver triples on Fp (Finite group with the same prime order as ec.n)
//
//  Beaver triples are given by hand not Multiparty Secret Calculation in the first code for simplicity.
//
// Alice            Bob            Carol
//  aliceBeaverA     bobBeaverA     carolBeaverA
//  aliceBeaverB     bobBeaverB     carolBeaverB
//  aliceBeaverC     bobBeaverC     carolBeaverC
//

const aliceBeaverA = bigInt(randomBytes(32).toString('hex'), 16);
const aliceBeaverB = bigInt(randomBytes(32).toString('hex'), 16);
const bobBeaverA = bigInt(randomBytes(32).toString('hex'), 16);
const bobBeaverB = bigInt(randomBytes(32).toString('hex'), 16);
const carolBeaverA = bigInt(randomBytes(32).toString('hex'), 16);
const carolBeaverB = bigInt(randomBytes(32).toString('hex'), 16);

// by hand in the first code
const [aliceBeaverC, bobBeaverC, carolBeaverC] = mul([aliceBeaverA, bobBeaverA, carolBeaverA], [aliceBeaverB, bobBeaverB, carolBeaverB]);

// check that Beaver triple is correct
assert(aliceBeaverC.add(bobBeaverC).add(carolBeaverC).mod(order).value = aliceBeaverA.add(bobBeaverA).add(carolBeaverA).multiply(aliceBeaverB.add(bobBeaverB).add(carolBeaverC)).mod(order).value);


//
// 2, Open beaverC
//
// Alice            Bob            Carol
//  aliceBeaverC ->             ->
//               <-  bobBeaverC ->
//               <-             <-  carolBeaverC
//  beaverC          beaverC        beaverC
//

const beaverC = aliceBeaverC.add(bobBeaverC).add(carolBeaverC).mod(order);


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
//  m       <->      m     <->      m
//
const m = "Satoshi Nakamoto";
const e = lsbToInt(m);
console.log("message: " + m);
console.log(e);



//
// 2, setting each k and calculating secret shared 1/k which is 1/(aliceK + bobK + carolK).
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
//                                  carolK
//                                  carolKInv
//                                  carolR
//

const aliceK = aliceBeaverA;
const aliceR = ec.keyFromPrivate(aliceK.value.toString(16)).getPublic();

const aliceKInv = beaverC.modInv(order).multiply(aliceBeaverB).mod(order);


const bobK = bobBeaverA;
const bobR = ec.keyFromPrivate(bobK.value.toString(16)).getPublic();

const bobKInv = beaverC.modInv(order).multiply(bobBeaverB).mod(order);

const carolK = carolBeaverA;
const carolR = ec.keyFromPrivate(carolK.value.toString(16)).getPublic();

const carolKInv = beaverC.modInv(order).multiply(carolBeaverB).mod(order);

// check that 1/(aliceK + bobK + carolK) = aliceKInv + bobKInv + carolKInv
assert(aliceK.add(bobK).add(carolK).modInv(order).value = aliceKInv.add(bobKInv).add(carolKInv).mod(order).value);




//
// 3, calcilating aliceShareDash and bobShareDash
//
//  aliceShareDash, bobShareDash and carolShareDash are given by hand not Multiparty Secret Calculation in the first code for simplicity.
//
// Alice            Bob            Carol
//  aliceShareDash   bobShareDash   carolShareDash
//
const aliceLambda = bigInt(3);
const bobLambda = bigInt(3).negate();
const carolLambda = bigInt(1);

const [aliceShareDash, bobShareDash, carolShareDash] = mul(
        [aliceKInv, bobKInv, carolKInv],
        [aliceLambda.multiply(aliceShare), bobLambda.multiply(bobShare), carolLambda.multiply(carolShare)]
    );

// check that aliceShareDash and bobShareDash are correct
assert(aliceShareDash.add(bobShareDash).add(carolShareDash).mod(order).value
    = aliceLambda.multiply(aliceShare).add(bobLambda.multiply(bobShare)).add(carolLambda.multiply(carolShare)).multiply(aliceK.add(bobK).add(carolK).modInv(order)).mod(order).value
    );




//
// 4, calculating r and s
//
// Alice            Bob            Carol
//             <-    (bobR, bobS)
//             <-                   (carolR, carolS)
//  R
//  (r, s)
//
const R = aliceR.add(bobR).add(carolR);
const r = bigInt(hDash(R).toString(16), 16).mod(order);

// check that R is correct
assert(R.x = ec.keyFromPrivate(aliceK.add(bobK).add(carolK).value.toString(16)).getPublic().x);
assert(R.y = ec.keyFromPrivate(aliceK.add(bobK).add(carolK).value.toString(16)).getPublic().y);




const aliceS = e.multiply(aliceKInv).add(r.multiply(aliceShareDash));
const bobS = e.multiply(bobKInv).add(r.multiply(bobShareDash));
const carolS = e.multiply(carolKInv).add(r.multiply(carolShareDash));

const s = aliceS.add(bobS).add(carolS).mod(order);


//
// 5, signature verification
//

const sig = {r: r.toString(16), s: s.toString(16)}; // DER format in the case of BTC
console.log("signature");
console.log(sig);

console.log();
console.log("signature is valid?");
console.log(ec.keyFromPublic(multiPubkey).verify(lsbToStr(m), sig));


//
// 6, broadcast
//

console.log("Alice broadcasts tx with one '3 of 5' valid signature");





// Beaver triple by hand in the first code
function mul([a1, a2, a3], [b1, b2, b3]){
    let a = a1.add(a2).add(a3);
    let b = b1.add(b2).add(b3);

    let c1 = bigInt(randomBytes(32).toString('hex'), 16);
    let c2 = bigInt(randomBytes(32).toString('hex'), 16);
    let c3 = a.multiply(b).add(c1.negate()).add(c2.negate()).add(order).mod(order);

    assert(c1.add(c2).add(c3).mod(order).value = a.multiply(b).mod(order).value);

    return [c1, c2, c3];
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
