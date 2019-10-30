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
// Secure Two-party Threshold ECDSA from ECDSA Assumptions
//   https://eprint.iacr.org/2019/889
//
//
// setup
//    2-of-3
//
//////////////

console.log("[Each players setups 2-of-3 multisig and send shares to Alice, Bob and Carol each other]\n");


//
// generating secrets
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
// creating shares for index [1, 2, 3]
//   additive shares
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
//   additive aggregated pubkey
//

console.log("[Pay to the multi-sig addr(additive)]\n");

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



// TODO: consistency check
// check whether multisig public key can be derived by langrange interpolation








console.log();


//////////////
//
// unlock by alice and bob
//
//////////////

console.log("[unlock by Alice and Bob (multiplicative signature aggregation)]\n");

//
// setting a message m (sighash in the case of BTC)
//
// Alice            Bob            Carol
//  m       <->      m
//
const m = "Satoshi Nakamoto";
const e = lsbToInt(m);
console.log("message: " + m);
console.log(e);


//////////////
//
// Multiplication and Instance Key Exchange
//
//   multiplicative signature aggregation not additive
//


// 
// 1, creating t0A and t0B
//
// Alice            Bob            Carol
//  t0A              t0B
//

const aliceLambda = bigInt(2);
const bobLambda = bigInt(1).negate();

const t0A = aliceLambda.multiply(aliceShare);
const t0B = bobLambda.multiply(bobShare);


// 
// 2, multiplication and instance key exchange
//

// 2.1, generating bobK and aliceKDash, and open bobD
//
// Alice            Bob            Carol
//  aliceKDash       bobK
//
//              <-   bobD
//

const bobK = bigInt(randomBytes(32).toString('hex'), 16);
const aliceKDash = bigInt(randomBytes(32).toString('hex'), 16);

const bobD = ec.keyFromPrivate(bobK.value.toString(16)).getPublic();



// 2.2, calculating R, RDash and aliceK from bobD and aliceKDash
//
// Alice            Bob            Carol
//  aliceR
//  aliceRDash
//  aliceK

const aliceRDash = bobD.mul(new BN(aliceKDash.value.toString()));
const aliceK = bigInt(aliceRDash.getX().toString(16), 16)
               .add(aliceKDash);
const aliceR = bobD.mul(new BN(aliceK.value.toString()));



// 2.3, generating phi as a pad (auxiliary valuable)
//
// Alice            Bob            Carol
//  alicePhi
//

const alicePhi = bigInt(randomBytes(32).toString('hex'), 16);



// 2.4, three Gilboa protocol (it is like Multiplicative to Additive in GG18 but using Oblivious Transfer Extension)
//
// Alice            Bob            Carol
//  t1A              t1B
//  t2aA             t2aB
//  t2bA             t2bB
//

const [t1A, t1B] = mul(alicePhi.add(aliceK.modInv(order)), bobK.modInv(order));
const [t2aA, t2aB] = mul(t0A.multiply(aliceK.modInv(order)), bobK.modInv(order));
const [t2bA, t2bB] = mul(t0B.multiply(bobK.modInv(order)),   aliceK.modInv(order));


// 2.5, calculating t2A and t2B
//
// Alice            Bob            Carol
//  t2A              t2B
//

const t2A = t2aA.add(t2bA);
const t2B = t2aB.add(t2bB);


// 2.6, Alice opens RDash and Bob calculates R
//
// Alice            Bob            Carol
//  aliceRDash ->
//                   bobR
//                   r
//

const bobR = bobD.mul(aliceRDash.getX()).add(aliceRDash);

// check that alice's R and bob's R is the same
assert(aliceR.getX().toString() == bobR.getX().toString());
assert(aliceR.getY().toString() == bobR.getY().toString());





//////////////
//
// Consistency Check, Signature and Verification
//



// 2, Alice opens etaPhi
//
// Alice            Bob            Carol
//  aliceGamma1
//  etaPhi      ->
//

const aliceGamma1 = ec.g
                    .add(ec.g.mul(new BN(alicePhi.multiply(aliceK).value.toString())))
                    .add(aliceR.mul(new BN(t1A.negate().value.toString())));
const etaPhi = bigInt(aliceGamma1.getX().toString(16), 16)
               .add(alicePhi);

// 3, Alice opens etaSig (not aliceS)
//
// Alice            Bob            Carol
//  r
//  aliceS
//  aliceGamma2
//
//  etaSig  ->
//

const r = bigInt(aliceR.getX().toString(16), 16).mod(order);
const aliceS = e.multiply(t1A)
               .add(r.multiply(t2A));
const aliceGamma2 = multiPubkey.mul(new BN(t1A.value.toString()))
                    .add(ec.g.mul(new BN(t2A.value.toString())).neg());
const etaSig = bigInt(aliceGamma2.getX().toString(16), 16)
               .add(aliceS);


// 4, Bob calculates signature
//
// Alice            Bob            Carol
//                   bobGamma1
//                   bobPhi
//                   theta
//                   bobS
//                   bobGamma2
//                   s
//

const bobGamma1 = bobR.mul(new BN(t1B.value.toString()));
// check differences between alice's gamma1 and bob's gamma1
assert(aliceGamma1.getX().toString() == bobGamma1.getX().toString()); // this asert is not possible actually
assert(aliceGamma1.getY().toString() == bobGamma1.getY().toString());



// check differences between alice's phi and bob's phi
const bobPhi = etaPhi.add(bigInt(bobGamma1.getX().toString(16), 16).negate()).mod(order);
assert(alicePhi.mod(order).value == bobPhi.mod(order).value);


const theta = t1B
              .add(bobPhi.multiply(bobK.modInv(order)).negate())
              .mod(order);

const bobS = e.multiply(theta)
                 .add(r.multiply(t2B));


// check differences between alice's gamma2 and bob's gamma2
const bobGamma2 = ec.g.mul(new BN(t2B.value.toString()))
                  .add(multiPubkey.mul(new BN(theta.value.toString())).neg());
assert(aliceGamma2.getX().toString() == bobGamma2.getX().toString());
assert(aliceGamma2.getY().toString() == bobGamma2.getY().toString());


const s = bobS.add(etaSig).add(bigInt(bobGamma2.getX().toString(16), 16).negate()).mod(order);



//
// 5, signature verification
//

const sig = {r: r.toString(16), s: s.toString(16)}; // DER format in the case of BTC
console.log("signature");
console.log(sig);

console.log();
console.log("signature is valid?");
console.log(ec.keyFromPublic(multiPubkey).verify(lsbToStr(m), sig));






// Gilboa protocol by hand in the first code
// TODO: implement MPC
function mul(alpha, beta){
    let a = bigInt(randomBytes(32).toString('hex'), 16);
    let b = alpha.multiply(beta).add(a.negate()).add(order).mod(order);

    assert(alpha.add(beta).mod(order).value = a.multiply(b).mod(order).value);

    return [a, b];
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
