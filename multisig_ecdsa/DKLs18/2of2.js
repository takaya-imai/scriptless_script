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
//    2-of-2
//
//////////////

console.log("[Each players setups 2-of-2 multisig]\n");


//
// generating secrets
//

// Alice            Bob
//  alicePrvkey      bobPrvkey
//
const alicePrvkey = bigInt(randomBytes(32).toString('hex'), 16);
const bobPrvkey = bigInt(randomBytes(32).toString('hex'), 16);

console.log();

//
// multisig public key
//

console.log("[Pay to the multi-sig addr]\n");

// Alice            Bob
//  alicePubkey ->
//              <-   bobPubkey
//
// Diffie-Hellman key exchange
//
const alicePubkey = ec.keyFromPrivate(alicePrvkey.value.toString(16)).getPublic();
const bobPubkey = ec.keyFromPrivate(bobPrvkey.value.toString(16)).getPublic();

const multiPubkey = alicePubkey.mul(new BN(bobPrvkey.value.toString()));
console.log("multisig publickey:");
console.log(multiPubkey);

assert(alicePubkey.mul(new BN(bobPrvkey.value.toString())).getX().toString() == bobPubkey.mul(new BN(alicePrvkey.value.toString())).getX().toString());
assert(alicePubkey.mul(new BN(bobPrvkey.value.toString())).getY().toString() == bobPubkey.mul(new BN(alicePrvkey.value.toString())).getY().toString());









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
// Alice            Bob
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


// 
// 2, multiplication and instance key exchange
//

// 2.1, generating bobK and aliceKDash, and open bobD
//
// Alice            Bob
//  aliceKDash       bobK
//
//              <-   bobD
//

const bobK = bigInt(randomBytes(32).toString('hex'), 16);
const aliceKDash = bigInt(randomBytes(32).toString('hex'), 16);

const bobD = ec.keyFromPrivate(bobK.value.toString(16)).getPublic();



// 2.2, calculating R, RDash and aliceK from bobD and aliceKDash
//
// Alice            Bob
//  aliceR
//  aliceRDash
//  aliceK

const aliceRDash = bobD.mul(new BN(aliceKDash.value.toString()));
const aliceK = bigInt(aliceRDash.getX().toString(16), 16)
               .add(aliceKDash);
const aliceR = bobD.mul(new BN(aliceK.value.toString()));



// 2.3, generating phi as a pad (auxiliary valuable)
//
// Alice            Bob
//  alicePhi
//

const alicePhi = bigInt(randomBytes(32).toString('hex'), 16);



// 2.4, three Gilboa protocol (it is like Multiplicative to Additive in GG18 but using Oblivious Transfer Extension)
//
// Alice            Bob
//  t1A              t1B
//  t2A              t2B
//

const [t1A, t1B] = mul(alicePhi.add(aliceK.modInv(order)), bobK.modInv(order));
const [t2A, t2B] = mul(alicePrvkey.multiply(aliceK.modInv(order)), bobPrvkey.multiply(bobK.modInv(order)));


// 2.6, Alice opens RDash and Bob calculates R
//
// Alice            Bob
//  aliceRDash ->
//                   bobR
//

const bobR = bobD.mul(aliceRDash.getX()).add(aliceRDash);

// check that alice's R and bob's R is the same
assert(aliceR.getX().toString() == bobR.getX().toString());
assert(aliceR.getY().toString() == bobR.getY().toString());





//
// Consistency Check, Signature and Verification
//



// 2, Alice opens etaPhi
//
// Alice            Bob
//  aliceGamma1
//  etaPhi   ->
//

const aliceGamma1 = ec.g
                    .add(ec.g.mul(new BN(alicePhi.multiply(aliceK).value.toString())))
                    .add(aliceR.mul(new BN(t1A.negate().value.toString())));

const etaPhi = bigInt(aliceGamma1.getX().toString(16), 16)
               .add(alicePhi);

// 3, Alice opens etaSig (not aliceS)
//
// Alice            Bob
//  aliceS
//  aliceGamma2
//
//  etaSig     ->
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
// Alice            Bob
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
