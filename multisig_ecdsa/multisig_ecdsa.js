const elliptic = require("elliptic").ec;
const ec = new elliptic("secp256k1");
const pjs = require("paillier-js");
const BN = require('bn.js');
const bigInt = require('big-integer');
const assert = require('assert');
const randomBytes = require('randombytes');





const order = bigInt(ec.n.toString());

//////////////
//
// Fast Multiparty Threshold ECDSA with Fast Trustless Setup
//   https://dl.acm.org/citation.cfm?id=3243859
//
// This code is trusted setup version for implementation simplicity.
//
// setup
//    2-of-3
//
//////////////

console.log("[Dealer setups 2-of-3 multisig and send shares to Alice, Bob and Carol]\n");


//
// generating dealer secret, dealerPrvkey
//

// Dealer         Alice            Bob            Carol
//  secret
//
const dealerPrvkey = bigInt(randomBytes(32).toString('hex'), 16);


//
// generating shares
//    2-of-3
//
// shares
// creating shares for index [1, 2, 3]
//  it needs VSS(zk) actually
//
// Dealer         Alice            Bob            Carol
//  dealerCoeff
//
//  aliceShare ->
//  bobShare                ->
//  carolShare                              ->
//
const dealerCoeff = bigInt(randomBytes(32).toString('hex'), 16);

const aliceShare = dealerPrvkey.add(dealerCoeff).mod(order); // for 1
const bobShare = dealerPrvkey.add(bigInt(2).multiply(dealerCoeff)).mod(order); // for 2
const carolShare = dealerPrvkey.add(bigInt(3).multiply(dealerCoeff)).mod(order); // for 3
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

// Dealer             Alice            Bob            Carol
//  dealerPubkey ->            ->              ->
//  
const multiPubkey = ec.keyFromPrivate(dealerPrvkey.value.toString(16)).getPublic();
console.log("multisig publickey:");
console.log(multiPubkey);


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
// Dealer         Alice            Bob            Carol
//                 m       <->      m
//
const m = "Satoshi Nakamoto";
const e = lsb(m);
console.log("message: " + m);
console.log(e);





//
// 2, generating k and gamma for alice and bob
//
// Dealer         Alice            Bob            Carol
//                 aliceK           bobK
//                 aliceGamma       bobGamma
//
const aliceK = bigInt(randomBytes(32).toString('hex'), 16).mod(order);
const aliceGamma = bigInt(randomBytes(32).toString('hex'), 16).mod(order);

const bobK = bigInt(randomBytes(32).toString('hex'), 16).mod(order);
const bobGamma = bigInt(randomBytes(32).toString('hex'), 16).mod(order);



///////////////
//
// 3, converting multicative to additive
//


// 3.1, k and gamma
//
// Dealer         Alice            Bob            Carol
//                 aliceK           bobGamma
//                 aliceGamma       bobK
//
//                 alpha12          beta12
//                 beta21           alpha21
//
//                 aliceDelta       bobDelta
//
const [alpha12, beta12] = multiplicativeToAdditive(aliceK, bobGamma, order);
const [alpha21, beta21] = multiplicativeToAdditive(aliceGamma, bobK, order);

const aliceDelta = aliceK.multiply(aliceGamma).add(alpha12).add(beta21);
const bobDelta = bobK.multiply(bobGamma).add(alpha21).add(beta12);


// Dealer         Alice            Bob            Carol
//                 aliceDelta  <->  bobDelta
//                 delta            delta
//

const delta = aliceDelta.add(bobDelta).mod(order);

// check k * gamma = aliceDelta + bobDelta
// it is not needed actually
const k = aliceK.add(bobK);
const gamma = aliceGamma.add(bobGamma);
assert(k.multiply(gamma).mod(order).value == delta.value);


//
// 3.2, k and private key(omega)
//
//
// Dealer         Alice            Bob            Carol
//                 aliceLambda
//                                  bobLambda
//
//                 aliceK           bobK
//                 aliceOmega      bobOmega
//
//                 mu12             nu12
//                 nu21             mu21
//
//                 aliceSigma       bobSigma
//
const aliceLambda = bigInt(2);
const bobLambda = bigInt(1).negate();


const aliceOmega = aliceLambda.multiply(aliceShare);
const bobOmega = bobLambda.multiply(bobShare).add(order); // add(order) makes bobOmega positive

// check that lambdas meet lagurange interpolation equation
// it is not needed actually
assert(aliceOmega.add(bobOmega).mod(order).value.toString(16) == dealerPrvkey.mod(order).value.toString(16));



const [mu12, nu12] = multiplicativeToAdditive(aliceK, bobOmega, order);
const [nu21, mu21] = multiplicativeToAdditive(aliceOmega, bobK, order);

const aliceSigma = aliceK.multiply(aliceOmega).add(mu12).add(nu21);
const bobSigma = bobK.multiply(bobOmega).add(mu21).add(nu12);

// k * x = aliceSigma + bobSigma
// actually it is not possible, private key is correct
assert(k.multiply(aliceOmega.add(bobOmega)).mod(order).value == aliceSigma.add(bobSigma).mod(order).value);


//
// 4, creating signature r
//


// Dealer         Alice                 Bob               Carol
//                 alicePubkeyGamma <->  bobPubkeyGamma
//                 r                     r
//
const alicePubkeyGamma = ec.keyFromPrivate(aliceGamma.value.toString(16)).getPublic();
const bobPubkeyGamma = ec.keyFromPrivate(bobGamma.value.toString(16)).getPublic();

const pubkeyR = ec.keyFromPrivate(aliceGamma.add(bobGamma).multiply(delta.modInv(order)).mod(order).value.toString(16)).getPublic();

assert(pubkeyR.getX().toString(16) == ec.keyFromPrivate(k.modInv(order).value.toString(16)).getPublic().getX().toString(16));
assert(pubkeyR.getY().toString(16) == ec.keyFromPrivate(k.modInv(order).value.toString(16)).getPublic().getY().toString(16));

const r = bigInt(hDash(pubkeyR).toString(16), 16).mod(order);


//
// 5, creating signature s
//


// Dealer         Alice            Bob            Carol
//                 aliceS   <->     bobS
//                 s                s
//
const aliceS = e.multiply(aliceK).add(r.multiply(aliceSigma));
const bobS = e.multiply(bobK).add(r.multiply(bobSigma));

const s = aliceS.add(bobS).mod(order);


//
// 6, signature verification
//

const sig = {r: r.toString(16), s: s.toString(16)}; // DER format in the case of BTC
console.log("signature");
console.log(sig);

console.log(ec.keyFromPublic(multiPubkey).verify(m, sig));


// returns alpha and beta as additive
function multiplicativeToAdditive(a, b, order){
    // alice creates Paillier keypair
    //
    // Alice            Bob
    //  prvkeyPjs
    //  pubkeyPjs  ->
    //
    let {publicKey, privateKey} = pjs.generateRandomKeys(1024);
    let prvkeyPjs = privateKey;
    let pubkeyPjs = publicKey;


    // "a" and "b" are a BN object

    // Alice            Bob
    //  a                b


    // Alice            Bob
    //  cA  ->
    //
    let cA = pubkeyPjs.encrypt(a);


    // Alice            Bob
    //                   betaDash
    //          <-       cB
    //
    let betaDash = bigInt(randomBytes(32).toString('hex'), 16);
    let cB = pubkeyPjs.addition(
        pubkeyPjs.multiply(
            cA,
            b
        ),
        pubkeyPjs.encrypt(betaDash)
    );



    // Alice            Bob
    //  alpha            beta
    //
    let alpha = prvkeyPjs.decrypt(cB).mod(order);
    let beta = betaDash.negate().mod(order) > 0 ? betaDash.negate().mod(order) : betaDash.negate().mod(order).add(order).mod(order);

    // check: a * b = alpha + beta
    assert(a.multiply(b).mod(order).value == alpha.add(beta).mod(order).value);

    return [alpha, beta];
};

function hDash(pubkey){
    return pubkey.getX();
};

// transform m to e by LSB
function lsb(m){
    let mHex = new BN(m, 16);
    let delta = mHex.byteLength() * 8 - ec.n.bitLength();
    return bigInt(mHex.ushrn(delta > 0 ? delta : 0).toString(16), 16);
};
