const elliptic = require("elliptic").ec;
const ec = new elliptic("secp256k1");
const BN = require("bn.js");
const bigInt = require("big-integer");
const randomBytes = require("randombytes");
const sha256 = require("js-sha256");



const order = bigInt(ec.n.toString());

//
// AOS ring signature
//    ECC(secp256k1) + schnorr signature
// 

///////////
//   
// setup
//
// generating basic keypairs and public
//
// Alice           Bob          Carol
//  aliceKeyPair    bobKeyPair   carolKeyPair
//  alicePubkey     bobPubkey    carolPubkey
//
const aliceKeyPair = ec.genKeyPair();
const alicePubkey = aliceKeyPair.getPublic();
console.log("alicePubkey: ");
console.log(alicePubkey);

const bobKeyPair = ec.genKeyPair();
const bobPubkey = bobKeyPair.getPublic();
console.log("bobPubkey: ");
console.log(bobPubkey);

const carolKeyPair = ec.genKeyPair();
const carolPubkey = carolKeyPair.getPublic();
console.log("carolPubkey: ");
console.log(carolPubkey);

console.log();



///////////
//   
// creating aos ring signature and verify it
//

// message
const m = "Satoshi Nakamoto";
console.log("message: " + m);
console.log();

// creating a signature
const pubkeys = [alicePubkey, bobPubkey, carolPubkey];
const sig = sign(m, pubkeys, bobKeyPair);
console.log("AOS ring signature:");
console.log(sig);
console.log();

// verification
console.log("the signature is valid?:");
console.log(verify(m, pubkeys, sig));

const pubkeys2 = [bobPubkey, alicePubkey, carolPubkey];
console.log("an order of pubkeys is different(reflection). the signature is valid for this pukeys?:");
console.log(verify(m, pubkeys2, sig));

const pubkeys3 = [carolPubkey, alicePubkey, bobPubkey];
console.log("an order of pubkeys is different(cyclic). the signature is valid for this pubkeys?:");
console.log(verify(m, pubkeys3, sig));

function sign(m, pubkeys, signerKeyPair){
    // "pubkeys" contains public key of Alice, Bob and Carol.
    // a signer is Bob in this case.

    //let u = bigInt(crypto.randomBytes(32).toString('hex'), 16).mod(order);
    let u = bigInt(randomBytes(32).toString('hex'), 16).mod(order);
    let e2 = hash(m, ec.keyFromPrivate(u.toString(16)).getPublic());

    //let s2 = bigInt(crypto.randomBytes(32).toString('hex'), 16).mod(order);
    let s2 = bigInt(randomBytes(32).toString('hex'), 16).mod(order);
    let s2Pubkey = ec.keyFromPrivate(s2.toString(16)).getPublic();
    let e2K = pubkeys[2].mul(new BN(e2, 16));
    let e0 = hash(m, s2Pubkey.add(e2K));

    //let s0 = bigInt(crypto.randomBytes(32).toString('hex'), 16).mod(order);
    let s0 = bigInt(randomBytes(32).toString('hex'), 16).mod(order);
    let s0Pubkey = ec.keyFromPrivate(s0.toString(16)).getPublic();
    let e0K = pubkeys[0].mul(new BN(e0, 16));
    let e1 = hash(m, s0Pubkey.add(e0K));

    let s1 = u.add(
        bigInt(e1, 16).multiply(
            bigInt(signerKeyPair.getPrivate().toString(16), 16)
        ).mod(order).negate()
    );

    return {
        'e0': e0,
        's0': s0.mod(order).value.toString(16),
        's1': s1 > 0 ? s1.mod(order).value.toString(16) : s1.add(order).mod(order).value.toString(16),
        's2': s2.mod(order).value.toString(16)
    };
};



function verify(m, pubkeys, sig){
    // "pubkeys" contains public key of Alice, Bob and Carol.
    // verifier does not need to know who is a signer.

    let s0Pubkey = ec.keyFromPrivate(sig.s0).getPublic();
    let e0K = pubkeys[0].mul(new BN(sig.e0, 16));
    let e1 = hash(m, s0Pubkey.add(e0K));

    let s1Pubkey = ec.keyFromPrivate(sig.s1).getPublic();
    let e1K = pubkeys[1].mul(new BN(e1, 16));
    let e2 = hash(m, s1Pubkey.add(e1K));

    let s2Pubkey = ec.keyFromPrivate(sig.s2).getPublic();
    let e2K = pubkeys[2].mul(new BN(e2, 16));
    let e0Dash = hash(m, s2Pubkey.add(e2K));

    return sig.e0 == e0Dash;
};



function hash(m, pubkey){
    let mHex = new BN(m, 16);
    //return crypto.createHash('sha256').update(bigInt(pubkey.encode('hex'), 16).add(bigInt(mHex, 16)).toString(16)).digest("hex");
    return sha256.create().update(bigInt(pubkey.encode('hex'), 16).add(bigInt(mHex, 16)).toString(16)).hex();
};
