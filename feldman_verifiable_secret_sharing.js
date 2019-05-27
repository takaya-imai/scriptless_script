const elliptic = require("elliptic").ec;
const ec = new elliptic("secp256k1");
const BN = require('bn.js');
const bigInt = require('big-integer');
const assert = require('assert');
const crypto = require("crypto");




const order = bigInt(ec.n.toString());

//////////////
//
// Feldman's Verifiable Secret Sharing 
//
// setup
//    2-of-3
//
//////////////



//
// generating dealer secret, dealerPrvkey
//

// Dealer         Alice            Bob            Carol
//  secret
//
const dealerPrvkey = bigInt(crypto.randomBytes(32).toString('hex'), 16);


//
// generating a polynomial
//    2-of-3
//
// Dealer         Alice            Bob            Carol
//  dealerCoeff
//
//
const dealerCoeff = bigInt(crypto.randomBytes(32).toString('hex'), 16).mod(order);


//
// creating shares for index [1, 2, 3]
//
// Dealer             Alice            Bob            Carol
//  (1, aliceShare)->
//  (2, bobShare)               ->
//  (3, carolShare)                             ->
//
//  dealerCommit0 ->            ->              ->
//  dealerCommit1 ->            ->              ->
//
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


const dealerCommit0 = ec.keyFromPrivate(dealerPrvkey.value.toString(16)).getPublic();
const dealerCommit1 = ec.keyFromPrivate(dealerCoeff.value.toString(16)).getPublic();
console.log("Dealer Commitment0:");
console.log((dealerCommit0));
console.log("Dealer Commitment1:");
console.log((dealerCommit1));

console.log();


//////////////
//
// Alice checks the share and commitments Dealer sent
// 
//
const aliceSharePubkey = ec.keyFromPrivate(aliceShare.value.toString(16)).getPublic();
const aliceDealerCommitmentPubkey = dealerCommit0.add(dealerCommit1);
console.log("public key from Alice share");
console.log(aliceSharePubkey);
console.log("public key Alice calculates from dealer's commtments");
console.log(aliceDealerCommitmentPubkey);
assert(aliceSharePubkey.getX().toString() == aliceDealerCommitmentPubkey.getX().toString());
assert(aliceSharePubkey.getY().toString() == aliceDealerCommitmentPubkey.getY().toString());

console.log();

//
// Bob checks the share and commitments Dealer sent
//
const bobSharePubkey = ec.keyFromPrivate(bobShare.value.toString(16)).getPublic();
const bobDealerCommitmentPubkey = dealerCommit0.add(dealerCommit1.mul(new BN(2)));
console.log("public key from Bob share");
console.log(bobSharePubkey);
console.log("public key Bob calculates from dealer's commtments");
console.log(bobDealerCommitmentPubkey);
assert(bobSharePubkey.getX().toString() == bobDealerCommitmentPubkey.getX().toString());
assert(bobSharePubkey.getY().toString() == bobDealerCommitmentPubkey.getY().toString());

console.log();

//
// Carol checks the share and commitments Dealer sent
//
const carolSharePubkey = ec.keyFromPrivate(carolShare.value.toString(16)).getPublic();
const carolDealerCommitmentPubkey = dealerCommit0.add(dealerCommit1.mul(new BN(3)));
console.log("public key from Carol share");
console.log(carolSharePubkey);
console.log("public key Carol calculates from dealer's commtments");
console.log(carolDealerCommitmentPubkey);
assert(carolSharePubkey.getX().toString() == carolDealerCommitmentPubkey.getX().toString());
assert(carolSharePubkey.getY().toString() == carolDealerCommitmentPubkey.getY().toString());

//
//////////////
