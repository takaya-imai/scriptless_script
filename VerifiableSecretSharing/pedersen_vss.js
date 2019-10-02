const elliptic = require("elliptic").ec;
const ec = new elliptic("secp256k1");
const BN = require('bn.js');
const bigInt = require('big-integer');
const assert = require('assert');
const randomBytes = require('randombytes');




const order = bigInt(ec.n.toString());

//////////////
//
// Pedersen's Verifiable Secret Sharing 
//
// setup
//    2-of-3
//
//////////////



//
// generating a polynomial (dealer secret and coefficients)
//
// Dealer         Alice            Bob            Carol
//  dealerPrvkey 
//  dealerCoeff
//  dealerPrvkeyDash
//  dealerCoeffDash
//
//
const dealerPrvkey = bigInt(randomBytes(32).toString('hex'), 16).mod(order);
const dealerCoeff = bigInt(randomBytes(32).toString('hex'), 16).mod(order);

const dealerPrvkeyDash = bigInt(randomBytes(32).toString('hex'), 16).mod(order);
const dealerCoeffDash = bigInt(randomBytes(32).toString('hex'), 16).mod(order);


//
// creating shares for index [1, 2, 3]
//
// Dealer                   Alice            Bob            Carol
//  (1, aliceShare)     ->
//  (2, bobShare)                    ->
//  (3, carolShare)                                  ->
//
//  (1, aliceShareDash) ->
//  (2, bobShareDash)               ->
//  (3, carolShareDash)                              ->
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

const aliceShareDash = dealerPrvkeyDash.add(dealerCoeffDash).mod(order); // for 1
const bobShareDash = dealerPrvkeyDash.add(bigInt(2).multiply(dealerCoeffDash)).mod(order); // for 2
const carolShareDash = dealerPrvkeyDash.add(bigInt(3).multiply(dealerCoeffDash)).mod(order); // for 3
console.log("alice share':");
console.log(aliceShareDash.toString(16));
console.log("bob share':");
console.log(bobShareDash.toString(16));
console.log("carol share':");
console.log(carolShareDash.toString(16));

console.log();


//
// creating commitments
//
// Dealer                   Alice            Bob            Carol
//  h                 ->            ->              ->
//
//  dealerCommit0     ->            ->              ->
//  dealerCommit1     ->            ->              ->
//

// h: another generator
const h = ec.genKeyPair().getPublic();

const dealerCommit0 = ec.keyFromPrivate(dealerPrvkey.value.toString(16)).getPublic()
                        .add(h.mul(dealerPrvkeyDash.value.toString(16)));
const dealerCommit1 = ec.keyFromPrivate(dealerCoeff.value.toString(16)).getPublic()
                        .add(h.mul(dealerCoeffDash.value.toString(16)));
console.log("Dealer Commitment0:");
console.log((dealerCommit0));
console.log("Dealer Commitment1:");
console.log((dealerCommit1));

console.log();


//////////////
//
// Alice checks the share and commitments which Dealer sent
// 
//
const aliceShareSum = ec.keyFromPrivate(aliceShare.value.toString(16)).getPublic()
                        .add(h.mul(aliceShareDash.value.toString(16)));
const aliceDealerCommitmentSum = dealerCommit0.add(dealerCommit1);
console.log("public key from Alice's share");
console.log(aliceShareSum);
console.log("public key which Alice calculates from dealer's commtments");
console.log(aliceDealerCommitmentSum);
assert(aliceShareSum.getX().toString() == aliceDealerCommitmentSum.getX().toString());
assert(aliceShareSum.getY().toString() == aliceDealerCommitmentSum.getY().toString());

console.log();

//
// Bob checks the share and commitments which Dealer sent
//
const bobShareSum = ec.keyFromPrivate(bobShare.value.toString(16)).getPublic()
                        .add(h.mul(bobShareDash.value.toString(16)));
const bobDealerCommitmentSum = dealerCommit0.add(dealerCommit1.mul(2));
console.log("public key from Bob's share");
console.log(bobShareSum);
console.log("public key which Bob calculates from dealer's commtments");
console.log(bobDealerCommitmentSum);
assert(bobShareSum.getX().toString() == bobDealerCommitmentSum.getX().toString());
assert(bobShareSum.getY().toString() == bobDealerCommitmentSum.getY().toString());

console.log();

//
// Carol checks the share and commitments which Dealer sent
//
const carolShareSum = ec.keyFromPrivate(carolShare.value.toString(16)).getPublic()
                        .add(h.mul(carolShareDash.value.toString(16)));
const carolDealerCommitmentSum = dealerCommit0.add(dealerCommit1.mul(3));
console.log("public key from Carol's share");
console.log(carolShareSum);
console.log("public key which Carol calculates from dealer's commtments");
console.log(carolDealerCommitmentSum);
assert(carolShareSum.getX().toString() == carolDealerCommitmentSum.getX().toString());
assert(carolShareSum.getY().toString() == carolDealerCommitmentSum.getY().toString());

//
//////////////
