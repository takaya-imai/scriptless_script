# scriptless_script

* This is a sample code repository.

# DISCLAIMER

* USE CODES IN THIS REPOSITORY AT YOUR OWN RISK.

# Execution Example

* aos_ring_signature.js

```
$ node aos_ring_signature.js
alicePubkey:
<EC Point x: ec4e3bd246edce3dfa13ffb39893f3e5b3e4b83e075ae49070f285e453d763c8 y: d7b3a8f4c15215139dbcd7798929bf26126566e134ce4ef20b3ad8cfa437fd89>
bobPubkey:
<EC Point x: 7f1951d244393b925306c525c248ca303a9e34db7bba46930cb97a99cf28e97c y: e3e27b5749ef50bbd3734c2cc24bdbe2724104585ad3819f409e80f0943a7ac3>
carolPubkey:
<EC Point x: 2b196b48de93ce9948c78e667310c7149b033e0b0eaae5506c42622f75e64db2 y: b414ad8f48f40f3795ececa0ef134f1441028aa265855f14275506e8bf241111>

message: Satoshi Nakamoto

AOS ring signature:
{ e0:
   '844d02d20e0da11a1aada057cca2fadc48d47b591924a29abaa42a71681f8bee',
  s0:
   'db2f7edd8cdd660e589af788e6a1b90848243d34dbe0154042ed5989eb9dfd61',
  s1:
   'c5f6d0730fb58b50088eecf5c6da16bd02e228cf49454238f96ade9feec01857',
  s2:
   'f0a215435c8e4a6b04e9930ccbbd8aa9942eb63a70edf528f040f70f41b76f89' }

the signature is valid?:
true
an order of pubkeys is different(reflection). the signature is valid for this pukeys?:
false
an order of pubkeys is different(cyclic). the signature is valid for this pubkeys?:
false
```

* multisig_ecdsa/GG18/alice-bob_2of3.js

```
$ node multisig_ecdsa/GG18/alice-bob_2of3.js
[Dealer setups 2-of-3 multisig and send shares to Alice, Bob and Carol]

alice share:
44ccaba7d57aa8771df00b35c8c3ef176709ebdfac0d55835dad5b5d4a4bad4
bob share:
72c4bad358b9c5e034d999e804c4f24759779070ada1d3aa92a5faae8540609f
carol share:
e13caaec341be138f7d4331cacfda59d3c7e82236082d1fcef711fa735dc066a

[Pay to the multi-sig addr]

multisig publickey:
<EC Point x: f863539e5c2fd52b0f2c64fa440a543a51a5964137ed10d745f4db2b46a9b6f2 y: 36ec10f928a7aea27064739446e4b49163ffcb71044e56b862c2afd883e34f72>

[unlock by Alice and Bob]

message: Satoshi Nakamoto
{ [Number: 262602451968515900] value: 262602451968515919n }
signature
{ r:
   '21e9cded5dc1763de3407e6b42270314b4c3d6d1ecc2e901cef39e24157b1b8e',
  s:
   '7680d857d80ee713d7c49edab2dba7ab969431497e796fdbc14aa06e509d1e2a' }
true
```

* multisig_ecdsa/DKOSS19/2of3.js

```
$ node multisig_ecdsa/DKOSS19/2of3.js
[Each players setups 2-of-3 multisig and send shares to Alice, Bob and Carol each other]

alice share:
f6b6e2a9f9b76590eda5f84a63dc2125493b92fdf9c6e468fa198f027360d3ab
bob share:
1c810bca459f675b3f3c93b76511887351cd2f21b8cf4c019ead03d69fd9c512
carol share:
424b34ea9187692590d32f246646efc0150da82c272053d60312d7379c88f7ba

[Pay to the multi-sig addr]

multisig publickey:
<EC Point x: b856dbf37beb07547ecd367f08130c14bedbe47d0af3536268d196056734ef3d y: bddee8e3f618049f87aa7eb8cdef569d1fa243e9937ac687291e16f7159aec44>

[unlock by Alice and Bob]

message: Satoshi Nakamoto
{ [Number: 1.0142666630799874e+64]
  value:
   10142666630799874325011227401619526506411153385155426573377048844n }
signature
{ r:
   'fc3da3ebd99d6e8d078f29cd628153fa2e6a56ec7954b165a855fe6356feda94',
  s:
   'ba966b227a6951d9a434f264a75e7cd24c24ea36ee682ed39e5739c6e8314be0' }

signature is valid?
true
Alice broadcasts tx with one '2 of 3' valid signature
```

# Environment

* nodejs

```
$ node -v
v10.8.0
```
