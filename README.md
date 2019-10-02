# scriptless_script

* This is a sample code repository.

# DISCLAIMER

* USE CODES IN THIS REPOSITORY AT YOUR OWN RISK.

# Execution Example

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

```
$ node scriptless_script/multisig_ecdsa/GG18/alice-bob_2of3.js
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

```
$ node scriptless_script/multisig_ecdsa/DKOSS19/2of3.js
[Each players setups 2-of-3 multisig and send shares to Alice, Bob and Carol each other]

alice share:
modify directory name
6116f5eca969f409e738906f138cd379b07521290d381c496e9cf75df323f1cf
bob share:
9fecc6d47acabcf92334813d0d75a1c131e6c8416e43cc44c9000944bda62686
carol share:
dec297bc4c2b85e85f30720b075e7008b3586f59cf4f7c4023631b2b88285b3d

[Pay to the multi-sig addr]

multisig publickey:
<EC Point x: a038d2088706dcdaa39eb789f01378bc1e8aa8fc5ca18b47b74b1ef8ee1f3634 y: 1096228af73b8b5103daafd4b5d96a4e666ba1458293a66a792ee6f29c5680b1>

[unlock by Alice and Bob]

message: Satoshi Nakamoto
modify file names
{ [Number: 1.0142666630799874e+64]
  value:
   10142666630799874325011227401619526506411153385155426573377048844n }
signature
{ r:
   '525fcb90b6a7cde913229c84b085d3a235cbe79165c649115629f35d4cf5f6df',
  s:
   '79800786dfa0bbaebd5cb4abdaf66251931667623b7a93a3fc0c349b2751e92b' }

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
