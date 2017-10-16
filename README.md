# A lightweight Attribute-Based Encryption Scheme in C++

This project is a C++ implementation of the lightweight Key-Policy Attribute-Based
Encryption (KP-ABE) scheme from [1].

The scheme has significant performance advantages[2] over other schemes by relying on
elliptic curve cryptography as opposed to bilinear pairings. Its security is proved in
the attribute-based selective-set model.

The implementation can run on a [ESP32](https://github.com/espressif/esp-idf)
device with slight modifications. I removed these modifications for simplicity, but if
you are interested in running it on an ESP32, open an issue and I will add it.
# Compilation
## Dependencies
The project depends on:

* [gmp](https://gmplib.org) - The GNU Multiple Precision Arithmetic Library
* [pbc](https://crypto.stanford.edu/pbc/) - Pairing-Based Cryptography Library
* mbedcrypto from [mbedtls](https://tls.mbed.org)
* (for the tests only) [Boost.Test](http://www.boost.org/doc/libs/1_65_1/libs/test/doc/html/index.html)

## Compiling
The project compiles with [scons](http://scons.org) in the root directory. Just run:

```sh
scons -f SConstruct.py
```

This generates the static library `libkpabe`, but it's straightforward to compile with
your code without using a library. The above also produces the tests (`kpabe_test`) and a
simple example program (`main`).

The reason that this is compiled as a static library and that it uses mbedtls instead of
some other common crypto is because the project had to run on a ESP32
device. 

# API
Here is a simple example of generating a key and a secret and then using the key to
recover the secret.

```c++
// Setup the scheme
PrivateParams priv;
PublicParams pub;
vector <int> attributeUniverse {1, 2, 3, 4, 5};
setup(attributeUniverse, pub, priv);

// Create an access policy and derive a key for it.
// (1 OR 2) AND (3 OR 4)
Node root(Node::Type::AND);
Node orNodeLeft(Node::Type::OR, {Node(1), Node(2)});
Node orNodeRight(Node::Type::OR, {Node(3), Node(4)});
root.addChild(orNodeLeft);
root.addChild(orNodeRight);

auto key = keyGeneration(priv, root);

// Create an attribute-based secret (attributes 1 and 3).
element_s secret;
vector<int> encryptionAttributes {1, 3};
auto Cw = createSecret(pub, encryptionAttributes, secret); // Decryption parameters

// Recover secret
element_s recovered;
recoverSecret(key, Cw, attributes, recovered);
element_cmp(&secret, recovered); // should be ==0

for(auto& attrCiPair: Cw) { //clean up
   element_clear(&attrCiPair.second);
}

// Secret cannot be recovered if the policy is not satisfied by the encryption attributes.
encryptionAttributes = {1};
Cw = createSecret(pub, encryptionAttributes, secret);
try {
   recoverSecret(key, Cw, encryptionAttributes, recovered);
} catch(const UnsatError& e) {
   cout << "Unsatisfied" << endl;
}

// Clean up (this should happen as part of destruction, so my bad)
for(auto& attrDiPair: key.Di) {
   element_clear(&attrDiPair.second);
}

for(auto& attrCiPair: Cw) {
   element_clear(&attrCiPair.second);
}
```

I would like to change at least a few things in the API, should I find the time.
Suggestions are always welcome.

There is also a [python implementation](https://github.com/JHUISI/charm/blob/dev/charm/schemes/abenc/abenc_yct14.py) of this scheme as part of Charm.

# Issues
It should be possible to use the same attribute more than once in a policy - e.g.
*((1 OR 2) AND (1 OR 3))*. However, the current implementation does not allow this.

# References
[1]   *X. Yao, Z. Chen and Y. Tian, “A lightweight attribute-based encryption scheme for the Internet of Things,” Future Generation Computer Systems, vol. 49, pp. 104-112, 2015.*
[link](http://www.sciencedirect.com/science/article/pii/S0167739X14002039)

[2]   *S. Zickau, D. Thatmann, A. Butyrtschik, I. Denisow and A. Küpper, “Applied Attribute- based Encryption Schemes,” in 19th International ICIN Conference - Innovations in Clouds, Internet and Networks, Paris, 2016.*
[link](http://dl.ifip.org/db/conf/icin/icin2016/1570228068.pdf)