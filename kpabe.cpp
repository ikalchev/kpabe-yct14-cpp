#include <string>
#include <map>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <functional>
#include <array>
#include <vector>

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
#include <pbc.h>

#include "kpabe.hpp"

using namespace std;

// For the encrypt/decrypt methods.
static const size_t AES_BLOCK_SIZE = 16;
static const size_t AES_KEY_SIZE = 32;

pairing_s pairing;
bool isInit = false;

pairing_ptr getPairing() {
   if(!isInit) {
      pairing_init_set_str(&pairing, TYPE_A_PARAMS.c_str());
      isInit = true;
   }
   return &pairing;
}

void hashElement(element_t e, uint8_t* hashBuf) {
   const int elementSize = element_length_in_bytes(e);
   uint8_t* elementBytes = new uint8_t[elementSize + 1];
   element_to_bytes(elementBytes, e);

   //TODO: use mbedtls_sha256
   auto mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
   mbedtls_md(mdInfo, elementBytes, elementSize, hashBuf);
   
   delete [] elementBytes;
}

/**
 * Common interface to for symmetric encryption and decryption.
 *
 * Uses AES-256-CBC and zero-filled IV.
 */
void mbedtlsSymCrypt(const uint8_t* input, size_t ilen, uint8_t* key, uint8_t* output, size_t* olen, mbedtls_operation_t mode) {
   const auto cipherInfo = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
   mbedtls_cipher_context_t ctx;
   mbedtls_cipher_setup(&ctx, cipherInfo);
   mbedtls_cipher_setkey(&ctx, key, cipherInfo->key_bitlen, mode);
   array<uint8_t, 16> iv;
   iv.fill(0);
   mbedtls_cipher_crypt(&ctx, iv.data(), cipherInfo->iv_size, input, ilen, output, olen);
}

void symEncrypt(const uint8_t* input, size_t ilen, uint8_t* key, uint8_t* output, size_t* olen) {
   mbedtlsSymCrypt(input, ilen, key, output, olen, MBEDTLS_ENCRYPT);
}

void symDecrypt(const uint8_t* input, size_t ilen, uint8_t* key, uint8_t* output, size_t* olen) {
   mbedtlsSymCrypt(input, ilen, key, output, olen, MBEDTLS_DECRYPT);
}

// Node

Node::Node(const Node& other) {
   attr = other.attr;
   type = other.type;
   children = other.children;
}

Node::Node(Node&& other):
   attr(move(other.attr)),
   type(other.type),
   children(move(other.children)) {
}

Node::Node(int attr) {
   this->attr = attr;
}

Node::Node(Type type, const vector<Node>& children) {
   this->children = children;
   this->type = type;
}

Node& Node::operator=(Node other) {
   //TODO: check if not self
   swap(attr, other.attr);
   swap(type, other.type);
   swap(children, other.children);
   return *this;
}

Node& Node::operator=(Node&& other) {
   //assert(this != &other);
   attr = move(other.attr);
   type = move(other.type);
   children = move(other.children);
   return *this;
}

void Node::addChild(const Node& node) {
   children.push_back(node);
}

vector<int> Node::getLeafs() const {
   vector<int> attrs;

   if(children.empty()) {
      // Handles non-leaf node with one child
      attrs.push_back(attr);
   } else {
      for(const Node& child: children) {
         if(child.children.empty()) {
            attrs.push_back(child.attr);
         } else {
            auto childAttrs = child.getLeafs();
            attrs.reserve(attrs.size() + childAttrs.size());
            attrs.insert(attrs.end(), childAttrs.begin(), childAttrs.end());
         }
      }
   }
   return attrs;
}

unsigned int Node::getThreshold() const {
   return type == Type::OR ? 1 : static_cast<unsigned int>(children.size());
}

unsigned int Node::getPolyDegree() const {
   return getThreshold() - 1;
}

vector<element_s> Node::splitShares(element_s& rootSecret) {
   // Generate the coefficients for the polynomial.
   auto threshold = getThreshold();
   vector<element_s> coeff(threshold);
   
   element_init_same_as(&coeff[0], &rootSecret);
   element_set(&coeff[0], &rootSecret);
   
   // Generate random coefficients, except for q(0), which is set to the rootSecret.
   for(int i = 1; i <= getPolyDegree(); ++i) {
      element_init_same_as(&coeff[i], &rootSecret);
      element_random(&coeff[i]);
   }

   // Calculate the shares for each child.
   vector<element_s> shares(children.size());
   
   element_t temp;
   element_init_Zr(temp, getPairing());

   // The scheme decription defines an ordering on the children in a node (index(x)).
   // Here, we implicitly use a left to right order.
   for(int x = 1; x <= children.size(); ++x) {
      auto share = &shares[x - 1];
      element_init_same_as(share, &rootSecret);
      element_set0(share);
      // share = coeff[0] + coeff[1] * x + ... + coeff[threshold - 1] * x ^ (threshold - 1)
      for(int power = 0; power < coeff.size(); ++power) {
         element_set_si(temp, pow(x, power)); //TODO: handle pow
         element_mul(temp, temp, &coeff[power]);
         element_add(share, share, temp);
      }
   }
   
   element_clear(temp);
   for(element_s& c: coeff) {
      element_clear(&c);
   }
   
   return shares;
}//splitShares

vector<element_s> Node::getSecretShares(element_s& rootSecret) {
   vector<element_s> shares;
   if(children.empty()) {
      shares.push_back(rootSecret);
   } else {
      auto childSplits = splitShares(rootSecret);
      auto childSplitsIter = childSplits.begin();
      for(Node& child: children) {
         auto childShares = child.getSecretShares(*childSplitsIter++);
         shares.reserve(shares.size() + childShares.size());
         shares.insert(shares.end(), childShares.begin(), childShares.end());
      }
   }
   
   return shares;
}

vector<element_s> Node::recoverCoefficients() {
   auto threshold = getThreshold();
   vector<element_s> coeff(threshold);

   element_t iVal, jVal, temp;
   element_init_Zr(iVal, getPairing());
   element_init_Zr(jVal, getPairing());
   element_init_Zr(temp, getPairing());
   
   for(int i = 1; i <= threshold; ++i) {
      element_set_si(iVal, i);
      element_s& result = coeff[i - 1];
      element_init_Zr(&result, getPairing());
      element_set1(&result);
      for(int j = 1; j <= threshold; ++j) {
         if(i == j) {
            continue;
         }
         // result *= (0 - j) / (i - j)
         element_set_si(jVal, -j);
         element_add(temp, iVal, jVal);
         element_div(temp, jVal, temp);
         element_mul(&result, &result, temp);
      }
   }

   element_clear(iVal);
   element_clear(jVal);
   element_clear(temp);
   
   return coeff;
}


vector< pair<int, element_s> >
Node::satisfyingAttributes(const vector<int>& attributes,
                           element_s& currentCoeff) {
   vector< pair<int, element_s> > sat;

   if (children.empty()) {
      if(find(attributes.begin(), attributes.end(), attr) != attributes.end()) {
         sat.push_back({attr, currentCoeff});
      }
   } else {
      auto recCoeffs = recoverCoefficients();
      
      if(type == Type::AND) {
         bool allSatisfied = true;
         vector< pair<int, element_s> > totalChildSat;
         for(int i = 0; i < children.size(); ++i) {
            element_mul(&recCoeffs[i], &recCoeffs[i], &currentCoeff);
            auto childSat = children[i].satisfyingAttributes(attributes, recCoeffs[i]);
            if(childSat.empty()) {
               allSatisfied = false;
               break;
            }
            totalChildSat.reserve(totalChildSat.size() + childSat.size());
            totalChildSat.insert(totalChildSat.end(), childSat.begin(), childSat.end());
         }
         if(allSatisfied) {
            sat = totalChildSat;
         }
      } else {
         auto& recCoeff0 = recCoeffs[0];
         element_mul(&recCoeff0, &recCoeff0, &currentCoeff);
         for (auto& child: children) {
            // TODO: Optimization -
            // Should return the shortest non-empty childSat instead of the first one.
            auto childSat = child.satisfyingAttributes(attributes, recCoeff0);
            if(!childSat.empty()){
               sat = childSat;
               break;
            }
         }
      }
   }
   
   return sat;
}

const vector<Node>& Node::getChildren() const {
   return children;
}

// DecryptionKey

DecryptionKey::DecryptionKey(const Node& policy): accessPolicy(policy) { }

// Algorithm Setup

void setup(const vector<int>& attributes,
           PublicParams& publicParams,
           PrivateParams& privateParams) {
   element_init_Zr(&privateParams.mk, getPairing());
   element_random(&privateParams.mk);
   
   element_t g;
   element_init_G1(g, getPairing());
   element_random(g);
   
   // Generate a random public and private element for each attribute
   for(auto attr: attributes) {
      // private
      element_s& si = privateParams.Si[attr];
      element_init_Zr(&si, getPairing());
      element_random(&si);
      
      // public
      element_s& Pi = publicParams.Pi[attr];
      element_init_G1(&Pi, getPairing());
      element_pow_zn(&Pi, g, &si);
   }
   
   element_init_G1(&publicParams.pk, getPairing());
   element_pow_zn(&publicParams.pk, g, &privateParams.mk);
   element_clear(g);
}

/**
 * @brief An abstraction of createKey that allows different operation for hiding the
 *    secret shares.
 *
 * @param scramblingFunc A function that sets an element to the result of a function on
 *    a scambling key and a secret share. In the original paper the scrambling keys are
 *    the private keys and the function is division. The result of the scrambling is put
 *    in the first element, the shares in the second, the scramblng keys in the third.
 * @type scramblingFunc function<void (element_t, element_t, element_t)>
 */
DecryptionKey _keyGeneration(element_s& rootSecret,
                             map<int, element_s>& scramblingKeys,
                             function<void (element_t, element_t, element_t)> scramblingFunc,
                             Node& accessPolicy) {
   auto leafs = accessPolicy.getLeafs();
   auto shares = accessPolicy.getSecretShares(rootSecret);
   
   DecryptionKey key(accessPolicy);
   auto attrIter = leafs.begin();
   auto sharesIter = shares.begin();
   // The below is: Du[attr] = shares[attr] / attributeSecrets[attr]
   for(; attrIter != leafs.end(); ++attrIter, ++sharesIter) {
      element_s& attrDi = key.Di[*attrIter];
      element_init_Zr(&attrDi, getPairing());
      scramblingFunc(&attrDi, &*sharesIter, &scramblingKeys[*attrIter]);
   }
   
   for(element_s& share: shares) {
      element_clear(&share);
   }
   
   return key;
}


DecryptionKey keyGeneration(PrivateParams& privateParams,
                            Node& accessPolicy) {
   return _keyGeneration(privateParams.mk, privateParams.Si, element_div, accessPolicy);
}

Cw_t createSecret(PublicParams& params,
                  const vector<int>& attributes,
                  element_s& Cs) {
   element_t k;
   element_init_Zr(k, getPairing());
   element_random(k);
   
   element_init_G1(&Cs, getPairing());
   element_pow_zn(&Cs, &params.pk, k);
   
   Cw_t Cw;
   for(auto attr: attributes) {
      element_s& i = Cw[attr];
      element_init_G1(&i, getPairing());
      element_pow_zn(&i, &params.Pi[attr], k);
   }
   element_clear(k);
   
   return Cw;
}

void recoverSecret(DecryptionKey& key,
                   Cw_t& Cw,
                   const vector<int>& attributes,
                   element_s& Cs) {
   // Get attributes that can satisfy the policy (and their coefficients).
   element_t rootCoeff;
   element_init_Zr(rootCoeff, getPairing());
   element_set1(rootCoeff);
   auto attrs = key.accessPolicy.satisfyingAttributes(attributes, *rootCoeff);
   element_clear(rootCoeff);

   if(attrs.empty()) {
      throw UnsatError();
      return;
   }
   
   element_t Zy;
   element_init_G1(&Cs, getPairing());
   element_init_G1(Zy, getPairing());
   bool pastFirst = false; // Is this the first "part" of the product
   
   // product = P(Ci ^ (Di * coeff(i)))
   // NOTE: attrCoeffPair is modified
   for(auto& attrCoeffPair: attrs) {
      element_mul(&attrCoeffPair.second, &key.Di[attrCoeffPair.first], &attrCoeffPair.second);
      element_pow_zn(Zy, &Cw[attrCoeffPair.first], &attrCoeffPair.second);
   
      if (pastFirst) {
         element_mul(&Cs, &Cs, Zy);
      } else {
         pastFirst = true;
         element_set(&Cs, Zy);
      }
   }
   
   for(auto& attrCoeffPair: attrs){
      element_clear(&attrCoeffPair.second);
   }
   element_clear(Zy);
}

std::vector<uint8_t> encrypt(PublicParams& params,
                             const vector<int>& attributes,
                             const string& message,
                             Cw_t& Cw) {
   element_s Cs;
   Cw = createSecret(params, attributes, Cs);
   
   // Use the key to encrypt the data using a symmetric cipher.
   size_t messageLen = message.size() + 1; // account for terminating byte
   size_t cipherMaxLen = messageLen + AES_BLOCK_SIZE;
   vector<uint8_t> ciphertext(cipherMaxLen);
   
   array<uint8_t, AES_KEY_SIZE> key;
   hashElement(&Cs, key.data());
   size_t clength = 0;
   symEncrypt((uint8_t*) message.c_str(), messageLen, key.data(), ciphertext.data(), &clength);
   ciphertext.resize(clength);

   element_clear(&Cs);
   
   return ciphertext;
}

string decrypt(DecryptionKey& key,
               Cw_t& Cw,
               const vector<int>& attributes,
               const vector<uint8_t>& ciphertext) {
   element_s Cs;
   recoverSecret(key, Cw, attributes, Cs);
   vector<uint8_t> plaintext(ciphertext.size());
   size_t plaintextLen = 0;

   array<uint8_t, AES_KEY_SIZE> symKey;
   hashElement(&Cs, symKey.data());
   symDecrypt(ciphertext.data(), ciphertext.size(), symKey.data(), plaintext.data(), &plaintextLen);
   plaintext.resize(plaintextLen);
   string message((char*) plaintext.data());

   element_clear(&Cs);
   
   return message;
}
