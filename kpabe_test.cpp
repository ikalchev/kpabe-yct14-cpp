#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE kpabe_test

#include <vector>
#include <string>
#include <iostream>

#include <boost/test/unit_test.hpp>
#include <pbc.h>

#include "kpabe.hpp"

using namespace std;

struct InitPolicy {
   Node root;
   vector<int> attributes;
   
   InitPolicy() : root(Node::Type::AND), attributes({1, 2, 3, 4}) {
      // (one or two) and (three or four)
      vector<Node> children1, children2;
      for(auto it = attributes.begin(); it != attributes.begin() + attributes.size() / 2; ++it) {
         children1.emplace_back(*it);
         children2.emplace_back(*(it + 2));
      }
      
      Node orNodeLeft(Node::Type::OR, children1);
      Node orNodeRight(Node::Type::OR, children2);
      root.addChild(orNodeLeft);
      root.addChild(orNodeRight);
   }
};

struct InitGenerator: InitPolicy {
   PrivateParams priv;
   PublicParams pub;
   
   InitGenerator() : InitPolicy() {
      setup({1, 2, 3, 4}, pub, priv);
   }
};


BOOST_AUTO_TEST_CASE(hashElement_test) {
   element_t el;
   element_init_G1(el, getPairing());
   element_random(el);
   
   uint8_t key[32];
   hashElement(el, key);
   //elementToKey(el, key, NULL);
   
   element_clear(el);
}

BOOST_FIXTURE_TEST_CASE(getLeafs_test, InitPolicy) {
   auto leafs = root.getLeafs();
   for(auto attr: attributes) {
      BOOST_CHECK(find(leafs.begin(), leafs.end(), attr) != leafs.end());
   }
}

BOOST_FIXTURE_TEST_CASE(splitShares_test, InitPolicy) {

   element_t rootSecret;
   element_init_Zr(rootSecret, getPairing());
   element_random(rootSecret);
   
   auto shares = root.splitShares(*rootSecret);
   
   for(auto& share: shares) {
      element_add_ui(&share, &share, 1ul); // Sanity check that the shares are initialized
      element_clear(&share);
   }
   
   element_clear(rootSecret);
}

BOOST_FIXTURE_TEST_CASE(getSecretShares_test, InitPolicy) {
   element_t rootSecret;
   element_init_Zr(rootSecret, getPairing());
   element_random(rootSecret);
   
   auto shares = root.getSecretShares(*rootSecret);
   
   for(auto& share: shares) {
      element_add_ui(&share, &share, 1ul); // Sanity check that the shares are initialized
      element_clear(&share);
   }

   element_clear(rootSecret);
}

BOOST_FIXTURE_TEST_CASE(recoverCoefficients_test, InitPolicy) {
   auto shares = root.recoverCoefficients();
   
   for(auto& share: shares) {
      element_add_ui(&share, &share, 1ul); // Sanity check that the shares are initialized
      element_clear(&share);
   }
}

BOOST_FIXTURE_TEST_CASE(satisfyingAttributes_test, InitPolicy) {
   element_t rootCoeff;
   element_init_Zr(rootCoeff, getPairing());
   element_set1(rootCoeff);
   
   vector<int> attr {1, 3};
   vector<int> expected {1, 3};
   auto sat = root.satisfyingAttributes(attr, *rootCoeff);

   BOOST_CHECK(expected.size() == sat.size());
   for(auto& s: sat) {
      BOOST_CHECK(find(expected.begin(), expected.end(), s.first) != expected.end());
      element_clear(&s.second);
   }
   
   element_clear(rootCoeff);
}

BOOST_FIXTURE_TEST_CASE(satisfyingAttributes_negative_test, InitPolicy) {
   element_t rootCoeff;
   element_init_Zr(rootCoeff, getPairing());
   element_set1(rootCoeff);
   
   vector<int> attr {1};
   vector<int> expected {};
   auto sat = root.satisfyingAttributes(attr, *rootCoeff);
   
   BOOST_CHECK(expected.size() == sat.size());
   // Just in case the test fails, clear all elements
   for(auto& s: sat) {
      const auto& a = s.first;
      BOOST_CHECK(find(expected.begin(), expected.end(), a) != expected.end());
      element_clear(&s.second);
   }
   
   element_clear(rootCoeff);
}

BOOST_AUTO_TEST_CASE(setupTest) {
   vector<int> attributes {1, 2, 3};
   PrivateParams priv;
   PublicParams pub;
   setup(attributes, pub, priv);
}

BOOST_FIXTURE_TEST_CASE(createSecretTest, InitPolicy) {
   vector<int> attrUniverse {1, 2, 3, 4};
   PrivateParams priv;
   PublicParams pub;
   setup(attributes, pub, priv);
   auto key = keyGeneration(priv, root);
   vector<int> expectedAttributes {1, 2, 3, 4};
   
   BOOST_CHECK(expectedAttributes.size() == key.Di.size());
   for(auto attr: expectedAttributes) {
      auto attrDuPairIter = key.Di.find(attr);
      BOOST_CHECK(attrDuPairIter != key.Di.end());
      element_clear(&attrDuPairIter->second);
   }
}

BOOST_FIXTURE_TEST_CASE(createSecretAndRecoverSecret, InitGenerator) {
   element_s CsEnc, CsDec;
   vector<int> encAttr {1, 3};
   auto Cw = createSecret(pub, encAttr, CsEnc);

   auto decKeyPolicy = keyGeneration(priv, root);
   recoverSecret(decKeyPolicy, Cw, encAttr, CsDec);
   
   BOOST_CHECK(!element_cmp(&CsEnc, &CsDec));

   for(auto& attrCiPair: Cw) {
      element_clear(&attrCiPair.second);
   }
   
   for(auto& attrDiPair: decKeyPolicy.Di) {
      element_clear(&attrDiPair.second);
   }
   
   element_clear(&CsEnc);
   element_clear(&CsDec);
}

BOOST_FIXTURE_TEST_CASE(encryptAndDecrypt, InitGenerator) {
   const string message("Hello World!");
   vector<int> attributes {1};

   Cw_t Cw;
   auto ciphertext = encrypt(pub, attributes, message, Cw);
   
   Node policy(Node::Type::OR);
   policy.addChild(Node(1));
   policy.addChild(Node(2));
   auto key = keyGeneration(priv, policy);
   
   auto msg = decrypt(key, Cw, attributes, ciphertext);
   
   for(auto& attrCiPair: Cw) {
      element_clear(&attrCiPair.second);
   }
   
   for(auto& attrDiPair: key.Di) {
      element_clear(&attrDiPair.second);
   }
   
   BOOST_CHECK(msg == message);
}

