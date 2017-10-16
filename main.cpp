#include <vector>
#include <iostream>

#include "pbc.h"

#include "kpabe.hpp"

using namespace std;

int main() {
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
   auto Cw = createSecret(pub, encryptionAttributes, secret);

   // Recover secret
   element_s recovered;
   recoverSecret(key, Cw, encryptionAttributes, recovered);
   cout << element_cmp(&secret, &recovered) << endl; // should be ==0

   for(auto& attrCiPair: Cw) {
      element_clear(&attrCiPair.second);
   }
   Cw.clear();

   // Secret cannto be recovered if the encryption attributes do not satisfy the policy.
   encryptionAttributes = {1};
   Cw = createSecret(pub, encryptionAttributes, secret);
   try {
      recoverSecret(key, Cw, encryptionAttributes, recovered);
   } catch(const UnsatError& e) {
      cout << "Unsatisfied" << endl;
   }

   return 0;
}
