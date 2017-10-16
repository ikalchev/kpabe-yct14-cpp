#ifndef kpabe_
#define kpabe_

#include <map>
#include <string>
#include <vector>
#include <exception>

#include <pbc.h>

#pragma GCC visibility push(default)

/**
 * @brief KP-ABE implicit parameters.
 */
static const std::string TYPE_A_PARAMS = \
"type a\n" \
"q 87807107996633125224377819847540498158068831994142082" \
"1102865339926647563088022295707862517942266222142315585" \
"8769582317459277713367317481324925129998224791\n" \
"h 12016012264891146079388821366740534204802954401251311" \
"822919615131047207289359704531102844802183906537786776\n" \
"r 730750818665451621361119245571504901405976559617\n" \
"exp2 159\n" \
"exp1 107\n" \
"sign1 1\n" \
"sign0 1\n";

/**
 * @brief Returns a pairing object.
 *
 * We only ever need one.
 */
pairing_ptr getPairing();

/**
 * @brief Compute a hash from an element.
 */
void hashElement(element_t e, uint8_t* key);

class Node {
   
public:
   enum Type { OR, AND };
   
   int attr;
   
private:
   Type type;
   std::vector<Node> children;

public:
   Node(const Node& other);
   Node(Node&& other);
   Node(int attr);
   Node(Type type, const std::vector<Node>& children = { });
   
   Node& operator=(Node other);
   Node& operator=(Node&& other);
   
   void addChild(const Node& node);
   const std::vector<Node>& getChildren() const;
   
   //TODO: Abstract traversal order
   /**
    * @brief Returns all leaf nodes under the given node.
    */
   std::vector<int> getLeafs() const;
   unsigned int getThreshold() const;
   unsigned int getPolyDegree() const;
   
   /**
    * @brief Split the given secret share to the children of the given node.
    *
    * This sets p(0) = rootSecret and generates a random getPolyDegree polynomial.
    * The index of the shares follow the index of the children of the node + 1 (index 0 is
    * the root secret).
    */
   std::vector<element_s> splitShares(element_s& rootSecret);

   //TODO: Abstract tree traversal
   /**
    * @brief Performs Shamir's secret-sharing scheme in a top-down manner.
    *
    * The secret shares for the access tree are returned as a vector, where the positions
    * correspond to the left-to-right tree traversal.
    */
   std::vector<element_s> getSecretShares(element_s& rootSecret);
   
   /**
    * @brief Computes the Lagrange coefficients.
    *
    * Assumes an interpolated value of 0 and that the children of the node have index()
    * values in the range 1..#numChildren.
    */
   std::vector<element_s> recoverCoefficients();
   
   /**
    * @brief Computes the Lagrange coefficients for a satisfying subset of attributes.
    *
    * @return A vector of attribute-coefficient pairs.
    */
   std::vector< std::pair<int, element_s> >
   satisfyingAttributes(const std::vector<int>& attributes,
                        element_s& currentCoeff);
};

class DecryptionKey {

public:
   Node accessPolicy;
   std::map<int, element_s> Di;

   DecryptionKey(const DecryptionKey& other) = default;
   DecryptionKey(const Node& policy);   
};

typedef struct {
   element_s pk;
   std::map<int, element_s> Pi;
} PublicParams;

typedef struct {
   element_s mk;
   std::map<int, element_s> Si;
} PrivateParams;

typedef std::map<int, element_s> Cw_t;

/**
 * @brief Generates the public and private parameters of the scheme.
 */
void setup(const std::vector<int>& attributes,
           PublicParams& publicParams,
           PrivateParams& privateParams);

/**
 * @brief Creates a decryption key.
 *
 * This is the KeyGeneration algorithm.
 */
DecryptionKey keyGeneration(PrivateParams& privateParams, Node &accessPolicy);

/**
 * @brief Creates a KP-ABE secret.
 *
 * This is the Encryption algorithm, but without deriving a key and encryption.
 * Ciphertext C will hold the decryption parameters, the secret is Cs.
 */
Cw_t createSecret(PublicParams& params,
                 const std::vector<int>& attributes,
                 element_s& Cs);

/**
 * @brief Recovers a KP-ABE secret using the decryption key and decryption parameters.
 */
void recoverSecret(DecryptionKey& key,
                   Cw_t& Cw,
                   const std::vector<int>& attributes,
                   element_s& Cs);

/**
 * @brief Encrypts a message under a given attribute set.
 *
 * This is the actual Encryption algorithm, but without a HMAC.
 */
std::vector<uint8_t> encrypt(PublicParams& params,
                             const std::vector<int>& attributes,
                             const std::string& message,
                             Cw_t& Cw);

/**
 * @brief Decrypts an attribute-encrypted message.
 *
 * This is the actual Decryptoon algorithm, but without a HMAC.
 */
std::string decrypt(DecryptionKey& key,
                    Cw_t& Cw,
                    const std::vector<int>& attributes,
                    const std::vector<uint8_t>& ciphertext);

class UnsatError: public std::exception { };

#pragma GCC visibility pop
#endif
