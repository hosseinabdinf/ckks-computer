#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#if __has_include(<openfhe.h>)

#include <openfhe.h>

#define CKKS_COMPUTER_OPENFHE_COMPAT_STUB 0

#else

#define CKKS_COMPUTER_OPENFHE_COMPAT_STUB 1

namespace lbcrypto {

struct DCRTPoly {};

enum SecurityLevel { HEStd_128_classic };
enum ScalingTechnique { FLEXIBLEAUTOEXT };
enum KeySwitchTechnique { HYBRID };
enum EncryptionTechnique { STANDARD };
enum Feature { PKE, KEYSWITCH, LEVELEDSHE, ADVANCEDSHE };

template <typename T>
class CCParams {
  public:
    void SetSecurityLevel(SecurityLevel) {}
    void SetEncryptionTechnique(EncryptionTechnique) {}
    void SetScalingTechnique(ScalingTechnique) {}
    void SetKeySwitchTechnique(KeySwitchTechnique) {}
    void SetScalingModSize(std::size_t) {}
    void SetMultiplicativeDepth(std::size_t) {}
    void SetBatchSize(std::size_t) {}
};

struct PlaintextImpl {
    std::vector<double> values;

    void SetLength(std::size_t) {}
    std::size_t GetSlots() const { return values.size(); }
    const std::vector<double>& GetRealPackedValue() const { return values; }
};

using Plaintext = std::shared_ptr<PlaintextImpl>;

template <typename T>
struct CiphertextImpl {
    std::vector<double> values;
};

template <typename T>
using Ciphertext = std::shared_ptr<CiphertextImpl<T>>;

template <typename T>
struct KeyPair {
    std::shared_ptr<int> publicKey = std::make_shared<int>(1);
    std::shared_ptr<int> secretKey = std::make_shared<int>(1);

    bool good() const { return static_cast<bool>(publicKey) && static_cast<bool>(secretKey); }
};

class CryptoContextBase {
  public:
    void Enable(Feature) {}
};

template <typename T>
class CryptoContext : public CryptoContextBase,
                     public std::enable_shared_from_this<CryptoContext<T>> {
  public:
    KeyPair<T> KeyGen() { return {}; }

    void EvalMultKeyGen(const std::shared_ptr<int>&) {}
    void EvalRotateKeyGen(const std::shared_ptr<int>&, const std::vector<int>&) {}
    void EvalConjugateKeyGen(const std::shared_ptr<int>&) {}

    Plaintext MakeCKKSPackedPlaintext(const std::vector<double>& values) const {
        auto plaintext = std::make_shared<PlaintextImpl>();
        plaintext->values = values;
        return plaintext;
    }

    Ciphertext<T> Encrypt(const std::shared_ptr<int>&, const Plaintext& plaintext) const {
        auto ciphertext = std::make_shared<CiphertextImpl<T>>();
        ciphertext->values = plaintext->values;
        return ciphertext;
    }

    void Decrypt(const std::shared_ptr<int>&, const Ciphertext<T>& ciphertext, Plaintext* plaintext) const {
        *plaintext = std::make_shared<PlaintextImpl>();
        (*plaintext)->values = ciphertext->values;
    }

    Ciphertext<T> EvalAdd(const Ciphertext<T>& lhs, const Ciphertext<T>& rhs) const {
        auto result = std::make_shared<CiphertextImpl<T>>();
        result->values.resize(lhs->values.size());
        for (std::size_t i = 0; i < lhs->values.size(); ++i) {
            result->values[i] = lhs->values[i] + rhs->values[i];
        }
        return result;
    }

    Ciphertext<T> EvalAdd(const Ciphertext<T>& lhs, double scalar) const {
        auto result = std::make_shared<CiphertextImpl<T>>();
        result->values.resize(lhs->values.size());
        for (std::size_t i = 0; i < lhs->values.size(); ++i) {
            result->values[i] = lhs->values[i] + scalar;
        }
        return result;
    }

    Ciphertext<T> EvalSub(const Ciphertext<T>& lhs, const Ciphertext<T>& rhs) const {
        auto result = std::make_shared<CiphertextImpl<T>>();
        result->values.resize(lhs->values.size());
        for (std::size_t i = 0; i < lhs->values.size(); ++i) {
            result->values[i] = lhs->values[i] - rhs->values[i];
        }
        return result;
    }

    Ciphertext<T> EvalSub(const Ciphertext<T>& lhs, double scalar) const {
        auto result = std::make_shared<CiphertextImpl<T>>();
        result->values.resize(lhs->values.size());
        for (std::size_t i = 0; i < lhs->values.size(); ++i) {
            result->values[i] = lhs->values[i] - scalar;
        }
        return result;
    }

    Ciphertext<T> EvalMult(const Ciphertext<T>& lhs, const Ciphertext<T>& rhs) const {
        auto result = std::make_shared<CiphertextImpl<T>>();
        result->values.resize(lhs->values.size());
        for (std::size_t i = 0; i < lhs->values.size(); ++i) {
            result->values[i] = lhs->values[i] * rhs->values[i];
        }
        return result;
    }

    Ciphertext<T> EvalMult(const Ciphertext<T>& lhs, double scalar) const {
        auto result = std::make_shared<CiphertextImpl<T>>();
        result->values.resize(lhs->values.size());
        for (std::size_t i = 0; i < lhs->values.size(); ++i) {
            result->values[i] = lhs->values[i] * scalar;
        }
        return result;
    }
};

class CryptoContextCKKSRNS {
  public:
    static std::shared_ptr<CryptoContext<DCRTPoly>> genCryptoContext(const CCParams<CryptoContextCKKSRNS>&) {
        return std::make_shared<CryptoContext<DCRTPoly>>();
    }
};

}  // namespace lbcrypto

#endif
