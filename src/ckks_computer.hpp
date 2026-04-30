#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

#include "openfhe_compat.hpp"

namespace ckks_computer {

struct IntegerParams {
    std::size_t bitWidth = 64;
    std::size_t digitBits = 4;
    std::size_t numSlots = 0;

    [[nodiscard]] std::uint64_t base() const;
    [[nodiscard]] std::size_t numDigits() const;
    [[nodiscard]] std::uint64_t bitMask() const;
};

struct IntegerCiphertext {
    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> digits;
};

class CkksContext {
  public:
    explicit CkksContext(const IntegerParams& params);

    void GenerateKeys();

    [[nodiscard]] const IntegerParams& Params() const noexcept;
    [[nodiscard]] const std::shared_ptr<lbcrypto::CryptoContext<lbcrypto::DCRTPoly>>& Context() const noexcept;

    [[nodiscard]] IntegerCiphertext EncryptDigits(const std::vector<std::vector<double>>& digitPlanes) const;
    [[nodiscard]] std::vector<std::vector<double>> DecryptDigits(const IntegerCiphertext& value) const;

  private:
    IntegerParams params_;
    std::shared_ptr<lbcrypto::CryptoContext<lbcrypto::DCRTPoly>> context_;
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> keyPair_;
};

class IntegerComputer {
  public:
    explicit IntegerComputer(CkksContext& context);

    [[nodiscard]] IntegerCiphertext Encrypt(const std::vector<std::uint64_t>& values) const;
    [[nodiscard]] std::vector<std::uint64_t> Decrypt(const IntegerCiphertext& value) const;

    [[nodiscard]] IntegerCiphertext Add(const IntegerCiphertext& lhs, const IntegerCiphertext& rhs) const;
    [[nodiscard]] IntegerCiphertext Sub(const IntegerCiphertext& lhs, const IntegerCiphertext& rhs) const;
    [[nodiscard]] IntegerCiphertext Mul(const IntegerCiphertext& lhs, const IntegerCiphertext& rhs) const;
    [[nodiscard]] IntegerCiphertext CompareGreaterEqual(
        const IntegerCiphertext& lhs,
        const IntegerCiphertext& rhs) const;
    [[nodiscard]] IntegerCiphertext LeftShift(const IntegerCiphertext& value, std::size_t bits) const;
    [[nodiscard]] IntegerCiphertext RightShift(const IntegerCiphertext& value, std::size_t bits) const;

    [[nodiscard]] IntegerCiphertext Reduce(const IntegerCiphertext& value) const;
    [[nodiscard]] IntegerCiphertext Carry(const IntegerCiphertext& value) const;

  private:
    CkksContext& context_;

    [[nodiscard]] IntegerCiphertext EncryptNormalized(const std::vector<std::uint64_t>& values) const;
    [[nodiscard]] std::vector<std::vector<long long>> DecryptRawDigits(const IntegerCiphertext& value) const;
    [[nodiscard]] std::vector<std::uint64_t> DecomposeHost(std::uint64_t value) const;
    [[nodiscard]] std::uint64_t RecomposeHost(const std::vector<std::uint64_t>& digits) const;
};

}  // namespace ckks_computer
