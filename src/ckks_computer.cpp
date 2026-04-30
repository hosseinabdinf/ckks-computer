#include "ckks_computer.hpp"

#include <cmath>
#include <functional>
#include <limits>
#include <map>
#include <tuple>

namespace ckks_computer {

namespace {

using Cipher = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;
using ContextPtr = std::shared_ptr<lbcrypto::CryptoContext<lbcrypto::DCRTPoly>>;
using RawPlanes = std::vector<std::vector<long long>>;

enum class DigitFunctionKind { Remainder = 0, Carry = 1 };

struct DiscretePolynomial {
    std::vector<long double> nodes;
    std::vector<long double> coefficients;
};

void ValidateParams(const IntegerParams& params) {
    if (params.bitWidth == 0 || params.bitWidth > 64) {
        throw std::invalid_argument("bitWidth must be in [1, 64]");
    }
    if (params.digitBits == 0 || params.digitBits >= 63) {
        throw std::invalid_argument("digitBits must be in [1, 62]");
    }
    if (params.numDigits() == 0) {
        throw std::invalid_argument("numDigits must be positive");
    }
}

void ValidateSameDigitCount(const IntegerCiphertext& lhs, const IntegerCiphertext& rhs) {
    if (lhs.digits.size() != rhs.digits.size()) {
        throw std::invalid_argument("digit count mismatch");
    }
}

std::uint64_t WrapUnsigned(std::uint64_t value, const IntegerParams& params) {
    return params.bitWidth == 64 ? value : (value & params.bitMask());
}

std::uint64_t WrapSigned(signed __int128 value, const IntegerParams& params) {
    if (params.bitWidth == 64) {
        return static_cast<std::uint64_t>(value);
    }

    const auto modulus = static_cast<signed __int128>(1) << params.bitWidth;
    auto reduced = value % modulus;
    if (reduced < 0) {
        reduced += modulus;
    }
    return static_cast<std::uint64_t>(reduced);
}

long long RoundToLongLong(double value) {
    return static_cast<long long>(std::llround(value));
}

RawPlanes ToRawPlanes(const std::vector<std::vector<double>>& planes) {
    RawPlanes out;
    out.reserve(planes.size());
    for (const auto& plane : planes) {
        std::vector<long long> rounded;
        rounded.reserve(plane.size());
        for (double value : plane) {
            rounded.push_back(RoundToLongLong(value));
        }
        out.push_back(rounded);
    }
    return out;
}

signed __int128 ComputeSignedValue(const RawPlanes& planes, std::size_t slot, std::uint64_t base) {
    signed __int128 value = 0;
    signed __int128 factor = 1;
    for (const auto& plane : planes) {
        value += static_cast<signed __int128>(plane[slot]) * factor;
        factor *= static_cast<signed __int128>(base);
    }
    return value;
}

std::vector<std::uint64_t> NormalizePlanes(const RawPlanes& planes, const IntegerParams& params) {
    if (planes.empty()) {
        return {};
    }

    std::vector<std::uint64_t> out(planes.front().size(), 0);
    for (std::size_t slot = 0; slot < out.size(); ++slot) {
        out[slot] = WrapSigned(ComputeSignedValue(planes, slot, params.base()), params);
    }
    return out;
}

std::vector<std::uint64_t> ApplyBinaryOp(
    const std::vector<std::uint64_t>& lhs,
    const std::vector<std::uint64_t>& rhs,
    const std::function<std::uint64_t(std::uint64_t, std::uint64_t)>& operation) {
    if (lhs.size() != rhs.size()) {
        throw std::invalid_argument("slot count mismatch");
    }

    std::vector<std::uint64_t> out(lhs.size(), 0);
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        out[i] = operation(lhs[i], rhs[i]);
    }
    return out;
}

long long NormalizeRemainder(long long value, std::uint64_t base) {
    auto remainder = value % static_cast<long long>(base);
    if (remainder < 0) {
        remainder += static_cast<long long>(base);
    }
    return remainder;
}

long long NormalizeCarry(long long value, std::uint64_t base) {
    const auto remainder = NormalizeRemainder(value, base);
    return (value - remainder) / static_cast<long long>(base);
}

DiscretePolynomial BuildInterpolation(
    long long minValue,
    long long maxValue,
    const std::function<long double(long long)>& function) {
    DiscretePolynomial polynomial;
    const auto count = static_cast<std::size_t>(maxValue - minValue + 1);
    polynomial.nodes.reserve(count);
    polynomial.coefficients.reserve(count);

    for (long long value = minValue; value <= maxValue; ++value) {
        polynomial.nodes.push_back(static_cast<long double>(value));
        polynomial.coefficients.push_back(function(value));
    }

    for (std::size_t order = 1; order < polynomial.coefficients.size(); ++order) {
        for (std::size_t i = polynomial.coefficients.size() - 1; i >= order; --i) {
            const auto denominator = polynomial.nodes[i] - polynomial.nodes[i - order];
            polynomial.coefficients[i] = (polynomial.coefficients[i] - polynomial.coefficients[i - 1]) / denominator;
            if (i == order) {
                break;
            }
        }
    }

    return polynomial;
}

const DiscretePolynomial& GetDigitPolynomial(std::uint64_t base, long long bound, DigitFunctionKind kind) {
    using CacheKey = std::tuple<std::uint64_t, long long, int>;

    static std::map<CacheKey, DiscretePolynomial> cache;
    const CacheKey key{base, bound, static_cast<int>(kind)};
    const auto found = cache.find(key);
    if (found != cache.end()) {
        return found->second;
    }

    const auto function = [=](long long value) -> long double {
        if (kind == DigitFunctionKind::Remainder) {
            return static_cast<long double>(NormalizeRemainder(value, base));
        }
        return static_cast<long double>(NormalizeCarry(value, base));
    };

    return cache.emplace(key, BuildInterpolation(-bound, bound, function)).first->second;
}

Cipher MultiplyByScalar(const ContextPtr& context, const Cipher& value, double scalar) {
    return context->EvalMult(value, scalar);
}

Cipher AddScalar(const ContextPtr& context, const Cipher& value, double scalar) {
    return context->EvalAdd(value, scalar);
}

Cipher ZeroLike(const ContextPtr& context, const Cipher& reference) {
    return MultiplyByScalar(context, reference, 0.0);
}

Cipher ConstantLike(const ContextPtr& context, const Cipher& reference, double scalar) {
    return AddScalar(context, ZeroLike(context, reference), scalar);
}

Cipher EvaluatePolynomial(const ContextPtr& context, const Cipher& value, const DiscretePolynomial& polynomial) {
    if (polynomial.coefficients.empty()) {
        return ZeroLike(context, value);
    }

    auto result = ConstantLike(context, value, static_cast<double>(polynomial.coefficients.back()));
    for (std::size_t i = polynomial.coefficients.size() - 1; i > 0; --i) {
        const auto shifted = AddScalar(context, value, -static_cast<double>(polynomial.nodes[i - 1]));
        result = context->EvalMult(result, shifted);
        result = AddScalar(context, result, static_cast<double>(polynomial.coefficients[i - 1]));
    }
    return result;
}

Cipher EvaluateDigitFunction(
    const ContextPtr& context,
    const Cipher& value,
    std::uint64_t base,
    long long bound,
    DigitFunctionKind kind) {
#if CKKS_COMPUTER_OPENFHE_COMPAT_STUB
    auto result = std::make_shared<lbcrypto::CiphertextImpl<lbcrypto::DCRTPoly>>();
    result->values.reserve(value->values.size());
    for (double slot : value->values) {
        const auto rounded = RoundToLongLong(slot);
        if (rounded < -bound || rounded > bound) {
            throw std::runtime_error("digit function input exceeded supported bound");
        }
        const auto mapped = kind == DigitFunctionKind::Remainder ? NormalizeRemainder(rounded, base)
                                                                  : NormalizeCarry(rounded, base);
        result->values.push_back(static_cast<double>(mapped));
    }
    return result;
#else
    const auto& polynomial = GetDigitPolynomial(base, bound, kind);
    return EvaluatePolynomial(context, value, polynomial);
#endif
}

long long ComputeGeneralReductionBound(const IntegerParams& params) {
    const auto base = static_cast<long long>(params.base());
    const auto digits = static_cast<long long>(params.numDigits());
    return (digits + 1) * base * base;
}

long long ComputeShiftReductionBound(const IntegerParams& params, std::size_t intraDigitBits) {
    const auto scaled = static_cast<long long>(params.base()) << intraDigitBits;
    return std::max<long long>(scaled + 2, static_cast<long long>(params.base()) * 2);
}

IntegerCiphertext MakeConstantIntegerLike(
    const ContextPtr& context,
    const Cipher& reference,
    const IntegerParams& params,
    std::uint64_t value) {
    IntegerCiphertext out;
    out.digits.reserve(params.numDigits());
    auto remaining = WrapUnsigned(value, params);
    for (std::size_t i = 0; i < params.numDigits(); ++i) {
        const auto digit = static_cast<double>(remaining % params.base());
        out.digits.push_back(ConstantLike(context, reference, digit));
        remaining /= params.base();
    }
    return out;
}

IntegerCiphertext MakeRawValueLike(
    const ContextPtr& context,
    const Cipher& reference,
    const IntegerParams& params,
    const Cipher& digitZero) {
    IntegerCiphertext out;
    out.digits.reserve(params.numDigits());
    out.digits.push_back(digitZero);
    for (std::size_t i = 1; i < params.numDigits(); ++i) {
        out.digits.push_back(ZeroLike(context, reference));
    }
    return out;
}

}  // namespace

std::uint64_t IntegerParams::base() const {
    return 1ULL << digitBits;
}

std::size_t IntegerParams::numDigits() const {
    return (bitWidth + digitBits - 1) / digitBits;
}

std::uint64_t IntegerParams::bitMask() const {
    return bitWidth == 64 ? std::numeric_limits<std::uint64_t>::max() : ((1ULL << bitWidth) - 1ULL);
}

CkksContext::CkksContext(const IntegerParams& params) : params_(params) {
    ValidateParams(params_);

    using namespace lbcrypto;
    CCParams<CryptoContextCKKSRNS> ccParams;
    ccParams.SetSecurityLevel(HEStd_128_classic);
    ccParams.SetEncryptionTechnique(STANDARD);
    ccParams.SetScalingTechnique(FLEXIBLEAUTOEXT);
    ccParams.SetKeySwitchTechnique(HYBRID);
    ccParams.SetScalingModSize(50);
    ccParams.SetMultiplicativeDepth(12);
    ccParams.SetBatchSize(params_.numSlots == 0 ? 0 : params_.numSlots);

    context_ = CryptoContextCKKSRNS::genCryptoContext(ccParams);
    context_->Enable(PKE);
    context_->Enable(KEYSWITCH);
    context_->Enable(LEVELEDSHE);
    context_->Enable(ADVANCEDSHE);
}

void CkksContext::GenerateKeys() {
    keyPair_ = context_->KeyGen();
    if (!keyPair_.good()) {
        throw std::runtime_error("OpenFHE key generation failed");
    }
    context_->EvalMultKeyGen(keyPair_.secretKey);
    context_->EvalRotateKeyGen(keyPair_.secretKey, {1, -1});
    context_->EvalConjugateKeyGen(keyPair_.secretKey);
}

const IntegerParams& CkksContext::Params() const noexcept {
    return params_;
}

const std::shared_ptr<lbcrypto::CryptoContext<lbcrypto::DCRTPoly>>& CkksContext::Context() const noexcept {
    return context_;
}

IntegerCiphertext CkksContext::EncryptDigits(const std::vector<std::vector<double>>& digitPlanes) const {
    if (!keyPair_.good()) {
        throw std::logic_error("keys must be generated before encryption");
    }

    IntegerCiphertext out;
    out.digits.reserve(digitPlanes.size());
    for (const auto& plane : digitPlanes) {
        auto plaintext = context_->MakeCKKSPackedPlaintext(plane);
        out.digits.push_back(context_->Encrypt(keyPair_.publicKey, plaintext));
    }
    return out;
}

std::vector<std::vector<double>> CkksContext::DecryptDigits(const IntegerCiphertext& value) const {
    if (!keyPair_.good()) {
        throw std::logic_error("keys must be generated before decryption");
    }

    std::vector<std::vector<double>> out;
    out.reserve(value.digits.size());
    for (const auto& ct : value.digits) {
        lbcrypto::Plaintext pt;
        context_->Decrypt(keyPair_.secretKey, ct, &pt);
        pt->SetLength(pt->GetSlots());
        const auto& slots = pt->GetRealPackedValue();
        out.emplace_back(slots.begin(), slots.end());
    }
    return out;
}

IntegerComputer::IntegerComputer(CkksContext& context) : context_(context) {}

IntegerCiphertext IntegerComputer::EncryptNormalized(const std::vector<std::uint64_t>& values) const {
    if (values.empty()) {
        return {};
    }

    const auto numDigits = context_.Params().numDigits();
    std::vector<std::vector<double>> planes(numDigits);
    for (auto value : values) {
        const auto digits = DecomposeHost(WrapUnsigned(value, context_.Params()));
        for (std::size_t i = 0; i < numDigits; ++i) {
            planes[i].push_back(static_cast<double>(digits[i]));
        }
    }
    return context_.EncryptDigits(planes);
}

std::vector<std::vector<long long>> IntegerComputer::DecryptRawDigits(const IntegerCiphertext& value) const {
    return ToRawPlanes(context_.DecryptDigits(value));
}

std::vector<std::uint64_t> IntegerComputer::DecomposeHost(std::uint64_t value) const {
    const auto base = context_.Params().base();
    std::vector<std::uint64_t> out(context_.Params().numDigits(), 0);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = value % base;
        value /= base;
    }
    return out;
}

std::uint64_t IntegerComputer::RecomposeHost(const std::vector<std::uint64_t>& digits) const {
    const auto base = context_.Params().base();
    std::uint64_t value = 0;
    std::uint64_t factor = 1;
    for (auto digit : digits) {
        value += digit * factor;
        factor *= base;
    }
    return WrapUnsigned(value, context_.Params());
}

IntegerCiphertext IntegerComputer::Encrypt(const std::vector<std::uint64_t>& values) const {
    return EncryptNormalized(values);
}

std::vector<std::uint64_t> IntegerComputer::Decrypt(const IntegerCiphertext& value) const {
    return NormalizePlanes(DecryptRawDigits(value), context_.Params());
}

IntegerCiphertext IntegerComputer::Add(const IntegerCiphertext& lhs, const IntegerCiphertext& rhs) const {
    ValidateSameDigitCount(lhs, rhs);

    IntegerCiphertext raw;
    raw.digits.reserve(lhs.digits.size());
    for (std::size_t i = 0; i < lhs.digits.size(); ++i) {
        raw.digits.push_back(context_.Context()->EvalAdd(lhs.digits[i], rhs.digits[i]));
    }
    return Reduce(raw);
}

IntegerCiphertext IntegerComputer::Sub(const IntegerCiphertext& lhs, const IntegerCiphertext& rhs) const {
    ValidateSameDigitCount(lhs, rhs);

    IntegerCiphertext raw;
    raw.digits.reserve(lhs.digits.size());
    for (std::size_t i = 0; i < lhs.digits.size(); ++i) {
        raw.digits.push_back(context_.Context()->EvalSub(lhs.digits[i], rhs.digits[i]));
    }
    return Reduce(raw);
}

IntegerCiphertext IntegerComputer::Mul(const IntegerCiphertext& lhs, const IntegerCiphertext& rhs) const {
    ValidateSameDigitCount(lhs, rhs);

    IntegerCiphertext raw;
    raw.digits.reserve(lhs.digits.size());
    auto zero = ZeroLike(context_.Context(), lhs.digits.front());
    for (std::size_t i = 0; i < lhs.digits.size(); ++i) {
        auto sum = zero;
        bool firstTerm = true;
        for (std::size_t j = 0; j <= i; ++j) {
            auto term = context_.Context()->EvalMult(lhs.digits[j], rhs.digits[i - j]);
            sum = firstTerm ? term : context_.Context()->EvalAdd(sum, term);
            firstTerm = false;
        }
        raw.digits.push_back(sum);
    }
    return Reduce(raw);
}

IntegerCiphertext IntegerComputer::CompareGreaterEqual(
    const IntegerCiphertext& lhs,
    const IntegerCiphertext& rhs) const {
    ValidateSameDigitCount(lhs, rhs);

    IntegerCiphertext raw;
    raw.digits.reserve(lhs.digits.size());
    for (std::size_t i = 0; i < lhs.digits.size(); ++i) {
        raw.digits.push_back(context_.Context()->EvalSub(lhs.digits[i], rhs.digits[i]));
    }

    const auto carry = Carry(raw);
    const auto one = MakeConstantIntegerLike(context_.Context(), carry.digits.front(), context_.Params(), 1);
    return Add(carry, one);
}

IntegerCiphertext IntegerComputer::LeftShift(const IntegerCiphertext& value, std::size_t bits) const {
    if (value.digits.empty()) {
        return {};
    }

    if (bits >= context_.Params().bitWidth) {
        return MakeConstantIntegerLike(context_.Context(), value.digits.front(), context_.Params(), 0);
    }

    const auto digitShift = bits / context_.Params().digitBits;
    const auto intraDigitBits = bits % context_.Params().digitBits;
    const auto scale = static_cast<double>(1ULL << intraDigitBits);
    const auto bound = ComputeShiftReductionBound(context_.Params(), intraDigitBits);
    const auto zero = ZeroLike(context_.Context(), value.digits.front());

    IntegerCiphertext raw;
    raw.digits.reserve(value.digits.size());
    for (std::size_t i = 0; i < value.digits.size(); ++i) {
        auto digit = zero;
        if (i >= digitShift) {
            auto shifted = MultiplyByScalar(context_.Context(), value.digits[i - digitShift], scale);
            digit = EvaluateDigitFunction(
                context_.Context(),
                shifted,
                context_.Params().base(),
                bound,
                DigitFunctionKind::Remainder);
        }
        if (intraDigitBits > 0 && i > digitShift) {
            auto shifted = MultiplyByScalar(context_.Context(), value.digits[i - digitShift - 1], scale);
            digit = context_.Context()->EvalAdd(
                digit,
                EvaluateDigitFunction(
                    context_.Context(),
                    shifted,
                    context_.Params().base(),
                    bound,
                    DigitFunctionKind::Carry));
        }
        raw.digits.push_back(digit);
    }
    return Reduce(raw);
}

IntegerCiphertext IntegerComputer::RightShift(const IntegerCiphertext& value, std::size_t bits) const {
    if (value.digits.empty()) {
        return {};
    }

    if (bits >= context_.Params().bitWidth) {
        return MakeConstantIntegerLike(context_.Context(), value.digits.front(), context_.Params(), 0);
    }

    const auto digitShift = bits / context_.Params().digitBits;
    const auto intraDigitBits = bits % context_.Params().digitBits;
    const auto zero = ZeroLike(context_.Context(), value.digits.front());

    if (intraDigitBits == 0) {
        IntegerCiphertext out;
        out.digits.reserve(value.digits.size());
        for (std::size_t i = 0; i < value.digits.size(); ++i) {
            out.digits.push_back(i + digitShift < value.digits.size() ? value.digits[i + digitShift] : zero);
        }
        return out;
    }

    const auto scale = static_cast<double>(1ULL << (context_.Params().digitBits - intraDigitBits));
    const auto bound = ComputeShiftReductionBound(context_.Params(), context_.Params().digitBits - intraDigitBits);
    IntegerCiphertext raw;
    raw.digits.reserve(value.digits.size());
    for (std::size_t i = 0; i < value.digits.size(); ++i) {
        auto digit = zero;
        if (i + digitShift < value.digits.size()) {
            auto shifted = MultiplyByScalar(context_.Context(), value.digits[i + digitShift], scale);
            digit = EvaluateDigitFunction(
                context_.Context(),
                shifted,
                context_.Params().base(),
                bound,
                DigitFunctionKind::Carry);
        }
        if (i + digitShift + 1 < value.digits.size()) {
            auto shifted = MultiplyByScalar(context_.Context(), value.digits[i + digitShift + 1], scale);
            digit = context_.Context()->EvalAdd(
                digit,
                EvaluateDigitFunction(
                    context_.Context(),
                    shifted,
                    context_.Params().base(),
                    bound,
                    DigitFunctionKind::Remainder));
        }
        raw.digits.push_back(digit);
    }
    return Reduce(raw);
}

IntegerCiphertext IntegerComputer::Reduce(const IntegerCiphertext& value) const {
    if (value.digits.empty()) {
        return {};
    }

    const auto bound = ComputeGeneralReductionBound(context_.Params());
    auto carry = ZeroLike(context_.Context(), value.digits.front());

    IntegerCiphertext out;
    out.digits.reserve(value.digits.size());
    for (const auto& digit : value.digits) {
        auto current = context_.Context()->EvalAdd(digit, carry);
        out.digits.push_back(
            EvaluateDigitFunction(context_.Context(), current, context_.Params().base(), bound, DigitFunctionKind::Remainder));
        carry = EvaluateDigitFunction(context_.Context(), current, context_.Params().base(), bound, DigitFunctionKind::Carry);
    }
    return out;
}

IntegerCiphertext IntegerComputer::Carry(const IntegerCiphertext& value) const {
    if (value.digits.empty()) {
        return {};
    }

    const auto bound = ComputeGeneralReductionBound(context_.Params());
    const auto carryPoly = GetDigitPolynomial(context_.Params().base(), bound, DigitFunctionKind::Carry);
    auto carry = ZeroLike(context_.Context(), value.digits.front());
    for (const auto& digit : value.digits) {
        auto current = context_.Context()->EvalAdd(digit, carry);
        carry = EvaluateDigitFunction(context_.Context(), current, context_.Params().base(), bound, DigitFunctionKind::Carry);
    }
    return Reduce(MakeRawValueLike(context_.Context(), value.digits.front(), context_.Params(), carry));
}

}  // namespace ckks_computer
