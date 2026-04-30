#include "../src/ckks_computer.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

namespace {

using ckks_computer::CkksContext;
using ckks_computer::IntegerComputer;
using ckks_computer::IntegerParams;

void AssertEqual(const std::vector<std::uint64_t>& actual, const std::vector<std::uint64_t>& expected) {
    assert(actual == expected);
}

IntegerComputer MakeComputer(CkksContext& context) {
    context.GenerateKeys();
    return IntegerComputer(context);
}

void TestRoundTrip() {
    // Arrange
    CkksContext context(IntegerParams{16, 4, 4});
    auto computer = MakeComputer(context);

    // Act
    const auto values = computer.Decrypt(computer.Encrypt({1, 42, 255, 4095}));

    // Assert
    AssertEqual(values, {1, 42, 255, 4095});
}

void TestReduceNormalizesDigits() {
    // Arrange
    CkksContext context(IntegerParams{8, 4, 2});
    auto computer = MakeComputer(context);
    const auto raw = context.EncryptDigits({{20.0, -1.0}, {20.0, 0.0}});

    // Act
    const auto reduced = computer.Decrypt(computer.Reduce(raw));

    // Assert
    AssertEqual(reduced, {84, 255});
}

void TestCarryExtractsOverflowWord() {
    // Arrange
    CkksContext context(IntegerParams{8, 4, 2});
    auto computer = MakeComputer(context);
    const auto raw = context.EncryptDigits({{20.0, -1.0}, {20.0, 0.0}});

    // Act
    const auto carry = computer.Decrypt(computer.Carry(raw));

    // Assert
    AssertEqual(carry, {1, 255});
}

void TestAddWrapsWithCarry() {
    // Arrange
    CkksContext context(IntegerParams{8, 4, 2});
    auto computer = MakeComputer(context);
    const auto lhs = computer.Encrypt({250, 15});
    const auto rhs = computer.Encrypt({10, 1});

    // Act
    const auto sum = computer.Decrypt(computer.Add(lhs, rhs));

    // Assert
    AssertEqual(sum, {4, 16});
}

void TestSubWrapsWithBorrow() {
    // Arrange
    CkksContext context(IntegerParams{8, 4, 2});
    auto computer = MakeComputer(context);
    const auto lhs = computer.Encrypt({3, 42});
    const auto rhs = computer.Encrypt({5, 10});

    // Act
    const auto diff = computer.Decrypt(computer.Sub(lhs, rhs));

    // Assert
    AssertEqual(diff, {254, 32});
}

void TestMulWrapsAtBitWidth() {
    // Arrange
    CkksContext context(IntegerParams{8, 4, 2});
    auto computer = MakeComputer(context);
    const auto lhs = computer.Encrypt({20, 14});
    const auto rhs = computer.Encrypt({13, 3});

    // Act
    const auto product = computer.Decrypt(computer.Mul(lhs, rhs));

    // Assert
    AssertEqual(product, {4, 42});
}

void TestCompareGreaterEqual() {
    // Arrange
    CkksContext context(IntegerParams{16, 4, 3});
    auto computer = MakeComputer(context);
    const auto lhs = computer.Encrypt({5, 7, 9});
    const auto rhs = computer.Encrypt({5, 8, 1});

    // Act
    const auto flags = computer.Decrypt(computer.CompareGreaterEqual(lhs, rhs));

    // Assert
    AssertEqual(flags, {1, 0, 1});
}

void TestLeftShift() {
    // Arrange
    CkksContext context(IntegerParams{16, 4, 2});
    auto computer = MakeComputer(context);
    const auto input = computer.Encrypt({3, 15});

    // Act
    const auto shifted = computer.Decrypt(computer.LeftShift(input, 3));

    // Assert
    AssertEqual(shifted, {24, 120});
}

void TestRightShift() {
    // Arrange
    CkksContext context(IntegerParams{16, 4, 2});
    auto computer = MakeComputer(context);
    const auto input = computer.Encrypt({24, 120});

    // Act
    const auto shifted = computer.Decrypt(computer.RightShift(input, 3));

    // Assert
    AssertEqual(shifted, {3, 15});
}

}  // namespace

int main() {
    TestRoundTrip();
    TestReduceNormalizesDigits();
    TestCarryExtractsOverflowWord();
    TestAddWrapsWithCarry();
    TestSubWrapsWithBorrow();
    TestMulWrapsAtBitWidth();
    TestCompareGreaterEqual();
    TestLeftShift();
    TestRightShift();
    std::cout << "ckks_computer tests passed\n";
    return 0;
}
