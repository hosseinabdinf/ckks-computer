#include "ckks_computer.hpp"

#include <iostream>

int main() {
    using namespace ckks_computer;

    IntegerParams params{64, 4, 8};

    CkksContext context(params);
    context.GenerateKeys();

    IntegerComputer computer(context);

    const auto lhs = computer.Encrypt({1234, 5678});
    const auto rhs = computer.Encrypt({11, 22});

    const auto sum = computer.Decrypt(computer.Add(lhs, rhs));
    const auto product = computer.Decrypt(computer.Mul(lhs, rhs));
    const auto compare = computer.Decrypt(computer.CompareGreaterEqual(lhs, rhs));

    std::cout << "sum:\n";
    for (auto value : sum) {
        std::cout << value << '\n';
    }

    std::cout << "product:\n";
    for (auto value : product) {
        std::cout << value << '\n';
    }

    std::cout << "compare:\n";
    for (auto value : compare) {
        std::cout << value << '\n';
    }

    return 0;
}
