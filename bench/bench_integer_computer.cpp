#include "../src/ckks_computer.hpp"

#include <chrono>
#include <iostream>

namespace {

using Clock = std::chrono::steady_clock;
using ckks_computer::CkksContext;
using ckks_computer::IntegerComputer;
using ckks_computer::IntegerParams;

template <typename Fn>
double MeasureMs(Fn&& fn, std::size_t iterations) {
    const auto start = Clock::now();
    for (std::size_t i = 0; i < iterations; ++i) {
        fn();
    }
    const auto end = Clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count();
}

void Report(const char* label, double elapsedMs, std::size_t iterations) {
    std::cout << label << ": total=" << elapsedMs << "ms, avg=" << (elapsedMs / iterations) << "ms\n";
}

}  // namespace

int main() {
    IntegerParams params{64, 4, 8};
    CkksContext context(params);
    context.GenerateKeys();

    IntegerComputer computer(context);
    const auto lhs = computer.Encrypt({1234, 5678, 42, 99});
    const auto rhs = computer.Encrypt({11, 22, 7, 3});
    constexpr std::size_t iterations = 100;

    Report("add", MeasureMs([&] { (void)computer.Add(lhs, rhs); }, iterations), iterations);
    Report("sub", MeasureMs([&] { (void)computer.Sub(lhs, rhs); }, iterations), iterations);
    Report("mul", MeasureMs([&] { (void)computer.Mul(lhs, rhs); }, iterations), iterations);
    Report(
        "cmp",
        MeasureMs([&] { (void)computer.CompareGreaterEqual(lhs, rhs); }, iterations),
        iterations);
    Report("shl", MeasureMs([&] { (void)computer.LeftShift(lhs, 2); }, iterations), iterations);
    Report("shr", MeasureMs([&] { (void)computer.RightShift(lhs, 2); }, iterations), iterations);

    return 0;
}
