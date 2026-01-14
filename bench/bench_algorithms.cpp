/**
 * @file bench_algorithms.cpp
 * @brief Performance benchmarks for Structor optimization algorithms
 * 
 * Compares optimized vs naive implementations to validate performance gains.
 * Build with: clang++ -O3 -std=c++20 -I../include bench_algorithms.cpp -o bench_algorithms
 */

#include <chrono>
#include <iostream>
#include <iomanip>
#include <random>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cstring>

// Define STRUCTOR_TESTING to avoid IDA dependencies
#define STRUCTOR_TESTING

#include "structor/optimized_algorithms.hpp"
#include "structor/optimized_containers.hpp"

using namespace structor;
using namespace structor::algorithms;

// ============================================================================
// Timing utilities
// ============================================================================

class Timer {
public:
    void start() {
        start_ = std::chrono::high_resolution_clock::now();
    }
    
    double stop_us() {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::micro>(end - start_).count();
    }
    
    double stop_ms() {
        return stop_us() / 1000.0;
    }

private:
    std::chrono::high_resolution_clock::time_point start_;
};

struct BenchResult {
    const char* name;
    double naive_us;
    double optimized_us;
    double speedup;
    
    void print() const {
        std::cout << std::left << std::setw(40) << name
                  << std::right << std::setw(12) << std::fixed << std::setprecision(2) << naive_us << " us"
                  << std::setw(12) << optimized_us << " us"
                  << std::setw(10) << std::setprecision(2) << speedup << "x"
                  << "\n";
    }
};

// ============================================================================
// Naive implementations for comparison
// ============================================================================

namespace naive {

uint32_t euclidean_gcd(uint32_t a, uint32_t b) {
    while (b != 0) {
        uint32_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

uint32_t gcd_array(const std::vector<uint32_t>& values) {
    if (values.empty()) return 0;
    uint32_t result = values[0];
    for (size_t i = 1; i < values.size(); ++i) {
        result = euclidean_gcd(result, values[i]);
    }
    return result;
}

// O(n^2) pairwise overlap detection
std::vector<std::pair<int32_t, int32_t>> find_overlaps_naive(
    const std::vector<Interval>& intervals)
{
    std::vector<std::pair<int32_t, int32_t>> result;
    for (size_t i = 0; i < intervals.size(); ++i) {
        for (size_t j = i + 1; j < intervals.size(); ++j) {
            if (intervals[i].overlaps(intervals[j])) {
                result.emplace_back(intervals[i].id, intervals[j].id);
            }
        }
    }
    return result;
}

} // namespace naive

// ============================================================================
// Data generators
// ============================================================================

std::vector<uint32_t> generate_random_values(size_t count, uint32_t max_val, unsigned seed = 42) {
    std::mt19937 rng(seed);
    std::uniform_int_distribution<uint32_t> dist(1, max_val);
    
    std::vector<uint32_t> values(count);
    for (auto& v : values) {
        v = dist(rng);
    }
    return values;
}

std::vector<Interval> generate_sparse_intervals(size_t count, int64_t range, unsigned seed = 42) {
    // Sparse intervals with few overlaps
    std::mt19937 rng(seed);
    std::uniform_int_distribution<int64_t> start_dist(0, range);
    std::uniform_int_distribution<int64_t> len_dist(1, range / count / 2);
    
    std::vector<Interval> intervals;
    intervals.reserve(count);
    
    for (size_t i = 0; i < count; ++i) {
        int64_t start = start_dist(rng);
        int64_t len = len_dist(rng);
        intervals.emplace_back(start, start + len, static_cast<int32_t>(i));
    }
    
    return intervals;
}

std::vector<Interval> generate_dense_intervals(size_t count, int64_t range, unsigned seed = 42) {
    // Dense intervals with many overlaps
    std::mt19937 rng(seed);
    std::uniform_int_distribution<int64_t> start_dist(0, range);
    std::uniform_int_distribution<int64_t> len_dist(range / 4, range / 2);
    
    std::vector<Interval> intervals;
    intervals.reserve(count);
    
    for (size_t i = 0; i < count; ++i) {
        int64_t start = start_dist(rng);
        int64_t len = len_dist(rng);
        intervals.emplace_back(start, start + len, static_cast<int32_t>(i));
    }
    
    return intervals;
}

// ============================================================================
// Benchmarks
// ============================================================================

BenchResult bench_gcd_single() {
    constexpr int ITERATIONS = 100000;
    Timer timer;
    
    // Test values
    std::vector<std::pair<uint32_t, uint32_t>> pairs;
    pairs.reserve(ITERATIONS);
    std::mt19937 rng(42);
    std::uniform_int_distribution<uint32_t> dist(1, 1000000);
    for (int i = 0; i < ITERATIONS; ++i) {
        pairs.emplace_back(dist(rng), dist(rng));
    }
    
    // Naive (Euclidean)
    volatile uint32_t sink = 0;
    timer.start();
    for (const auto& [a, b] : pairs) {
        sink = naive::euclidean_gcd(a, b);
    }
    double naive_us = timer.stop_us();
    
    // Optimized (Binary)
    timer.start();
    for (const auto& [a, b] : pairs) {
        sink = binary_gcd(a, b);
    }
    double opt_us = timer.stop_us();
    
    (void)sink;
    return {"GCD single pair (100k iterations)", naive_us, opt_us, naive_us / opt_us};
}

BenchResult bench_gcd_array_small() {
    constexpr int ITERATIONS = 10000;
    constexpr size_t ARRAY_SIZE = 16;
    Timer timer;
    
    std::vector<std::vector<uint32_t>> arrays;
    for (int i = 0; i < ITERATIONS; ++i) {
        arrays.push_back(generate_random_values(ARRAY_SIZE, 10000, i));
    }
    
    // Naive
    volatile uint32_t sink = 0;
    timer.start();
    for (const auto& arr : arrays) {
        sink = naive::gcd_array(arr);
    }
    double naive_us = timer.stop_us();
    
    // Optimized
    timer.start();
    for (const auto& arr : arrays) {
        sink = gcd_array(arr);
    }
    double opt_us = timer.stop_us();
    
    (void)sink;
    return {"GCD array (16 elements, 10k iterations)", naive_us, opt_us, naive_us / opt_us};
}

BenchResult bench_gcd_array_large() {
    constexpr int ITERATIONS = 1000;
    constexpr size_t ARRAY_SIZE = 256;
    Timer timer;
    
    std::vector<std::vector<uint32_t>> arrays;
    for (int i = 0; i < ITERATIONS; ++i) {
        arrays.push_back(generate_random_values(ARRAY_SIZE, 100000, i));
    }
    
    // Naive
    volatile uint32_t sink = 0;
    timer.start();
    for (const auto& arr : arrays) {
        sink = naive::gcd_array(arr);
    }
    double naive_us = timer.stop_us();
    
    // Optimized
    timer.start();
    for (const auto& arr : arrays) {
        sink = gcd_array(arr);
    }
    double opt_us = timer.stop_us();
    
    (void)sink;
    return {"GCD array (256 elements, 1k iterations)", naive_us, opt_us, naive_us / opt_us};
}

BenchResult bench_overlap_sparse_small() {
    constexpr int ITERATIONS = 1000;
    constexpr size_t N = 64;
    Timer timer;
    
    std::vector<std::vector<Interval>> datasets;
    for (int i = 0; i < ITERATIONS; ++i) {
        datasets.push_back(generate_sparse_intervals(N, 10000, i));
    }
    
    // Naive O(n^2)
    volatile size_t sink = 0;
    timer.start();
    for (auto& data : datasets) {
        auto result = naive::find_overlaps_naive(data);
        sink = result.size();
    }
    double naive_us = timer.stop_us();
    
    // Optimized sweep line
    timer.start();
    for (auto& data : datasets) {
        auto result = find_overlapping_pairs(data);
        sink = result.size();
    }
    double opt_us = timer.stop_us();
    
    (void)sink;
    return {"Overlap detection sparse (64 intervals, 1k iter)", naive_us, opt_us, naive_us / opt_us};
}

BenchResult bench_overlap_sparse_large() {
    constexpr int ITERATIONS = 100;
    constexpr size_t N = 512;
    Timer timer;
    
    std::vector<std::vector<Interval>> datasets;
    for (int i = 0; i < ITERATIONS; ++i) {
        datasets.push_back(generate_sparse_intervals(N, 100000, i));
    }
    
    // Naive O(n^2)
    volatile size_t sink = 0;
    timer.start();
    for (auto& data : datasets) {
        auto result = naive::find_overlaps_naive(data);
        sink = result.size();
    }
    double naive_us = timer.stop_us();
    
    // Optimized sweep line
    timer.start();
    for (auto& data : datasets) {
        auto result = find_overlapping_pairs(data);
        sink = result.size();
    }
    double opt_us = timer.stop_us();
    
    (void)sink;
    return {"Overlap detection sparse (512 intervals, 100 iter)", naive_us, opt_us, naive_us / opt_us};
}

BenchResult bench_overlap_dense() {
    constexpr int ITERATIONS = 100;
    constexpr size_t N = 256;
    Timer timer;
    
    std::vector<std::vector<Interval>> datasets;
    for (int i = 0; i < ITERATIONS; ++i) {
        datasets.push_back(generate_dense_intervals(N, 1000, i));
    }
    
    // Naive O(n^2)
    volatile size_t sink = 0;
    timer.start();
    for (auto& data : datasets) {
        auto result = naive::find_overlaps_naive(data);
        sink = result.size();
    }
    double naive_us = timer.stop_us();
    
    // Optimized sweep line
    timer.start();
    for (auto& data : datasets) {
        auto result = find_overlapping_pairs(data);
        sink = result.size();
    }
    double opt_us = timer.stop_us();
    
    (void)sink;
    return {"Overlap detection dense (256 intervals, 100 iter)", naive_us, opt_us, naive_us / opt_us};
}

// Simple naive union-find without std::function overhead
class NaiveUnionFind {
public:
    explicit NaiveUnionFind(size_t n) : parent_(n) {
        for (size_t i = 0; i < n; ++i) parent_[i] = i;
    }
    
    size_t find(size_t x) {
        if (parent_[x] != x) {
            parent_[x] = find(parent_[x]);  // Path compression
        }
        return parent_[x];
    }
    
    void unite(size_t a, size_t b) {
        size_t ra = find(a);
        size_t rb = find(b);
        if (ra != rb) parent_[ra] = rb;
    }
    
private:
    std::vector<size_t> parent_;
};

BenchResult bench_union_find() {
    constexpr int ITERATIONS = 10000;
    constexpr size_t N = 256;
    Timer timer;
    
    // Generate random union operations
    std::mt19937 rng(42);
    std::uniform_int_distribution<size_t> dist(0, N - 1);
    
    std::vector<std::pair<size_t, size_t>> operations;
    for (size_t i = 0; i < N * 4; ++i) {
        operations.emplace_back(dist(rng), dist(rng));
    }
    
    // Naive implementation using vector-based union-find
    timer.start();
    for (int iter = 0; iter < ITERATIONS; ++iter) {
        NaiveUnionFind uf(N);
        for (const auto& [a, b] : operations) {
            uf.unite(a, b);
        }
    }
    double naive_us = timer.stop_us();
    
    // Optimized FlatUnionFind
    timer.start();
    for (int iter = 0; iter < ITERATIONS; ++iter) {
        FlatUnionFind uf(N);
        // Initialize all elements first
        for (size_t i = 0; i < N; ++i) {
            uf.make_set(static_cast<int32_t>(i));
        }
        // Then perform union operations
        for (const auto& [a, b] : operations) {
            uf.unite(a, b);
        }
    }
    double opt_us = timer.stop_us();
    
    return {"Union-Find (256 elements, 10k iterations)", naive_us, opt_us, naive_us / opt_us};
}

BenchResult bench_small_vector() {
    constexpr int ITERATIONS = 100000;
    constexpr size_t INLINE_SIZE = 8;
    Timer timer;
    
    // Operations: push_back up to INLINE_SIZE elements
    timer.start();
    for (int iter = 0; iter < ITERATIONS; ++iter) {
        std::vector<int> vec;
        for (size_t i = 0; i < INLINE_SIZE; ++i) {
            vec.push_back(static_cast<int>(i));
        }
        volatile int sink = vec.back();
        (void)sink;
    }
    double std_us = timer.stop_us();
    
    timer.start();
    for (int iter = 0; iter < ITERATIONS; ++iter) {
        SmallVector<int, INLINE_SIZE> vec;
        for (size_t i = 0; i < INLINE_SIZE; ++i) {
            vec.push_back(static_cast<int>(i));
        }
        volatile int sink = vec.back();
        (void)sink;
    }
    double opt_us = timer.stop_us();
    
    return {"SmallVector<8> inline ops (100k iterations)", std_us, opt_us, std_us / opt_us};
}

BenchResult bench_arena_allocator() {
    constexpr int ITERATIONS = 10000;
    constexpr size_t NUM_ALLOCS = 100;
    constexpr size_t ALLOC_SIZE = 64;
    Timer timer;
    
    // Standard allocator
    timer.start();
    for (int iter = 0; iter < ITERATIONS; ++iter) {
        std::vector<void*> ptrs;
        ptrs.reserve(NUM_ALLOCS);
        for (size_t i = 0; i < NUM_ALLOCS; ++i) {
            ptrs.push_back(std::malloc(ALLOC_SIZE));
        }
        for (void* p : ptrs) {
            std::free(p);
        }
    }
    double std_us = timer.stop_us();
    
    // Arena allocator - use larger block size to avoid reallocation
    timer.start();
    for (int iter = 0; iter < ITERATIONS; ++iter) {
        Arena arena(NUM_ALLOCS * ALLOC_SIZE * 2);  // 2x space for alignment overhead
        for (size_t i = 0; i < NUM_ALLOCS; ++i) {
            volatile void* p = arena.allocate(ALLOC_SIZE);
            (void)p;
        }
        // Arena automatically freed when it goes out of scope
    }
    double opt_us = timer.stop_us();
    
    return {"Arena allocator (100 allocs, 10k iterations)", std_us, opt_us, std_us / opt_us};
}

BenchResult bench_arithmetic_progression() {
    constexpr int ITERATIONS = 100000;
    constexpr size_t N = 16;
    Timer timer;
    
    // Generate test data
    std::vector<int64_t> ap_data(N);
    for (size_t i = 0; i < N; ++i) {
        ap_data[i] = 100 + static_cast<int64_t>(i) * 8;
    }
    
    // Naive: check all differences
    volatile bool sink = false;
    timer.start();
    for (int iter = 0; iter < ITERATIONS; ++iter) {
        bool is_ap = true;
        if (ap_data.size() >= 2) {
            int64_t diff = ap_data[1] - ap_data[0];
            for (size_t i = 2; i < ap_data.size(); ++i) {
                if (ap_data[i] - ap_data[i-1] != diff) {
                    is_ap = false;
                    break;
                }
            }
        }
        sink = is_ap;
    }
    double naive_us = timer.stop_us();
    
    // Optimized
    timer.start();
    for (int iter = 0; iter < ITERATIONS; ++iter) {
        auto result = detect_arithmetic_progression(ap_data.data(), ap_data.size());
        sink = result.has_value();
    }
    double opt_us = timer.stop_us();
    
    (void)sink;
    return {"Arithmetic progression (16 elements, 100k iter)", naive_us, opt_us, naive_us / opt_us};
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "\n";
    std::cout << "===============================================================================\n";
    std::cout << "                     Structor Algorithm Benchmarks\n";
    std::cout << "===============================================================================\n\n";
    
    std::cout << std::left << std::setw(40) << "Benchmark"
              << std::right << std::setw(15) << "Naive"
              << std::setw(15) << "Optimized"
              << std::setw(10) << "Speedup"
              << "\n";
    std::cout << std::string(80, '-') << "\n";
    
    std::vector<BenchResult> results;
    
    try {
    
    // GCD benchmarks
    results.push_back(bench_gcd_single());
    results.push_back(bench_gcd_array_small());
    results.push_back(bench_gcd_array_large());
    
    // Overlap detection benchmarks
    results.push_back(bench_overlap_sparse_small());
    results.push_back(bench_overlap_sparse_large());
    results.push_back(bench_overlap_dense());
    
    // Container benchmarks
    results.push_back(bench_union_find());
    results.push_back(bench_small_vector());
    results.push_back(bench_arena_allocator());
    
    // Algorithm benchmarks
    results.push_back(bench_arithmetic_progression());
    
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    }
    
    for (const auto& r : results) {
        r.print();
    }
    
    std::cout << "\n";
    
    // Summary statistics
    double avg_speedup = 0;
    double max_speedup = 0;
    double min_speedup = std::numeric_limits<double>::max();
    
    for (const auto& r : results) {
        avg_speedup += r.speedup;
        max_speedup = std::max(max_speedup, r.speedup);
        min_speedup = std::min(min_speedup, r.speedup);
    }
    avg_speedup /= results.size();
    
    std::cout << "Summary:\n";
    std::cout << "  Average speedup: " << std::fixed << std::setprecision(2) << avg_speedup << "x\n";
    std::cout << "  Max speedup:     " << max_speedup << "x\n";
    std::cout << "  Min speedup:     " << min_speedup << "x\n";
    std::cout << "\n";
    
    return 0;
}
