// Simple test for overlap detection
#define STRUCTOR_TESTING
#include "structor/optimized_algorithms.hpp"
#include <iostream>
#include <random>

using namespace structor::algorithms;

int main() {
    std::cerr << "Creating intervals...\n";
    
    std::mt19937 rng(42);
    std::uniform_int_distribution<int64_t> start_dist(0, 1000);
    std::uniform_int_distribution<int64_t> len_dist(250, 500);
    
    std::vector<Interval> intervals;
    for (int i = 0; i < 256; ++i) {
        int64_t start = start_dist(rng);
        int64_t len = len_dist(rng);
        intervals.emplace_back(start, start + len, i);
    }
    
    std::cerr << "Created " << intervals.size() << " intervals\n";
    std::cerr << "Finding overlaps...\n";
    
    try {
        auto result = find_overlapping_pairs(intervals);
        std::cerr << "Found " << result.size() << " overlapping pairs\n";
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    }
    
    std::cerr << "Done\n";
    return 0;
}
