#define STRUCTOR_TESTING
#include "structor/optimized_containers.hpp"
#include <iostream>
#include <vector>

using namespace structor;

int main() {
    std::cerr << "Creating FlatUnionFind...\n";
    FlatUnionFind uf(256);
    
    std::cerr << "Making sets...\n";
    for (int i = 0; i < 256; ++i) {
        uf.make_set(i);
    }
    
    std::cerr << "Performing unions...\n";
    for (int i = 0; i < 100; ++i) {
        uf.unite(i, i + 100);
        if (i % 20 == 0) {
            std::cerr << "  united " << i << " and " << i+100 << "\n";
        }
    }
    
    std::cerr << "Done\n";
    return 0;
}
