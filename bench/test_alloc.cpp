// Test aligned allocation
#include <iostream>
#include <cstdlib>
#include <cstdint>

void* my_aligned_alloc(size_t alignment, size_t size) {
    std::cerr << "aligned_alloc(alignment=" << alignment << ", size=" << size << ")\n";
    
#if defined(__APPLE__)
    void* ptr = nullptr;
    int result = posix_memalign(&ptr, alignment, size);
    std::cerr << "  posix_memalign returned " << result << ", ptr=" << ptr << "\n";
    if (result != 0) {
        return nullptr;
    }
    return ptr;
#else
    return std::aligned_alloc(alignment, size);
#endif
}

int main() {
    // Test with alignof(int32_t) = 4
    void* p1 = my_aligned_alloc(4, 64);
    if (p1) std::free(p1);
    
    // Test with alignment = 16
    void* p2 = my_aligned_alloc(16, 64);
    if (p2) std::free(p2);
    
    // Test with alignment = 4 but small size
    void* p3 = my_aligned_alloc(4, 32);
    if (p3) std::free(p3);
    
    return 0;
}
