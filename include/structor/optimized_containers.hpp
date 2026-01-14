#ifndef STRUCTOR_OPTIMIZED_CONTAINERS_HPP
#define STRUCTOR_OPTIMIZED_CONTAINERS_HPP

/**
 * @file optimized_containers.hpp
 * @brief High-performance data structures for Structor
 * 
 * Contains:
 * - Arena/Pool allocators for reduced allocation overhead
 * - Optimized Union-Find with flat storage
 * - Interval tree for O(n log n) overlap detection  
 * - Flat hash maps with cache-friendly probing
 * - Small vector optimization
 */

#include "structor/simd.hpp"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>
#include <type_traits>
#include <new>
#include <cassert>
#include <unordered_map>

namespace structor {

// ============================================================================
// Arena Allocator
// ============================================================================

/**
 * @brief Fast bump-pointer allocator for temporary allocations
 * 
 * Allocations are O(1) - just bump the pointer. All memory is freed at once
 * when the arena is destroyed or reset. Perfect for algorithms that allocate
 * many small objects with similar lifetimes.
 * 
 * Thread-safety: NOT thread-safe. Use one arena per thread.
 */
class Arena {
public:
    static constexpr size_t kDefaultBlockSize = 64 * 1024;  // 64KB blocks
    
    explicit Arena(size_t block_size = kDefaultBlockSize)
        : block_size_(block_size)
        , current_block_(nullptr)
        , current_pos_(0)
        , current_end_(0)
    {
        allocate_block();
    }
    
    ~Arena() {
        for (char* block : blocks_) {
            simd::aligned_free(block);
        }
    }
    
    // No copy/move - arena has identity
    Arena(const Arena&) = delete;
    Arena& operator=(const Arena&) = delete;
    Arena(Arena&&) = delete;
    Arena& operator=(Arena&&) = delete;
    
    /**
     * @brief Allocate memory from the arena
     * 
     * @param size Bytes to allocate
     * @param align Alignment requirement (default: 16)
     * @return Pointer to allocated memory (never null)
     * @throws std::bad_alloc if allocation fails
     */
    void* allocate(size_t size, size_t align = 16) {
        // Align current position
        size_t aligned_pos = simd::align_up<16>(current_pos_);
        
        // Check if we need a new block
        if (STRUCTOR_UNLIKELY(aligned_pos + size > current_end_)) {
            // Need new block
            if (size > block_size_ / 2) {
                // Large allocation - give it its own block
                char* large_block = static_cast<char*>(
                    simd::aligned_alloc(simd::kCacheLine, size));
                if (!large_block) throw std::bad_alloc();
                large_blocks_.push_back(large_block);
                return large_block;
            }
            
            allocate_block();
            aligned_pos = 0;
        }
        
        void* result = current_block_ + aligned_pos;
        current_pos_ = aligned_pos + size;
        bytes_allocated_ += size;
        
        return result;
    }
    
    /**
     * @brief Allocate and construct an object
     */
    template<typename T, typename... Args>
    T* create(Args&&... args) {
        void* mem = allocate(sizeof(T), alignof(T));
        return new (mem) T(std::forward<Args>(args)...);
    }
    
    /**
     * @brief Allocate array of objects
     */
    template<typename T>
    T* allocate_array(size_t count) {
        if (count == 0) return nullptr;
        void* mem = allocate(sizeof(T) * count, alignof(T));
        return static_cast<T*>(mem);
    }
    
    /**
     * @brief Reset arena for reuse (keeps allocated blocks)
     */
    void reset() {
        // Free large blocks
        for (char* block : large_blocks_) {
            simd::aligned_free(block);
        }
        large_blocks_.clear();
        
        // Reset to first block
        if (!blocks_.empty()) {
            current_block_ = blocks_[0];
            current_pos_ = 0;
            current_end_ = block_size_;
        }
        
        bytes_allocated_ = 0;
    }
    
    size_t bytes_allocated() const { return bytes_allocated_; }
    size_t block_count() const { return blocks_.size(); }
    
private:
    void allocate_block() {
        char* block = static_cast<char*>(
            simd::aligned_alloc(simd::kCacheLine, block_size_));
        if (!block) throw std::bad_alloc();
        
        blocks_.push_back(block);
        current_block_ = block;
        current_pos_ = 0;
        current_end_ = block_size_;
    }
    
    size_t block_size_;
    char* current_block_;
    size_t current_pos_;
    size_t current_end_;
    size_t bytes_allocated_ = 0;
    
    std::vector<char*> blocks_;       // Fixed-size blocks
    std::vector<char*> large_blocks_; // Oversized allocations
};

// ============================================================================
// Object Pool
// ============================================================================

/**
 * @brief Type-safe object pool with free list
 * 
 * Provides O(1) allocation and deallocation for fixed-size objects.
 * Memory is reused via a free list, avoiding fragmentation.
 */
template<typename T>
class ObjectPool {
    static_assert(sizeof(T) >= sizeof(void*), 
                  "Object must be at least pointer-sized");
    
    union Slot {
        Slot* next;
        alignas(T) char storage[sizeof(T)];
    };
    
    static constexpr size_t kSlotsPerBlock = 
        std::max(size_t{64}, simd::kCacheLine * 8 / sizeof(Slot));
    
public:
    ObjectPool() : free_list_(nullptr) {}
    
    ~ObjectPool() {
        // Note: Objects are NOT destructed - caller must do that
        for (Slot* block : blocks_) {
            simd::aligned_free(block);
        }
    }
    
    // No copy/move
    ObjectPool(const ObjectPool&) = delete;
    ObjectPool& operator=(const ObjectPool&) = delete;
    
    T* allocate() {
        if (STRUCTOR_UNLIKELY(!free_list_)) {
            grow();
        }
        
        Slot* slot = free_list_;
        free_list_ = slot->next;
        return reinterpret_cast<T*>(&slot->storage);
    }
    
    void deallocate(T* ptr) {
        if (!ptr) return;
        
        Slot* slot = reinterpret_cast<Slot*>(ptr);
        slot->next = free_list_;
        free_list_ = slot;
    }
    
    template<typename... Args>
    T* create(Args&&... args) {
        T* ptr = allocate();
        return new (ptr) T(std::forward<Args>(args)...);
    }
    
    void destroy(T* ptr) {
        if (ptr) {
            ptr->~T();
            deallocate(ptr);
        }
    }
    
private:
    void grow() {
        // Use at least minimum alignment required by posix_memalign
        constexpr size_t align = alignof(Slot) > simd::kMinAlignment 
                                 ? alignof(Slot) : simd::kMinAlignment;
        
        Slot* block = static_cast<Slot*>(
            simd::aligned_alloc(align, sizeof(Slot) * kSlotsPerBlock));
        if (!block) throw std::bad_alloc();
        
        blocks_.push_back(block);
        
        // Link all slots into free list
        for (size_t i = 0; i < kSlotsPerBlock - 1; ++i) {
            block[i].next = &block[i + 1];
        }
        block[kSlotsPerBlock - 1].next = free_list_;
        free_list_ = block;
    }
    
    Slot* free_list_;
    std::vector<Slot*> blocks_;
};

// ============================================================================
// Optimized Union-Find (Disjoint Set)
// ============================================================================

/**
 * @brief High-performance Union-Find with flat contiguous storage
 * 
 * Improvements over std::unordered_map-based implementation:
 * - Flat array storage - cache-friendly sequential access
 * - Path compression with halving (non-recursive)
 * - Union by rank
 * - Batch operations
 * 
 * Time complexity: O(alpha(n)) per operation where alpha is inverse Ackermann
 */
class FlatUnionFind {
public:
    explicit FlatUnionFind(size_t capacity = 0)
        : size_(0)
        , capacity_(0)  // Start with 0, let reserve() set it properly
    {
        if (capacity > 0) {
            reserve(capacity);
        }
    }
    
    /**
     * @brief Reserve capacity for n elements
     */
    void reserve(size_t n) {
        if (n <= capacity_) return;
        
        // Round up to at least 64 entries for cache efficiency
        constexpr size_t kMinCapacity = 64;
        if (n < kMinCapacity) n = kMinCapacity;
        
        // Ensure allocation size is cache-line aligned
        size_t alloc_size = n * sizeof(Entry);
        alloc_size = simd::align_up<simd::kCacheLine>(alloc_size);
        n = alloc_size / sizeof(Entry);
        
        Entry* new_data = static_cast<Entry*>(
            simd::aligned_alloc(simd::kCacheLine, alloc_size));
        if (!new_data) throw std::bad_alloc();
        
        if (data_) {
            std::memcpy(new_data, data_, size_ * sizeof(Entry));
            simd::aligned_free(data_);
        }
        
        data_ = new_data;
        capacity_ = n;
    }
    
    ~FlatUnionFind() {
        if (data_) simd::aligned_free(data_);
    }
    
    // Move only
    FlatUnionFind(FlatUnionFind&& other) noexcept
        : data_(other.data_)
        , size_(other.size_)
        , capacity_(other.capacity_)
    {
        other.data_ = nullptr;
        other.size_ = 0;
        other.capacity_ = 0;
    }
    
    FlatUnionFind& operator=(FlatUnionFind&& other) noexcept {
        if (this != &other) {
            if (data_) simd::aligned_free(data_);
            data_ = other.data_;
            size_ = other.size_;
            capacity_ = other.capacity_;
            other.data_ = nullptr;
            other.size_ = 0;
            other.capacity_ = 0;
        }
        return *this;
    }
    
    FlatUnionFind(const FlatUnionFind&) = delete;
    FlatUnionFind& operator=(const FlatUnionFind&) = delete;
    
    /**
     * @brief Ensure element exists in the set
     * @return Index of the element
     */
    size_t make_set(int32_t id) {
        auto it = id_to_index_.find(id);
        if (it != id_to_index_.end()) {
            return it->second;
        }
        
        if (size_ >= capacity_) {
            reserve(std::max(capacity_ * 2, size_t{64}));
        }
        
        size_t idx = size_++;
        data_[idx].parent = static_cast<uint32_t>(idx);  // Self-parent
        data_[idx].rank = 0;
        data_[idx].id = id;
        
        id_to_index_[id] = idx;
        return idx;
    }
    
    /**
     * @brief Find with path compression (halving)
     * 
     * Uses path halving: each node skips one level up.
     * Non-recursive, cache-friendly.
     */
    size_t find(size_t idx) noexcept {
        assert(idx < size_);
        
        // Path halving: make every node point to its grandparent
        while (data_[idx].parent != idx) {
            size_t grandparent = data_[data_[idx].parent].parent;
            data_[idx].parent = static_cast<uint32_t>(grandparent);
            idx = grandparent;
        }
        
        return idx;
    }
    
    /**
     * @brief Find by ID (creates set if needed)
     */
    size_t find_by_id(int32_t id) {
        size_t idx = make_set(id);
        return find(idx);
    }
    
    /**
     * @brief Union by rank
     * @return Root of the merged set
     */
    size_t unite(size_t x, size_t y) noexcept {
        x = find(x);
        y = find(y);
        
        if (x == y) return x;
        
        // Union by rank
        if (data_[x].rank < data_[y].rank) {
            std::swap(x, y);
        }
        
        data_[y].parent = static_cast<uint32_t>(x);
        
        if (data_[x].rank == data_[y].rank) {
            data_[x].rank++;
        }
        
        return x;
    }
    
    /**
     * @brief Unite by ID
     */
    size_t unite_by_id(int32_t id1, int32_t id2) {
        size_t x = make_set(id1);
        size_t y = make_set(id2);
        return unite(x, y);
    }
    
    /**
     * @brief Check if two elements are in the same set
     */
    bool same_set(size_t x, size_t y) noexcept {
        return find(x) == find(y);
    }
    
    bool same_set_by_id(int32_t id1, int32_t id2) {
        return same_set(make_set(id1), make_set(id2));
    }
    
    /**
     * @brief Get all elements in the same set as x
     */
    std::vector<int32_t> get_set(size_t x) {
        std::vector<int32_t> result;
        size_t root = find(x);
        
        for (size_t i = 0; i < size_; ++i) {
            if (find(i) == root) {
                result.push_back(data_[i].id);
            }
        }
        
        return result;
    }
    
    /**
     * @brief Batch unite - more cache-efficient for multiple operations
     */
    void batch_unite(const std::vector<std::pair<int32_t, int32_t>>& pairs) {
        // Prefetch all indices first
        for (const auto& [id1, id2] : pairs) {
            make_set(id1);
            make_set(id2);
        }
        
        // Then perform unites
        for (const auto& [id1, id2] : pairs) {
            unite_by_id(id1, id2);
        }
    }
    
    size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    
    /**
     * @brief Get the ID for an index
     */
    int32_t get_id(size_t idx) const noexcept {
        assert(idx < size_);
        return data_[idx].id;
    }
    
    void clear() {
        size_ = 0;
        id_to_index_.clear();
    }
    
private:
    struct Entry {
        uint32_t parent;
        uint16_t rank;
        int32_t id;
    };
    static_assert(sizeof(Entry) <= 16, "Entry should fit in 16 bytes");
    
    Entry* data_ = nullptr;
    size_t size_ = 0;
    size_t capacity_ = 0;
    std::unordered_map<int32_t, size_t> id_to_index_;
};

// ============================================================================
// Interval Tree for Overlap Detection
// ============================================================================

/**
 * @brief Interval tree for efficient overlap queries
 * 
 * Replaces O(n²) pairwise overlap checking with O(n log n + k) queries
 * where k is the number of overlapping pairs.
 */
template<typename T = int64_t>
class IntervalTree {
public:
    struct Interval {
        T start;
        T end;
        int32_t id;  // User-defined identifier
        
        bool overlaps(const Interval& other) const noexcept {
            return start < other.end && other.start < end;
        }
    };
    
    IntervalTree() = default;
    
    /**
     * @brief Build tree from intervals
     * @param intervals Vector of intervals (will be modified)
     */
    void build(std::vector<Interval>& intervals) {
        intervals_ = std::move(intervals);
        
        if (intervals_.empty()) return;
        
        // Sort by start point
        std::sort(intervals_.begin(), intervals_.end(),
            [](const Interval& a, const Interval& b) {
                return a.start < b.start;
            });
        
        // Build segment tree with max-end augmentation
        size_t n = intervals_.size();
        tree_.resize(n * 4);
        max_end_.resize(n * 4);
        
        build_tree(1, 0, n - 1);
    }
    
    /**
     * @brief Find all intervals overlapping with query
     * @return Vector of overlapping interval IDs
     */
    std::vector<int32_t> query_overlaps(T start, T end) const {
        std::vector<int32_t> result;
        if (intervals_.empty()) return result;
        
        query_overlaps_impl(1, 0, intervals_.size() - 1, start, end, result);
        return result;
    }
    
    /**
     * @brief Find all overlapping pairs (more efficient than O(n²))
     * @return Vector of overlapping pairs (id1, id2)
     */
    std::vector<std::pair<int32_t, int32_t>> find_all_overlaps() const {
        std::vector<std::pair<int32_t, int32_t>> result;
        if (intervals_.size() < 2) return result;
        
        // Use plane sweep algorithm
        // Events: start points (type=0), end points (type=1)
        struct Event {
            T point;
            int type;  // 0=start, 1=end
            int32_t id;
            
            bool operator<(const Event& other) const {
                if (point != other.point) return point < other.point;
                return type < other.type;  // Process starts before ends at same point
            }
        };
        
        std::vector<Event> events;
        events.reserve(intervals_.size() * 2);
        
        for (const auto& iv : intervals_) {
            events.push_back({iv.start, 0, iv.id});
            events.push_back({iv.end, 1, iv.id});
        }
        
        std::sort(events.begin(), events.end());
        
        // Active intervals set
        std::vector<int32_t> active;
        
        for (const auto& event : events) {
            if (event.type == 0) {
                // Start event - report overlaps with all active intervals
                for (int32_t active_id : active) {
                    result.emplace_back(
                        std::min(active_id, event.id),
                        std::max(active_id, event.id)
                    );
                }
                active.push_back(event.id);
            } else {
                // End event - remove from active
                auto it = std::find(active.begin(), active.end(), event.id);
                if (it != active.end()) {
                    active.erase(it);
                }
            }
        }
        
        // Remove duplicates
        std::sort(result.begin(), result.end());
        result.erase(std::unique(result.begin(), result.end()), result.end());
        
        return result;
    }
    
    size_t size() const noexcept { return intervals_.size(); }
    bool empty() const noexcept { return intervals_.empty(); }
    
private:
    void build_tree(size_t node, size_t l, size_t r) {
        if (l == r) {
            tree_[node] = l;
            max_end_[node] = intervals_[l].end;
            return;
        }
        
        size_t mid = (l + r) / 2;
        build_tree(node * 2, l, mid);
        build_tree(node * 2 + 1, mid + 1, r);
        
        max_end_[node] = std::max(max_end_[node * 2], max_end_[node * 2 + 1]);
    }
    
    void query_overlaps_impl(
        size_t node, size_t l, size_t r,
        T qstart, T qend,
        std::vector<int32_t>& result) const
    {
        // If max_end in this subtree is <= qstart, no overlaps possible
        if (max_end_[node] <= qstart) return;
        
        // If start of leftmost interval in range is >= qend, no overlaps
        if (intervals_[l].start >= qend) return;
        
        if (l == r) {
            // Leaf node - check overlap
            if (intervals_[l].start < qend && qstart < intervals_[l].end) {
                result.push_back(intervals_[l].id);
            }
            return;
        }
        
        size_t mid = (l + r) / 2;
        query_overlaps_impl(node * 2, l, mid, qstart, qend, result);
        query_overlaps_impl(node * 2 + 1, mid + 1, r, qstart, qend, result);
    }
    
    std::vector<Interval> intervals_;
    std::vector<size_t> tree_;
    std::vector<T> max_end_;
};

// ============================================================================
// Small Vector (inline storage optimization)
// ============================================================================

/**
 * @brief Vector with inline storage for small sizes
 * 
 * Avoids heap allocation for small vectors, commonly used for
 * small sets of overlapping candidates.
 */
template<typename T, size_t InlineCapacity = 8>
class SmallVector {
public:
    SmallVector() : size_(0), capacity_(InlineCapacity), heap_(nullptr) {}
    
    explicit SmallVector(size_t count) : size_(0), capacity_(InlineCapacity), heap_(nullptr) {
        resize(count);
    }
    
    SmallVector(std::initializer_list<T> init) 
        : size_(0), capacity_(InlineCapacity), heap_(nullptr)
    {
        reserve(init.size());
        for (const auto& v : init) {
            push_back(v);
        }
    }
    
    ~SmallVector() {
        clear();
        if (heap_) simd::aligned_free(heap_);
    }
    
    SmallVector(const SmallVector& other) 
        : size_(0), capacity_(InlineCapacity), heap_(nullptr)
    {
        reserve(other.size_);
        for (size_t i = 0; i < other.size_; ++i) {
            new (data() + i) T(other[i]);
        }
        size_ = other.size_;
    }
    
    SmallVector& operator=(const SmallVector& other) {
        if (this != &other) {
            clear();
            reserve(other.size_);
            for (size_t i = 0; i < other.size_; ++i) {
                new (data() + i) T(other[i]);
            }
            size_ = other.size_;
        }
        return *this;
    }
    
    SmallVector(SmallVector&& other) noexcept 
        : size_(other.size_), capacity_(other.capacity_)
    {
        if (other.is_inline()) {
            // Move inline elements
            for (size_t i = 0; i < size_; ++i) {
                new (inline_storage() + i) T(std::move(other.inline_storage()[i]));
                other.inline_storage()[i].~T();
            }
            heap_ = nullptr;
        } else {
            // Steal heap pointer
            heap_ = other.heap_;
            other.heap_ = nullptr;
        }
        other.size_ = 0;
        other.capacity_ = InlineCapacity;
    }
    
    SmallVector& operator=(SmallVector&& other) noexcept {
        if (this != &other) {
            clear();
            if (heap_) simd::aligned_free(heap_);
            
            size_ = other.size_;
            capacity_ = other.capacity_;
            
            if (other.is_inline()) {
                for (size_t i = 0; i < size_; ++i) {
                    new (inline_storage() + i) T(std::move(other.inline_storage()[i]));
                    other.inline_storage()[i].~T();
                }
                heap_ = nullptr;
            } else {
                heap_ = other.heap_;
                other.heap_ = nullptr;
            }
            
            other.size_ = 0;
            other.capacity_ = InlineCapacity;
        }
        return *this;
    }
    
    void reserve(size_t n) {
        if (n <= capacity_) return;
        
        // Use at least minimum alignment required by posix_memalign
        constexpr size_t align = alignof(T) > simd::kMinAlignment 
                                 ? alignof(T) : simd::kMinAlignment;
        
        T* new_data = static_cast<T*>(
            simd::aligned_alloc(align, n * sizeof(T)));
        if (!new_data) throw std::bad_alloc();
        
        // Move elements
        for (size_t i = 0; i < size_; ++i) {
            new (new_data + i) T(std::move(data()[i]));
            data()[i].~T();
        }
        
        if (heap_) simd::aligned_free(heap_);
        heap_ = new_data;
        capacity_ = n;
    }
    
    void resize(size_t n) {
        if (n > capacity_) {
            reserve(std::max(n, capacity_ * 2));
        }
        
        // Construct new elements
        while (size_ < n) {
            new (data() + size_) T();
            ++size_;
        }
        
        // Destroy excess elements
        while (size_ > n) {
            --size_;
            data()[size_].~T();
        }
    }
    
    void push_back(const T& value) {
        if (size_ >= capacity_) {
            reserve(std::max(capacity_ * 2, size_t{16}));
        }
        new (data() + size_) T(value);
        ++size_;
    }
    
    void push_back(T&& value) {
        if (size_ >= capacity_) {
            reserve(std::max(capacity_ * 2, size_t{16}));
        }
        new (data() + size_) T(std::move(value));
        ++size_;
    }
    
    template<typename... Args>
    T& emplace_back(Args&&... args) {
        if (size_ >= capacity_) {
            reserve(std::max(capacity_ * 2, size_t{16}));
        }
        T* ptr = new (data() + size_) T(std::forward<Args>(args)...);
        ++size_;
        return *ptr;
    }
    
    void pop_back() {
        if (size_ > 0) {
            --size_;
            data()[size_].~T();
        }
    }
    
    void clear() {
        for (size_t i = 0; i < size_; ++i) {
            data()[i].~T();
        }
        size_ = 0;
    }
    
    T* data() noexcept { 
        return is_inline() ? inline_storage() : heap_; 
    }
    const T* data() const noexcept { 
        return is_inline() ? inline_storage() : heap_; 
    }
    
    T& operator[](size_t i) noexcept { return data()[i]; }
    const T& operator[](size_t i) const noexcept { return data()[i]; }
    
    T& front() noexcept { return data()[0]; }
    const T& front() const noexcept { return data()[0]; }
    
    T& back() noexcept { return data()[size_ - 1]; }
    const T& back() const noexcept { return data()[size_ - 1]; }
    
    T* begin() noexcept { return data(); }
    T* end() noexcept { return data() + size_; }
    const T* begin() const noexcept { return data(); }
    const T* end() const noexcept { return data() + size_; }
    
    size_t size() const noexcept { return size_; }
    size_t capacity() const noexcept { return capacity_; }
    bool empty() const noexcept { return size_ == 0; }
    
private:
    bool is_inline() const noexcept { return capacity_ <= InlineCapacity; }
    
    T* inline_storage() noexcept {
        return reinterpret_cast<T*>(&inline_);
    }
    const T* inline_storage() const noexcept {
        return reinterpret_cast<const T*>(&inline_);
    }
    
    size_t size_;
    size_t capacity_;
    T* heap_;
    alignas(T) char inline_[sizeof(T) * InlineCapacity];
};

// ============================================================================
// Flat Hash Set (for small sets with fast iteration)
// ============================================================================

/**
 * @brief Compact hash set with linear probing
 * 
 * Optimized for small sets with frequent iteration.
 * Uses Robin Hood hashing for cache-friendly probing.
 */
template<typename T, typename Hash = std::hash<T>>
class FlatHashSet {
    static constexpr float kMaxLoadFactor = 0.75f;
    static constexpr size_t kMinCapacity = 16;
    
    struct Slot {
        T value;
        uint8_t distance;  // Distance from ideal position (0 = empty)
    };
    
public:
    FlatHashSet() : slots_(nullptr), size_(0), capacity_(0) {}
    
    ~FlatHashSet() {
        clear();
        if (slots_) simd::aligned_free(slots_);
    }
    
    FlatHashSet(const FlatHashSet&) = delete;
    FlatHashSet& operator=(const FlatHashSet&) = delete;
    
    void reserve(size_t n) {
        size_t new_cap = std::max(kMinCapacity, 
            static_cast<size_t>(n / kMaxLoadFactor) + 1);
        // Round to power of 2 - use portable clz from simd.hpp
        new_cap = simd::next_power_of_2(new_cap);
        
        if (new_cap <= capacity_) return;
        rehash(new_cap);
    }
    
    bool insert(const T& value) {
        if (size_ + 1 > capacity_ * kMaxLoadFactor) {
            reserve(std::max(size_ + 1, capacity_ * 2));
        }
        
        return insert_impl(value);
    }
    
    bool contains(const T& value) const {
        if (capacity_ == 0) return false;
        
        size_t idx = Hash{}(value) & (capacity_ - 1);
        uint8_t dist = 1;
        
        while (slots_[idx].distance >= dist) {
            if (slots_[idx].value == value) {
                return true;
            }
            ++dist;
            idx = (idx + 1) & (capacity_ - 1);
        }
        
        return false;
    }
    
    void clear() {
        for (size_t i = 0; i < capacity_; ++i) {
            if (slots_[i].distance > 0) {
                slots_[i].value.~T();
                slots_[i].distance = 0;
            }
        }
        size_ = 0;
    }
    
    size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    
    // Iteration
    class iterator {
    public:
        iterator(Slot* slots, size_t idx, size_t cap) 
            : slots_(slots), idx_(idx), capacity_(cap) 
        {
            advance_to_valid();
        }
        
        T& operator*() { return slots_[idx_].value; }
        iterator& operator++() { ++idx_; advance_to_valid(); return *this; }
        bool operator!=(const iterator& other) const { return idx_ != other.idx_; }
        
    private:
        void advance_to_valid() {
            while (idx_ < capacity_ && slots_[idx_].distance == 0) {
                ++idx_;
            }
        }
        
        Slot* slots_;
        size_t idx_;
        size_t capacity_;
    };
    
    iterator begin() { return iterator(slots_, 0, capacity_); }
    iterator end() { return iterator(slots_, capacity_, capacity_); }
    
private:
    bool insert_impl(const T& value) {
        size_t idx = Hash{}(value) & (capacity_ - 1);
        uint8_t dist = 1;
        T current = value;
        
        while (slots_[idx].distance >= dist) {
            if (slots_[idx].value == current) {
                return false;  // Already exists
            }
            
            // Robin Hood: swap if current has traveled farther
            if (slots_[idx].distance < dist) {
                std::swap(current, slots_[idx].value);
                std::swap(dist, slots_[idx].distance);
            }
            
            ++dist;
            idx = (idx + 1) & (capacity_ - 1);
        }
        
        // Insert here
        new (&slots_[idx].value) T(std::move(current));
        slots_[idx].distance = dist;
        ++size_;
        return true;
    }
    
    void rehash(size_t new_cap) {
        Slot* old_slots = slots_;
        size_t old_cap = capacity_;
        
        // Use at least minimum alignment required by posix_memalign
        constexpr size_t align = alignof(Slot) > simd::kMinAlignment 
                                 ? alignof(Slot) : simd::kMinAlignment;
        
        slots_ = static_cast<Slot*>(
            simd::aligned_alloc(align, new_cap * sizeof(Slot)));
        if (!slots_) throw std::bad_alloc();
        
        std::memset(slots_, 0, new_cap * sizeof(Slot));
        capacity_ = new_cap;
        size_ = 0;
        
        if (old_slots) {
            for (size_t i = 0; i < old_cap; ++i) {
                if (old_slots[i].distance > 0) {
                    insert_impl(old_slots[i].value);
                    old_slots[i].value.~T();
                }
            }
            simd::aligned_free(old_slots);
        }
    }
    
    Slot* slots_;
    size_t size_;
    size_t capacity_;
};

} // namespace structor

#endif // STRUCTOR_OPTIMIZED_CONTAINERS_HPP
