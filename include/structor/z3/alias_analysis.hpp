#pragma once

#include <z3++.h>
#include "structor/z3/type_lattice.hpp"
#include "structor/z3/instruction_semantics.hpp"
#include "structor/synth_types.hpp"

#ifndef STRUCTOR_TESTING
#include <hexrays.hpp>
#endif

#include <unordered_map>
#include <unordered_set>

namespace structor::z3 {

/// Represents an abstract memory location
struct AbstractLocation {
    enum class Kind {
        Stack,      // Local stack variable
        Heap,       // Heap allocation (malloc, new, etc.)
        Global,     // Global/static variable  
        Parameter,  // Function parameter (might alias with caller's memory)
        Unknown     // Unknown origin
    };
    
    Kind kind = Kind::Unknown;
    ea_t func_ea = BADADDR;           // Containing function (for stack/parameter)
    ea_t allocation_site = BADADDR;   // For heap allocations
    ea_t global_addr = BADADDR;       // For globals
    int var_idx = -1;                 // For stack/parameter
    
    // For structs/arrays: track field-sensitivity
    std::optional<sval_t> offset;     // Offset within the location
    std::optional<uint32_t> size;     // Size of the access
    
    AbstractLocation() = default;
    
    static AbstractLocation stack(ea_t func_ea, int var_idx);
    static AbstractLocation heap(ea_t alloc_site);
    static AbstractLocation global(ea_t addr);
    static AbstractLocation parameter(ea_t func_ea, int param_idx);
    static AbstractLocation unknown();
    
    /// Create a derived location at an offset
    [[nodiscard]] AbstractLocation at_offset(sval_t off, uint32_t sz) const;
    
    /// Check if two locations may alias
    [[nodiscard]] bool may_alias(const AbstractLocation& other) const;
    
    /// Check if two locations must alias
    [[nodiscard]] bool must_alias(const AbstractLocation& other) const;
    
    bool operator==(const AbstractLocation& other) const;
    bool operator!=(const AbstractLocation& other) const { return !(*this == other); }
    
    [[nodiscard]] std::size_t hash() const noexcept;
    [[nodiscard]] qstring to_string() const;
};

/// Hash for AbstractLocation
struct AbstractLocationHash {
    std::size_t operator()(const AbstractLocation& loc) const noexcept {
        return loc.hash();
    }
};

/// Union-Find data structure for Steensgaard-style alias analysis
class UnionFind {
public:
    /// Find the representative for an element
    [[nodiscard]] int find(int x);
    
    /// Union two elements
    void unite(int x, int y);
    
    /// Check if two elements are in the same set
    [[nodiscard]] bool same_set(int x, int y);
    
    /// Get all elements in the same set as x
    [[nodiscard]] std::vector<int> get_set(int x);
    
    /// Ensure element exists
    void ensure(int x);
    
    /// Get number of elements
    [[nodiscard]] std::size_t size() const noexcept { return parent_.size(); }

private:
    std::unordered_map<int, int> parent_;
    std::unordered_map<int, int> rank_;
};

/// Steensgaard-style alias analysis using unification
/// Fast (almost linear) but imprecise - may report spurious aliases
class SteensgaardAliasAnalyzer {
public:
    SteensgaardAliasAnalyzer(Z3Context& ctx);
    
    /// Analyze a function and build alias sets
    void analyze(cfunc_t* cfunc);
    
    /// Process an assignment: dst = src
    void process_assignment(int dst_id, int src_id);
    
    /// Process a load: dst = *ptr
    void process_load(int dst_id, int ptr_id);
    
    /// Process a store: *ptr = src
    void process_store(int ptr_id, int src_id);
    
    /// Process address-of: dst = &loc
    void process_address_of(int dst_id, int loc_id);
    
    /// Check if two variables may alias
    [[nodiscard]] bool may_alias(int var1_id, int var2_id);
    
    /// Get all variables that may alias with given variable
    [[nodiscard]] std::vector<int> get_alias_set(int var_id);
    
    /// Get or create ID for an abstract location
    [[nodiscard]] int get_location_id(const AbstractLocation& loc);
    
    /// Get abstract location for an ID
    [[nodiscard]] std::optional<AbstractLocation> get_location(int id) const;
    
    /// Generate type equality constraints for aliasing locations
    [[nodiscard]] qvector<TypeConstraint> generate_type_constraints(
        const std::unordered_map<int, TypeVariable>& var_types
    );

private:
    Z3Context& ctx_;
    UnionFind union_find_;
    
    // Location ID management
    int next_id_ = 0;
    std::unordered_map<AbstractLocation, int, AbstractLocationHash> loc_to_id_;
    std::unordered_map<int, AbstractLocation> id_to_loc_;
    
    // Deref (points-to) sets: deref_[x] is what x points to
    std::unordered_map<int, int> deref_;
    
    /// Get or create the "deref" node for a pointer
    [[nodiscard]] int get_deref_id(int ptr_id);
    
    /// Analyze an expression and return its location ID
    [[nodiscard]] int analyze_expr(cexpr_t* expr, cfunc_t* cfunc);
};

/// Andersen-style alias analysis using inclusion constraints
/// More precise than Steensgaard but O(n^3) in worst case
class AndersenAliasAnalyzer {
public:
    AndersenAliasAnalyzer(Z3Context& ctx);
    
    /// Analyze a function using inclusion-based constraints
    void analyze(cfunc_t* cfunc);
    
    /// Get the points-to set for a variable
    [[nodiscard]] std::unordered_set<int> get_points_to(int var_id);
    
    /// Check if ptr may point to loc
    [[nodiscard]] bool may_point_to(int ptr_id, int loc_id);
    
    /// Check if two pointers may alias (point to same location)
    [[nodiscard]] bool may_alias(int ptr1_id, int ptr2_id);
    
    /// Generate type constraints from alias analysis
    [[nodiscard]] qvector<TypeConstraint> generate_type_constraints(
        const std::unordered_map<int, TypeVariable>& var_types
    );

private:
    Z3Context& ctx_;
    
    // Points-to sets: pts[x] is the set of locations x may point to
    std::unordered_map<int, std::unordered_set<int>> points_to_;
    
    // Subset constraints: if p in pts[x] then pts[p] subset pts[*x]
    struct InclusionConstraint {
        int src;  // pts[src] subset pts[dst]
        int dst;
    };
    std::vector<InclusionConstraint> constraints_;
    
    // Worklist for fixed-point computation
    std::vector<int> worklist_;
    
    /// Solve constraints to fixed point
    void solve();
    
    /// Propagate new pointee to dependents
    void propagate(int var_id);
};

/// Configuration for alias analysis
struct AliasAnalysisConfig {
    enum class Algorithm {
        Steensgaard,  // Fast unification-based
        Andersen,     // Precise inclusion-based
        FieldSensitive // Andersen + field sensitivity
    };
    
    Algorithm algorithm = Algorithm::Steensgaard;
    bool field_sensitive = true;       // Track struct fields separately
    bool context_sensitive = false;    // Distinguish call sites (expensive)
    int max_iterations = 1000;         // For fixed-point computation
};

/// Unified alias analyzer interface
class AliasAnalyzer {
public:
    AliasAnalyzer(Z3Context& ctx, const AliasAnalysisConfig& config = {});
    
    /// Analyze a function
    void analyze(cfunc_t* cfunc);
    
    /// Clear analysis state
    void reset();
    
    /// Check if two expressions may alias
    [[nodiscard]] bool may_alias(cexpr_t* e1, cexpr_t* e2, cfunc_t* cfunc);
    
    /// Generate type constraints from alias information
    [[nodiscard]] qvector<TypeConstraint> generate_type_constraints(
        const std::unordered_map<int, TypeVariable>& var_types
    );
    
    /// Get configuration
    [[nodiscard]] const AliasAnalysisConfig& config() const noexcept { return config_; }

private:
    Z3Context& ctx_;
    AliasAnalysisConfig config_;
    
    std::unique_ptr<SteensgaardAliasAnalyzer> steensgaard_;
    std::unique_ptr<AndersenAliasAnalyzer> andersen_;
    
    // Current function being analyzed
    cfunc_t* current_cfunc_ = nullptr;
};

} // namespace structor::z3
