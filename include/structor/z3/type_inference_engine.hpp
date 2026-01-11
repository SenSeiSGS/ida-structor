#pragma once

#include <z3++.h>
#include "structor/z3/context.hpp"
#include "structor/z3/type_lattice.hpp"
#include "structor/z3/instruction_semantics.hpp"
#include "structor/z3/alias_analysis.hpp"
#include "structor/z3/layout_constraints.hpp"
#include "structor/synth_types.hpp"
#include "structor/cross_function_analyzer.hpp"

#ifndef STRUCTOR_TESTING
#include <hexrays.hpp>
#endif

#include <chrono>
#include <functional>

namespace structor::z3 {

/// Configuration for the type inference engine
struct TypeInferenceConfig {
    // Phase enables
    bool phase_constraint_extraction = true;
    bool phase_alias_analysis = true;
    bool phase_soft_constraints = true;
    bool phase_cross_function = true;
    bool phase_polymorphic_detection = false;  // Expensive, disabled by default
    
    // Constraint generation
    InstructionSemanticsConfig semantics_config;
    
    // Alias analysis
    AliasAnalysisConfig alias_config;
    
    // Solver configuration
    bool use_optimize = true;          // Use z3::optimize for soft constraints
    bool use_incremental = true;       // Use incremental solving
    unsigned solver_timeout_ms = 10000;
    unsigned max_relaxation_iterations = 10;
    
    // Type preference weights (for MaxSMT)
    int weight_signed_over_unsigned = 5;
    int weight_concrete_over_unknown = 10;
    int weight_pointer_for_mem_base = 15;
    int weight_from_signature = 20;
    int weight_from_decompiler = 10;
    
    // Output options
    bool generate_confidence_scores = true;
    bool propagate_to_decompiler = true;
};

/// Statistics from type inference
struct TypeInferenceStats {
    // Phase timings
    std::chrono::milliseconds constraint_extraction_time{0};
    std::chrono::milliseconds alias_analysis_time{0};
    std::chrono::milliseconds constraint_building_time{0};
    std::chrono::milliseconds solving_time{0};
    std::chrono::milliseconds total_time{0};
    
    // Counts
    unsigned functions_analyzed = 0;
    unsigned variables_typed = 0;
    unsigned type_constraints_hard = 0;
    unsigned type_constraints_soft = 0;
    unsigned constraints_relaxed = 0;
    unsigned alias_pairs_found = 0;
    
    // Results
    unsigned types_inferred = 0;
    unsigned types_pointer = 0;
    unsigned types_integer = 0;
    unsigned types_floating = 0;
    unsigned types_unknown = 0;
    
    // Solver iterations
    unsigned solve_iterations = 0;
    bool used_relaxation = false;
    
    [[nodiscard]] qstring summary() const;
};

/// Result of type inference for a single variable
struct InferredVariableType {
    int var_idx;
    qstring var_name;
    InferredType type;
    TypeConfidence confidence;
    
    // Provenance - where this type came from
    qvector<ea_t> source_constraints;
    bool from_signature = false;
    bool from_decompiler = false;
    bool from_alias = false;
    bool from_usage = false;
    
    InferredVariableType()
        : var_idx(-1)
        , confidence(TypeConfidence::Low) {}
};

/// Result of type inference for a function
struct FunctionTypeInferenceResult {
    ea_t func_ea = BADADDR;
    qstring func_name;
    
    // Inferred types for local variables
    qvector<InferredVariableType> local_types;
    
    // Inferred types for memory locations accessed
    std::unordered_map<std::size_t, InferredType> memory_types;  // hash -> type
    
    // Function signature inference
    std::optional<InferredType> return_type;
    qvector<InferredType> param_types;
    
    // Status
    bool success = false;
    qstring error_message;
    TypeInferenceStats stats;
    
    /// Get inferred type for a variable
    [[nodiscard]] std::optional<InferredType> get_var_type(int var_idx) const;
    
    /// Get inferred type for a memory location
    [[nodiscard]] std::optional<InferredType> get_mem_type(ea_t base, sval_t offset) const;
    
    /// Convert all inferred types to IDA tinfo_t
    [[nodiscard]] std::unordered_map<int, tinfo_t> to_ida_types() const;
};

/// Callback for progress reporting
using InferenceProgressCallback = std::function<void(
    const char* phase,
    int progress,      // 0-100
    const char* message
)>;

/// Main type inference engine
/// Orchestrates all phases of the type inference pipeline
class TypeInferenceEngine {
public:
    TypeInferenceEngine(
        Z3Context& ctx,
        const TypeInferenceConfig& config = {}
    );
    
    /// Infer types for all variables in a function
    [[nodiscard]] FunctionTypeInferenceResult infer_function(cfunc_t* cfunc);
    
    /// Infer types for a specific variable
    [[nodiscard]] InferredVariableType infer_variable(
        cfunc_t* cfunc,
        int var_idx
    );
    
    /// Infer types across multiple functions (inter-procedural)
    [[nodiscard]] std::vector<FunctionTypeInferenceResult> infer_cross_function(
        const qvector<cfunc_t*>& cfuncs
    );
    
    /// Set progress callback
    void set_progress_callback(InferenceProgressCallback callback) {
        progress_callback_ = std::move(callback);
    }
    
    /// Get configuration
    [[nodiscard]] const TypeInferenceConfig& config() const noexcept { return config_; }
    
    /// Modify configuration
    TypeInferenceConfig& config() noexcept { return config_; }
    
    /// Get statistics from last inference
    [[nodiscard]] const TypeInferenceStats& last_stats() const noexcept { return last_stats_; }

private:
    Z3Context& ctx_;
    TypeInferenceConfig config_;
    TypeInferenceStats last_stats_;
    InferenceProgressCallback progress_callback_;
    
    // Sub-analyzers
    std::unique_ptr<InstructionSemanticsExtractor> semantics_extractor_;
    std::unique_ptr<AliasAnalyzer> alias_analyzer_;
    std::unique_ptr<SignednessInferrer> signedness_inferrer_;
    std::unique_ptr<PointerIntegerDiscriminator> ptr_int_discriminator_;
    TypeLatticeEncoder type_encoder_;
    
    // Current analysis state
    cfunc_t* current_cfunc_ = nullptr;
    TypeConstraintSet current_constraints_;
    std::unordered_map<int, TypeVariable> var_to_type_var_;
    
    /// Phase 1: Extract type constraints from ctree
    void phase_constraint_extraction(cfunc_t* cfunc);
    
    /// Phase 2: Perform alias analysis
    void phase_alias_analysis(cfunc_t* cfunc);
    
    /// Phase 3: Generate soft constraints (heuristics)
    void phase_soft_constraints(cfunc_t* cfunc);
    
    /// Phase 4: Build Z3 constraints
    ::z3::optimize build_z3_constraints();
    
    /// Phase 5: Solve constraints
    bool phase_solve(::z3::optimize& opt, ::z3::model& out_model);
    
    /// Phase 6: Extract results from model
    void extract_results(
        const ::z3::model& model,
        FunctionTypeInferenceResult& result
    );
    
    /// Report progress
    void report_progress(const char* phase, int progress, const char* message);
    
    /// Initialize sub-analyzers
    void initialize_analyzers();
    
    /// Reset analysis state
    void reset_state();
    
    /// Get or create TypeVariable for a local variable
    [[nodiscard]] TypeVariable get_type_var(int var_idx);
    
    /// Add type preference soft constraints
    void add_type_preferences();
    
    /// Add calling convention constraints
    void add_calling_convention_constraints(cfunc_t* cfunc);
};

/// Type scheme for polymorphic functions
/// Represents universally quantified types: forall a. ptr(a) -> ptr(a) -> int -> ptr(a)
struct TypeScheme {
    struct TypeParam {
        int id;
        qstring name;
    };
    
    qvector<TypeParam> type_params;  // Universally quantified variables
    InferredType body;               // The actual type with type params as unknowns
    
    /// Check if this is a polymorphic (non-trivial) type scheme
    [[nodiscard]] bool is_polymorphic() const noexcept { return !type_params.empty(); }
    
    /// Instantiate the scheme with fresh type variables
    [[nodiscard]] std::pair<InferredType, std::unordered_map<int, TypeVariable>> 
    instantiate(int call_site_id, std::function<TypeVariable(int, const char*)> make_var) const;
};

/// Detects polymorphic functions (memcpy, qsort, etc.)
class PolymorphicFunctionDetector {
public:
    PolymorphicFunctionDetector(Z3Context& ctx);
    
    /// Check if a function is polymorphic based on its usage patterns
    [[nodiscard]] bool is_polymorphic(ea_t func_ea);
    
    /// Get the type scheme for a polymorphic function
    [[nodiscard]] std::optional<TypeScheme> get_type_scheme(ea_t func_ea);
    
    /// Register a known polymorphic function
    void register_polymorphic(ea_t func_ea, TypeScheme scheme);
    
    /// Common polymorphic functions
    void register_known_functions();

private:
    Z3Context& ctx_;
    std::unordered_map<ea_t, TypeScheme> known_schemes_;
    std::unordered_set<ea_t> known_polymorphic_;
};

/// Calling convention detector
class CallingConventionDetector {
public:
    enum class Convention {
        Unknown,
        CDecl,          // x86 cdecl
        Stdcall,        // x86 stdcall
        Fastcall,       // x86 fastcall
        Thiscall,       // x86 thiscall (C++ methods)
        SystemV_x64,    // System V AMD64 ABI (Linux/macOS)
        Microsoft_x64,  // Microsoft x64
        ARM_AAPCS,      // ARM AAPCS
        ARM64_AAPCS64   // ARM64 AAPCS64
    };
    
    CallingConventionDetector(Z3Context& ctx);
    
    /// Detect calling convention for a function
    [[nodiscard]] Convention detect(cfunc_t* cfunc);
    
    /// Get parameter types based on convention
    [[nodiscard]] qvector<InferredType> get_param_constraints(
        Convention conv,
        cfunc_t* cfunc
    );
    
    /// Get return type constraints based on convention
    [[nodiscard]] std::optional<InferredType> get_return_constraint(
        Convention conv,
        cfunc_t* cfunc
    );
    
    /// Get parameter register/stack mapping
    struct ParamLocation {
        bool is_register;
        qstring reg_name;      // If is_register
        sval_t stack_offset;   // If !is_register
    };
    [[nodiscard]] std::vector<ParamLocation> get_param_locations(
        Convention conv,
        const qvector<InferredType>& param_types
    );

private:
    Z3Context& ctx_;
    
    /// Heuristics to detect convention
    [[nodiscard]] Convention detect_from_prologue(cfunc_t* cfunc);
    [[nodiscard]] Convention detect_from_param_usage(cfunc_t* cfunc);
};

} // namespace structor::z3
