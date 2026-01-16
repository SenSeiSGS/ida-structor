#pragma once

/// @file fwd.hpp
/// @brief Forward declarations for all Structor types
///
/// Include this header when you only need type declarations (for pointers/references).
/// This minimizes compile-time dependencies between modules.

// When testing, IDA types are provided by mock_ida.hpp
#ifndef STRUCTOR_TESTING
#include <pro.h>  // For ea_t, tid_t, etc.
#endif

#include <cstdint>
#include <memory>
#include <optional>

namespace structor {

// ============================================================================
// Core Types (core/)
// ============================================================================

// Access and semantic types
enum class AccessType : std::uint8_t;
enum class SemanticType : std::uint8_t;
enum class TypeConfidence : std::uint8_t;

// Basic structures
struct BitfieldInfo;
struct NestedAccessInfo;
struct FieldAccess;
struct AccessPattern;

// Synthesized structures
struct SynthField;
struct VTableSlot;
struct SynthVTable;
struct SynthStruct;
struct SubStructInfo;

// Results
enum class SynthError : std::uint8_t;
enum class Z3SynthesisStatus : std::uint8_t;
struct Z3SynthesisInfo;
struct AccessConflict;
struct SynthResult;

// Propagation
enum class PropagationDirection : std::uint8_t;
struct PropagationSite;
struct PropagationResult;

// Rewrite
struct RewriteTransform;
struct RewriteResult;

// Configuration
enum class Z3SynthesisMode : std::uint8_t;
struct Z3Options;
struct SynthOptions;
class Config;

// Utility structures
namespace utils {
    struct PtrArithInfo;
}

// ============================================================================
// Analysis Types (analysis/)
// ============================================================================

// Visitor classes
class AccessPatternVisitor;
class AccessCollector;

// VTable detection
class VTableDetector;

// Cross-function analysis
struct FunctionVariable;
struct FunctionVariableHash;
struct PointerFlowEdge;
struct CalleeCallInfo;
struct CallerCallInfo;
struct TypeEquivalenceClass;
struct UnifiedAccessPattern;
struct CrossFunctionConfig;
struct CrossFunctionStats;
class CrossFunctionAnalyzer;
class ArgDeltaExtractor;
class CallSiteFinder;
class CallerFinder;

// ============================================================================
// Synthesis Types (synthesis/)
// ============================================================================

// Layout synthesis
struct SynthesisResult;
struct LayoutSynthConfig;
class LayoutSynthesizer;

// Structure persistence
class StructurePersistence;

// Type propagation
class TypePropagator;

// Type fixing
enum class TypeDifference : std::uint8_t;
struct TypeComparison;
struct VariableTypeFix;
struct TypeFixResult;
struct TypeFixerConfig;
class TypeFixer;

// ============================================================================
// UI Types (ui/)
// ============================================================================

class PseudocodeRewriter;
class UIIntegration;

// ============================================================================
// Z3 Types (z3/)
// ============================================================================

namespace z3 {
    // Context
    struct Z3Config;
    class Z3Context;
    
    // Constraints
    struct ConstraintProvenance;
    class ConstraintTracker;
    
    // Field candidates
    struct FieldCandidate;
    struct CandidateGenerationConfig;
    class FieldCandidateGenerator;
    
    // Array constraints
    struct ArrayCandidate;
    class ArrayConstraintBuilder;
    
    // Layout constraints
    struct LayoutConstraintConfig;
    struct Z3Statistics;
    struct Z3Result;
    class LayoutConstraintBuilder;
    
    // Type encoding
    class TypeEncoder;
    
    // Type lattice
    class InferredType;
    class TypeLattice;
    
    // Type inference
    struct TypeConstraint;
    struct TypeInferenceConfig;
    struct FunctionTypeInferenceResult;
    class TypeInferenceEngine;
    
    // Type applicator
    struct TypeApplicationConfig;
    struct TypeApplicationResult;
    class TypeApplicator;
    
    // Alias analysis
    class AliasAnalysis;
    class SteensgaardAnalysis;
    class AndersenAnalysis;
}

// ============================================================================
// API Types (bindings/)
// ============================================================================

class StructorAPI;

} // namespace structor
