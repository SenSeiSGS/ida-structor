<h1 align="center">structor</h1>

<h5 align="center">
Structor is a Hex-Rays plugin that synthesizes C structures from raw pointer arithmetic.<br/>
Where IDA shows <code>*(int*)((char*)ptr + 8)</code>, Structor reveals <code>ptr->field_8</code>.<br/>
Access patterns analyzed. Types inferred. Layouts reconstructed automatically.<br/>
<br/>
VTables detected. Fields aligned. Padding inserted where needed.<br/>
Types propagate through callers and callees alike.<br/>
The arithmetic fades. The structure emerges.
</h5>

<br />

**Automatic C Structure Synthesis for Hex-Rays Decompiler**

Structor is an IDA Pro plugin that automatically synthesizes C structure definitions from pointer arithmetic access patterns. It transforms unreadable pointer arithmetic like `*(int*)((char*)ptr + 8)` into clean, typed member accesses like `ptr->field_8`.

---

## Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Interactive Mode](#interactive-mode)
  - [Scripted Mode](#scripted-mode)
  - [Programmatic API](#programmatic-api)
- [How It Works](#how-it-works)
  - [Synthesis Pipeline](#synthesis-pipeline)
  - [Z3 Constraint-Based Synthesis](#z3-constraint-based-synthesis)
  - [Type Inference System](#type-inference-system)
  - [Cross-Function Analysis](#cross-function-analysis)
  - [Array Detection](#array-detection)
  - [Union Handling](#union-handling)
  - [Fallback Strategies](#fallback-strategies)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Building from Source](#building-from-source)
- [Testing](#testing)
- [Architecture](#architecture)
- [Relationship to Suture](#relationship-to-suture)
- [Known Limitations](#known-limitations)
- [License](#license)

---

## Overview

When reverse engineering compiled binaries, type information is lost. Variables that were once well-typed structures become opaque `void*` pointers with manual pointer arithmetic to access fields. Structor analyzes these access patterns in the Hex-Rays decompiler output and automatically reconstructs the original structure layout.

### Before Structor

```c
void process_object(void* ptr) {
    int type = *(int*)ptr;
    void* data = *(void**)((char*)ptr + 8);
    void (*callback)() = *(void(**)())((char*)ptr + 0x10);

    if (type == 1) {
        callback();
    }
}
```

### After Structor

```c
struct synth_process_object_0 {
    int field_0;
    int _pad_4;
    void* field_8;
    void (*field_10)();
};

void process_object(synth_process_object_0* ptr) {
    int type = ptr->field_0;
    void* data = ptr->field_8;
    void (*callback)() = ptr->field_10;

    if (type == 1) {
        callback();
    }
}
```

---

## Problem Statement

Reverse engineering structures manually is tedious and error-prone:

1. **Scattered Access Patterns**: Structure fields are accessed across multiple functions, making it difficult to see the complete picture
2. **Type Information is Lost**: Compilers discard type information; you must infer types from usage patterns
3. **Pointer Arithmetic is Hard to Read**: Expressions like `*(void**)((char*)obj + 0x10)` require mental effort to interpret
4. **VTables are Complex**: C++ virtual function tables involve multiple levels of pointer indirection
5. **Field Overlaps and Alignment**: Handling unions, padding, and alignment manually is tedious

Structor automates this entire process by analyzing how pointers are dereferenced and synthesizing matching structure definitions using a Z3-based constraint solver with advanced type inference.

---

## Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **Z3-Based Constraint Synthesis** | Uses the Z3 SMT solver with Max-SMT optimization for optimal field layout |
| **Type Inference Engine** | Full type lattice with subtyping, LUB/GLB, and constraint-based inference |
| **Alias Analysis** | Steensgaard (fast) and Andersen (precise) algorithms for pointer tracking |
| **Cross-Function Analysis** | Traces type flow across function boundaries with pointer delta tracking |
| **Automatic Array Detection** | Recognizes arithmetic progressions and synthesizes array fields |
| **Union Type Creation** | Handles overlapping accesses by creating C union types |
| **VTable Detection** | Recognizes C++ vtable access patterns and synthesizes vtable structures |
| **Type Propagation** | Propagates synthesized types to callers and callees across the call graph |
| **Tiered Fallback** | Falls back gracefully from Z3 to heuristics when constraints fail |
| **Predicate Filtering** | Allows filtering accesses before synthesis (e.g., only function pointers) |

### Type Inference Features

| Feature | Description |
|---------|-------------|
| **Recursive Type System** | Supports base types, pointers, functions, arrays, structs, and sum types |
| **Signedness Inference** | Detects signed vs unsigned from comparison patterns (`slt` vs `ult`) |
| **Pointer/Integer Discrimination** | Soft constraints distinguish pointers from integers of same size |
| **Polymorphic Function Detection** | Recognizes `memcpy`, `qsort`, and similar patterns |
| **Calling Convention Detection** | Infers calling conventions from register usage patterns |
| **Bitvector Type Encoding** | Fast 32-bit bitvector encoding for improved solver performance |

### User Interface

- **Hotkey**: Press `Shift+S` to synthesize structure for selected variable
- **Context Menu**: Right-click on variable → "Synthesize Structure"
- **Automatic View Refresh**: Pseudocode updates immediately after synthesis
- **Visual Feedback**: Highlights transformed expressions

### Automation

- **IDC Functions**: Scriptable via IDA's IDC API for batch processing
- **Python Integration**: Full Python scripting support via `ida_expr`
- **C++ API**: Direct programmatic access for plugin development

---

## Requirements

- **IDA Pro 8.0+** with a valid license
- **Hex-Rays Decompiler** (x86/x64/ARM)
- **Operating System**: Windows, macOS (Intel/Apple Silicon), or Linux
- **Z3 Theorem Prover 4.8+**: Bundled with the plugin or system-installed

---

## Installation

### From Pre-built Binary

1. Download the appropriate plugin binary for your platform:
   - Windows: `structor64.dll`
   - macOS: `structor64.dylib`
   - Linux: `structor64.so`

2. Copy to your IDA plugins directory:
   ```bash
   # macOS/Linux
   cp structor64.dylib ~/.idapro/plugins/

   # Windows
   copy structor64.dll "%APPDATA%\Hex-Rays\IDA Pro\plugins\"
   ```

3. On macOS, code-sign the plugin:
   ```bash
   codesign -s - -f ~/.idapro/plugins/structor64.dylib
   ```

4. Restart IDA Pro. The plugin loads automatically.

### From Source

See [Building from Source](#building-from-source) below.

---

## Usage

### Interactive Mode

1. Open a function containing pointer arithmetic in IDA Pro
2. Press `F5` to open the Hex-Rays pseudocode view
3. Click on a `void*` or untyped pointer variable
4. Press `Shift+S` or right-click → **"Synthesize Structure"**

The plugin will:
- Analyze all dereferences of the selected variable
- Extract type constraints from instruction semantics
- Run alias analysis to track pointer relationships
- Trace type flow across function boundaries (if cross-function analysis is enabled)
- Use Z3 to find the optimal field layout satisfying all constraints
- Infer precise field types using the type lattice
- Create a structure with fields at the detected offsets
- Detect and create array fields where applicable
- Apply the structure type to the variable
- Refresh the decompiler view with the new types

### Scripted Mode

Structor exposes IDC functions for batch processing and automation:

```python
import ida_expr
import idc

# Synthesize structure by variable index
result = ida_expr.idc_value_t()
ida_expr.eval_idc_expr(result, idc.BADADDR, "structor_synthesize(0x100000460, 0)")
struct_tid = result.i64

if struct_tid != idc.BADADDR:
    print(f"Created structure with TID: {struct_tid:#x}")

    # Get field count
    ida_expr.eval_idc_expr(result, idc.BADADDR, "structor_get_field_count()")
    print(f"Field count: {result.num}")

    # Check for vtable
    ida_expr.eval_idc_expr(result, idc.BADADDR, "structor_get_vtable_tid()")
    if result.i64 != idc.BADADDR:
        print(f"VTable TID: {result.i64:#x}")
else:
    # Get error message
    ida_expr.eval_idc_expr(result, idc.BADADDR, "structor_get_error()")
    print(f"Error: {result.c_str()}")
```

#### Synthesize by Variable Name

```python
# Find variable by name instead of index
ida_expr.eval_idc_expr(result, idc.BADADDR,
    'structor_synthesize_by_name(0x100000460, "ptr")')
```

### Programmatic API

For C++ plugin development:

```cpp
#include <structor/api.hpp>

// Synthesize with custom options
structor::SynthOptions opts;
opts.min_accesses = 3;
opts.vtable_detection = true;
opts.access_filter = structor::predicates::exclude_vtable;

// Enable Z3 synthesis with cross-function analysis
opts.z3.mode = structor::Z3SynthesisMode::Preferred;
opts.z3.cross_function = true;
opts.z3.detect_arrays = true;

// Enable type inference
opts.use_type_inference = true;
opts.apply_inferred_types = true;

structor::SynthResult result =
    structor::StructorAPI::instance().synthesize_structure(
        func_ea, var_idx, &opts);

if (result.success()) {
    msg("Created %s with %d fields\n",
        result.synthesized_struct->name.c_str(),
        result.fields_created);

    // Check Z3 synthesis details
    if (result.z3_info.used_z3()) {
        msg("Z3 solve time: %ums\n", result.z3_info.solve_time_ms);
        msg("Arrays detected: %u\n", result.z3_info.arrays_detected);
    }

    if (result.vtable_struct) {
        msg("VTable: %s with %zu slots\n",
            result.vtable_struct->name.c_str(),
            result.vtable_struct->slots.size());
    }
}
```

---

## How It Works

### Synthesis Pipeline

Structor operates as a multi-stage pipeline with Z3-based constraint solving and type inference at its core:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Structor Synthesis Pipeline                         │
└─────────────────────────────────────────────────────────────────────────────┘

   ┌──────────────┐    ┌──────────────────┐    ┌─────────────────────────┐
   │   Hex-Rays   │───▶│ AccessCollector  │───▶│ CrossFunctionAnalyzer   │
   │   Decompiler │    │ (ctree visitor)  │    │ (type equivalence class)│
   └──────────────┘    └──────────────────┘    └─────────────────────────┘
                                                           │
         ┌─────────────────────────────────────────────────┘
         ▼
   ┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────┐
   │ InstructionSemantics│───▶│   AliasAnalyzer     │───▶│ TypeInference   │
   │   Extractor         │    │ (Steensgaard/       │    │    Engine       │
   │ (type constraints)  │    │  Andersen)          │    │ (7-phase solve) │
   └─────────────────────┘    └─────────────────────┘    └─────────────────┘
                                                                │
         ┌──────────────────────────────────────────────────────┘
         ▼
   ┌────────────────────┐    ┌─────────────────────┐    ┌─────────────────┐
   │FieldCandidateGen   │───▶│ Z3 LayoutConstraint │───▶│   Max-SMT       │
   │ (generate options) │    │  Builder (encode)   │    │   Solver        │
   └────────────────────┘    └─────────────────────┘    └─────────────────┘
                                                               │
         ┌─────────────────────────────────────────────────────┘
         ▼
   ┌──────────────────┐    ┌────────────────────┐    ┌───────────────┐
   │ VTableDetector   │───▶│StructurePersistence│───▶│TypePropagator │
   │ (vtable patterns)│    │  (creates in IDB)  │    │(caller/callee)│
   └──────────────────┘    └────────────────────┘    └───────────────┘
                                                            │
         ┌──────────────────────────────────────────────────┘
         ▼
   ┌───────────────────┐    ┌───────────────────┐
   │  TypeApplicator   │───▶│PseudocodeRewriter │
   │ (apply to IDA)    │    │  (refreshes view) │
   └───────────────────┘    └───────────────────┘
```

### Stage 1: Access Collection

The `AccessCollector` walks the Hex-Rays control tree (ctree) looking for dereference patterns on the target variable:

```c
// Detected pattern: *(type*)((char*)base + offset)
*(int*)ptr           → FieldAccess(offset=0, size=4, type=Read)
*(long*)((char*)ptr + 8)  → FieldAccess(offset=8, size=8, type=Read)
*((void**)ptr + 2)   → FieldAccess(offset=16, size=8, type=Read)
```

### Z3 Constraint-Based Synthesis

Structor uses the Z3 SMT solver for optimal structure layout synthesis. This approach treats field placement as a constraint satisfaction problem:

#### Constraint Types

| Constraint Type | Classification | Description |
|-----------------|----------------|-------------|
| **Coverage** | Hard | Every observed access must be covered by a selected field |
| **Non-Overlap** | Soft | Fields should not overlap (unless forming a union) |
| **Alignment** | Soft | Fields should respect natural alignment |
| **Type Consistency** | Soft | Field types should match observed access patterns |
| **Size Bounds** | Hard | Structure must fit within max size limits |

#### Max-SMT Optimization

Z3 uses Max-SMT (Maximum Satisfiability Modulo Theories) to:
1. Satisfy all **hard constraints** (coverage, bounds)
2. Maximize satisfaction of **soft constraints** with configurable weights
3. Find the globally optimal field layout, not just a valid one

```cpp
// Optimization weights (configurable)
weight_coverage = 100;           // Hard: every access must be covered
weight_type_consistency = 10;    // Soft: prefer consistent types
weight_alignment = 5;            // Soft: prefer aligned fields
weight_minimize_fields = 2;      // Soft: prefer fewer fields
weight_minimize_padding = 1;     // Soft: prefer compact layout
weight_prefer_arrays = 3;        // Soft: prefer array detection
```

### Type Inference System

Structor includes a comprehensive type inference system that goes beyond simple size-based field typing. The system uses a formal type lattice with constraint-based solving to infer precise types.

#### Type Lattice

The type system is built on a recursive `InferredType` representation:

```cpp
enum class Kind {
    Base,       // Scalar base type (int8, int32, float, etc.)
    Pointer,    // Pointer to another type
    Function,   // Function type (return + params)
    Array,      // Array type (element + count)
    Struct,     // Structure type (tid-based)
    Sum         // Sum type for unions (multiple alternatives)
};
```

The `TypeLattice` class implements subtyping relationships with lattice operations:

| Operation | Description |
|-----------|-------------|
| `is_subtype(a, b)` | Check if type `a` is a subtype of `b` |
| `lub(a, b)` | Least upper bound (join) - most general common supertype |
| `glb(a, b)` | Greatest lower bound (meet) - most specific common subtype |
| `are_compatible(a, b)` | Check if types can coexist at same location |
| `widen_to_size(t, n)` | Widen type to target byte size |

**Subtyping Rules:**
- `int8 <: int16 <: int32 <: int64` (signed widening)
- `uint8 <: uint16 <: uint32 <: uint64` (unsigned widening)
- `Bottom <: T <: Unknown` for all types T
- Pointer subtyping is covariant in pointee type
- Function subtyping is contravariant in parameters, covariant in return

#### Type Constraint Extraction

The `InstructionSemanticsExtractor` walks the Hex-Rays ctree to extract type constraints:

| Instruction Pattern | Generated Constraint |
|--------------------|---------------------|
| `x = y` | `TypeConstraint::Equal(type(x), type(y))` |
| `x < y` (signed) | `TypeConstraint::IsSigned(type(x))`, `TypeConstraint::IsSigned(type(y))` |
| `x < y` (unsigned) | `TypeConstraint::IsUnsigned(type(x))`, `TypeConstraint::IsUnsigned(type(y))` |
| `*p` | `TypeConstraint::IsPointer(type(p))` |
| `p + n` | `TypeConstraint::IsPointer(type(p))` or `TypeConstraint::IsInteger(type(p))` |
| `(T)x` | `TypeConstraint::Cast(type(x), T)` |
| `f(a, b)` | Constraints from function signature |
| `p->field` | `TypeConstraint::HasField(type(p), offset, field_type)` |
| `arr[i]` | `TypeConstraint::IsArray(type(arr))` |

#### Alias Analysis

Two alias analysis algorithms are available for tracking pointer relationships:

**Steensgaard's Algorithm** (fast, O(n·α(n))):
- Unification-based analysis
- May-alias approximation
- Best for large functions

**Andersen's Algorithm** (precise, O(n³)):
- Inclusion-based analysis  
- Flow-insensitive but more precise
- Better for complex pointer patterns

```cpp
// Configure alias analysis
opts.alias_analysis.algorithm = AliasAlgorithm::Steensgaard;  // or Andersen
opts.alias_analysis.max_iterations = 1000;
opts.alias_analysis.track_fields = true;
```

#### Type Inference Engine

The `TypeInferenceEngine` orchestrates a 7-phase inference pipeline:

1. **Constraint Extraction**: Walk ctree, extract type constraints from operations
2. **Alias Analysis**: Run Steensgaard or Andersen to find pointer equivalences
3. **Constraint Augmentation**: Add alias-derived equality constraints
4. **Soft Constraint Generation**: Add heuristic constraints (pointer vs int discrimination)
5. **Z3 Encoding**: Encode constraints into Z3 expressions with weights
6. **Max-SMT Solving**: Solve for optimal type assignment
7. **Model Extraction**: Extract inferred types from Z3 model

```cpp
// Type inference configuration
struct TypeInferenceConfig {
    bool enable_signedness_inference = true;
    bool enable_pointer_discrimination = true;
    bool enable_polymorphic_detection = true;
    bool enable_calling_convention_detection = true;
    
    AliasAlgorithm alias_algorithm = AliasAlgorithm::Steensgaard;
    
    uint32_t min_confidence = 50;  // Minimum confidence threshold (0-100)
    uint32_t z3_timeout_ms = 5000;
    
    // Soft constraint weights for pointer vs integer heuristics
    uint32_t weight_pointer_alignment = 10;
    uint32_t weight_small_constant_is_int = 5;
    uint32_t weight_arithmetic_result_is_int = 8;
};
```

#### Type Encodings for Z3

Two encoding strategies are available:

**Integer Encoding** (default):
- Types encoded as integers with bit-packed fields
- Bits 0-7: Type kind tag
- Bits 8-15: Base type enum value
- Bits 16-23: Pointer depth / array count
- Uses arithmetic operations (mod, div) for constraints

**Bitvector Encoding** (faster):
- Types encoded as 32-bit bitvectors
- Native bitwise operations
- Better solver performance for large constraint sets

```cpp
// Encoding scheme for BitvectorTypeEncoder
// Bits 0-5:   Base type tag (0-63)
// Bits 6-13:  Size in bytes (0-255)  
// Bit  14:    Is pointer flag
// Bit  15:    Is signed flag
// Bits 16-23: Pointer depth (0-255)
// Bits 24-31: Reserved
```

#### Type Application

The `TypeApplicator` applies inferred types back to IDA:

```cpp
TypeApplicationConfig config;
config.min_confidence = 50;           // Only apply types with >= 50% confidence
config.overwrite_existing = false;    // Don't replace existing typed variables
config.propagate_to_callers = true;   // Update caller functions
config.propagate_to_callees = true;   // Update callee functions

TypeApplicator applicator(config);
auto result = applicator.apply(cfunc, inference_result);

msg("Applied %u types, failed %u, skipped %u\n",
    result.types_applied, result.types_failed, result.types_skipped);
```

### Cross-Function Analysis

Structor traces type flow across function boundaries to build complete structure definitions:

```
┌─────────────────┐    pass ptr    ┌─────────────────┐
│   caller()      │───────────────▶│   callee(ptr)   │
│  ptr->field_0   │                │  ptr->field_8   │
│  ptr->field_10  │                │  ptr->field_20  │
└─────────────────┘                └─────────────────┘
         │                                  │
         └──────────┬───────────────────────┘
                    ▼
        ┌─────────────────────────┐
        │  Unified Access Pattern │
        │  fields: 0, 8, 10, 20   │
        └─────────────────────────┘
```

#### Pointer Delta Tracking

When pointers are passed with adjustments (e.g., `callee(ptr + 0x10)`), Structor tracks these deltas to correctly align field offsets:

```c
void caller(void* ptr) {
    *(int*)ptr = 1;                    // offset 0
    callee((char*)ptr + 0x10);         // pass ptr+0x10
}

void callee(void* adjusted_ptr) {
    *(int*)adjusted_ptr = 2;           // offset 0 in callee = offset 0x10 in caller
    *(int*)((char*)adjusted_ptr + 8);  // offset 8 in callee = offset 0x18 in caller
}
```

The cross-function analyzer detects the delta (0x10) and normalizes all offsets to the canonical base.

#### Type Equivalence Classes

Variables across functions that share the same underlying type are grouped into equivalence classes:

```cpp
struct TypeEquivalenceClass {
    qvector<FunctionVariable> variables;   // Variables in this class
    qvector<AccessPattern> patterns;       // Access patterns per function
    qvector<PointerFlowEdge> flow_edges;   // How pointers flow between functions
};
```

### Array Detection

Structor automatically detects array access patterns using arithmetic progression analysis:

```c
// These accesses at offsets 0x10, 0x18, 0x20, 0x28 with size 8
// are detected as: arr_10[4] with stride 8
*(long*)((char*)ptr + 0x10);
*(long*)((char*)ptr + 0x18);
*(long*)((char*)ptr + 0x20);
*(long*)((char*)ptr + 0x28);
```

#### Detection Algorithm

1. **Group by size**: Accesses with the same size are grouped
2. **Find arithmetic progression**: Check if offsets form `base + i * stride`
3. **Z3 symbolic detection**: For complex cases, use Z3 to solve for stride
4. **Struct-of-arrays handling**: When stride > access_size, create element struct

```cpp
struct ArrayCandidate {
    sval_t base_offset;           // Starting offset of array
    uint32_t stride;              // Bytes between elements
    uint32_t element_count;       // Number of elements
    tinfo_t element_type;         // Type of each element
    bool needs_element_struct;    // For stride > access_size cases
};
```

### Union Handling

When conflicting accesses occur at the same offset, Structor creates union types:

```c
// Two accesses at offset 0x10 with different sizes
*(int*)((char*)ptr + 0x10);    // 4-byte access
*(long*)((char*)ptr + 0x10);   // 8-byte access

// Results in union field:
union {
    int as_int;
    long as_long;
} field_10;
```

The type inference system represents these as `InferredType::Sum` types.

### Fallback Strategies

Structor employs a tiered fallback system:

1. **Z3 Max-SMT**: Primary solver with full optimization
2. **Z3 with Relaxation**: Drop soft constraints iteratively on UNSAT
3. **Raw Bytes Fallback**: Create `uint8_t[]` for irreconcilable regions
4. **Heuristic Synthesis**: Traditional grouping-based approach

```cpp
// Fallback configuration
bool relax_alignment_on_unsat = true;
bool relax_types_on_unsat = true;
bool use_raw_bytes_fallback = true;
bool fallback_to_heuristics = true;
```

---

## Configuration

Structor saves its configuration to `~/.idapro/structor.cfg`:

```ini
# Structor Configuration

[General]
hotkey=Shift+S              # Keyboard shortcut
interactive_mode=false      # Prompt before applying changes
auto_open_struct=true       # Open structure editor after synthesis
debug_mode=false            # Enable debug logging

[Synthesis]
min_accesses=2              # Minimum access count to trigger synthesis
alignment=8                 # Default structure alignment
vtable_detection=true       # Enable vtable pattern detection

[Propagation]
auto_propagate=true         # Automatically propagate to related functions
propagate_to_callers=true   # Backward propagation
propagate_to_callees=true   # Forward propagation
max_propagation_depth=3     # Maximum recursion depth

[UI]
highlight_changes=true      # Highlight transformed expressions
highlight_duration_ms=2000  # Duration of highlight in milliseconds
generate_comments=true      # Add comments to synthesized fields

[Z3]
z3_mode=preferred           # Z3 mode: disabled, preferred, required
z3_timeout_ms=5000          # Z3 solver timeout in milliseconds
z3_memory_limit_mb=256      # Z3 memory limit in megabytes
z3_enable_maxsmt=true       # Use Max-SMT optimization
z3_enable_unsat_core=true   # Extract UNSAT core for debugging
z3_detect_arrays=true       # Enable array detection via Z3
z3_min_array_elements=3     # Minimum elements to consider as array
z3_cross_function=true      # Enable cross-function analysis
z3_max_candidates=1000      # Maximum field candidates to consider
z3_allow_unions=true        # Allow union type creation for conflicts
z3_min_confidence=20        # Minimum confidence threshold (0-100)
z3_relax_on_unsat=true      # Relax constraints if UNSAT
z3_max_relax_iterations=5   # Maximum relaxation iterations

[TypeInference]
enable_type_inference=true          # Enable advanced type inference
apply_inferred_types=true           # Apply inferred types to IDA
enable_signedness_inference=true    # Infer signed vs unsigned
enable_pointer_discrimination=true  # Distinguish pointers from integers
enable_polymorphic_detection=true   # Detect polymorphic functions
alias_algorithm=steensgaard         # Alias analysis: steensgaard or andersen
type_encoding=integer               # Type encoding: integer or bitvector
min_type_confidence=50              # Minimum confidence for type application
```

The config file is created automatically with defaults on first run if it doesn't exist.

### Z3 Synthesis Modes

| Mode | Description |
|------|-------------|
| `disabled` | Use heuristic-only synthesis (original behavior) |
| `preferred` | Try Z3 first, fall back to heuristics on failure |
| `required` | Z3 only, fail if Z3 fails |

### Alias Analysis Algorithms

| Algorithm | Complexity | Precision | Use Case |
|-----------|------------|-----------|----------|
| `steensgaard` | O(n·α(n)) | Lower | Large functions, quick analysis |
| `andersen` | O(n³) | Higher | Complex pointer patterns, precise results |

### Predicate-Based Filtering

Filter accesses before synthesis using built-in predicates:

```cpp
// Only synthesize function pointer fields
opts.access_filter = structor::predicates::funcptr_only;

// Only pointer-type fields
opts.access_filter = structor::predicates::pointer_only;

// Exclude vtable accesses
opts.access_filter = structor::predicates::exclude_vtable;

// Only positive offsets (exclude negative indexing)
opts.access_filter = structor::predicates::positive_offsets_only;

// Access size range
opts.access_filter = structor::predicates::size_range(4, 8);

// Offset range
opts.access_filter = structor::predicates::offset_range(0, 0x100);

// Combine predicates
opts.access_filter = structor::predicates::all_of({
    structor::predicates::positive_offsets_only,
    structor::predicates::size_range(4, 8)
});
```

---

## API Reference

### IDC Functions

| Function | Parameters | Returns | Description |
|----------|------------|---------|-------------|
| `structor_synthesize` | `(func_ea, var_idx)` | `tid_t` | Synthesize structure by variable index |
| `structor_synthesize_by_name` | `(func_ea, var_name)` | `tid_t` | Synthesize structure by variable name |
| `structor_get_error` | `()` | `string` | Get last error message |
| `structor_get_field_count` | `()` | `long` | Get field count from last synthesis |
| `structor_get_vtable_tid` | `()` | `tid_t` | Get vtable TID from last synthesis |

### Return Values

- **Success**: Returns the structure type ID (`tid_t`)
- **Failure**: Returns `BADADDR` (use `structor_get_error()` for details)

### Error Messages

| Error | Meaning |
|-------|---------|
| "Failed to decompile function" | Hex-Rays couldn't decompile the function |
| "Variable index out of range" | Invalid `var_idx` parameter |
| "Variable 'X' not found in function" | Invalid `var_name` parameter |
| "No dereferences found for variable" | Variable isn't dereferenced in the function |
| "Only N accesses found (minimum: 2)" | Not enough field accesses detected |
| "Failed to create struct type" | IDA type system error |
| "Z3 solver timed out" | Z3 exceeded configured timeout |
| "Z3 constraints unsatisfiable" | No valid layout satisfies all hard constraints |
| "Type inference failed" | Type inference engine couldn't solve constraints |

---

## Building from Source

### Prerequisites

- **CMake 3.20+**
- **C++20 compatible compiler** (Clang 13+, GCC 11+, MSVC 2019+)
- **IDA SDK 8.0+**
- **Z3 Theorem Prover 4.8+** (headers and library)

### Environment Setup

Set the IDA SDK path:

```bash
# Option 1: Environment variable
export IDA_SDK_DIR=/path/to/idasdk

# Option 2: Alternative name
export IDASDK=/path/to/idasdk
```

Optionally set IDA installation path for direct install:

```bash
export IDA_INSTALL_DIR=/path/to/ida
```

### Build Commands

Using the Makefile (recommended):

```bash
# Build the plugin
make

# Build with debug symbols
make debug

# Install to ~/.idapro/plugins
make install

# Clean build directory
make clean

# Full rebuild
make rebuild
```

Using CMake directly:

```bash
mkdir build && cd build
cmake -DIDA_SDK_DIR=/path/to/idasdk \
      -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

### Build Options

| CMake Option | Default | Description |
|--------------|---------|-------------|
| `IDA_SDK_DIR` | *required* | Path to IDA SDK directory |
| `IDA_INSTALL_DIR` | - | Path to IDA installation (for install target) |
| `IDA_EA64` | `ON` | Build for 64-bit IDA (`ida64`) |
| `BUILD_TESTS` | `OFF` | Build unit tests |
| `Z3_USE_SYSTEM` | `ON` | Use system-installed Z3 |
| `CMAKE_BUILD_TYPE` | `Release` | Build type (`Release`/`Debug`) |

### Platform-Specific Output

| Platform | Output File |
|----------|-------------|
| macOS | `structor64.dylib` |
| Linux | `structor64.so` |
| Windows | `structor64.dll` |

---

## Testing

### Unit Tests

Build and run unit tests:

```bash
mkdir build && cd build
cmake -DIDA_SDK_DIR=/path/to/idasdk -DBUILD_TESTS=ON ..
make
ctest --output-on-failure
```

### Test Coverage

| Test Suite | Description |
|------------|-------------|
| `test_z3_context` | Z3 context creation and configuration |
| `test_z3_type_encoding` | IDA type to Z3 type encoding |
| `test_z3_layout_constraints` | Constraint building and solving |
| `test_z3_array_detection` | Arithmetic progression and array synthesis |
| `test_z3_cross_function` | Cross-function analysis and delta tracking |
| `test_z3_synthesis_integration` | Z3 synthesis integration scenarios |
| `test_e2e_synthesis` | End-to-end synthesis scenarios |
| `test_type_lattice` | Type lattice operations (31 sub-tests) |

The `test_type_lattice` suite covers:
- Base type utilities (names, sizes, classification)
- `InferredType` construction (base, pointer, function, array, struct, sum)
- Pointer depth tracking
- Type equality and hashing
- `TypeLattice` subtyping relations
- LUB/GLB operations
- `TypeLatticeEncoder` Z3 integration
- `BitvectorTypeEncoder` encode/decode

### Integration Tests

The `integration_tests/` directory contains Python scripts and C/C++ source files for testing various patterns:

| Test | Description |
|------|-------------|
| `test_simple_struct.c` | Basic 3-field structure |
| `test_vtable.cpp` | C++ vtable patterns |
| `test_nested.c` | Nested structures and arrays |
| `test_linked_list.c` | Self-referential linked list nodes |
| `test_function_ptr.c` | Function pointer callbacks |
| `test_cross_function.py` | Cross-function analysis verification |
| `test_substructure_xfunc.py` | Substructure with pointer deltas |

Compile test files and load into IDA to verify synthesis:

```bash
# Compile test
clang -g -O0 -o test_simple integration_tests/test_simple_struct.c

# Load in IDA, navigate to process_simple(), run Structor
```

---

## Architecture

### Core Data Types

| Type | Purpose |
|------|---------|
| `FieldAccess` | Single observed memory access (offset, size, type) |
| `AccessPattern` | Collection of accesses for a variable |
| `UnifiedAccessPattern` | Merged pattern from cross-function analysis |
| `FieldCandidate` | Candidate field for Z3 constraint solving |
| `SynthField` | Synthesized field definition |
| `SynthStruct` | Complete synthesized structure |
| `SynthVTable` | Synthesized vtable with function pointer slots |
| `SynthResult` | Result of synthesis operation with Z3 details |

### Z3 Module Components

| Component | Purpose |
|-----------|---------|
| `Z3Context` | RAII wrapper for Z3 context with Structor configuration |
| `TypeEncoder` | Encodes IDA types to Z3 expressions |
| `FieldCandidateGenerator` | Generates candidate fields from accesses |
| `ArrayConstraintBuilder` | Detects and encodes array patterns |
| `LayoutConstraintBuilder` | Builds and solves layout constraints |
| `ConstraintTracker` | Tracks constraint provenance for debugging |

### Type Inference Components

| Component | Purpose |
|-----------|---------|
| `InferredType` | Recursive type representation (base, pointer, function, array, struct, sum) |
| `TypeLattice` | Subtyping with LUB/GLB operations |
| `TypeLatticeEncoder` | Encodes `InferredType` to Z3 integer expressions |
| `BitvectorTypeEncoder` | Fast 32-bit bitvector encoding for Z3 |
| `TypeVariable` | Represents unknown types for variables/memory |
| `TypeConstraint` | Constraint types (Equal, Subtype, IsBase, IsPointer, IsSigned, etc.) |
| `InstructionSemanticsExtractor` | Extracts type constraints from Hex-Rays ctree |
| `SignednessInferrer` | Infers signedness from comparison patterns |
| `PointerIntegerDiscriminator` | Soft constraint heuristics for pointer vs integer |
| `AbstractLocation` | Memory location representation (stack, heap, global, parameter) |
| `SteensgaardAliasAnalyzer` | Fast unification-based alias analysis O(n·α(n)) |
| `AndersenAliasAnalyzer` | Precise inclusion-based alias analysis O(n³) |
| `AliasAnalyzer` | Unified interface selecting algorithm based on config |
| `TypeInferenceEngine` | Main orchestrator implementing 7-phase pipeline |
| `TypeApplicator` | Applies inferred types to IDA decompiler |
| `PolymorphicFunctionDetector` | Detects memcpy, qsort-like patterns |
| `CallingConventionDetector` | Infers calling conventions from register usage |

### Base Type Hierarchy

```
BaseType
├── Unknown      (top)
├── Bottom       (contradiction)
├── Signed Integers
│   ├── Int8
│   ├── Int16
│   ├── Int32
│   └── Int64
├── Unsigned Integers
│   ├── UInt8
│   ├── UInt16
│   ├── UInt32
│   └── UInt64
├── Floating Point
│   ├── Float32
│   └── Float64
└── Special
    ├── Void
    └── Bool
```

### Type Resolution Priority

When multiple accesses target the same offset with different types, the more specific type wins:

| Semantic Type | Priority |
|---------------|----------|
| VTablePointer | 100 |
| FunctionPointer | 90 |
| NestedStruct | 85 |
| Pointer | 80 |
| Double | 70 |
| Float | 65 |
| Array | 60 |
| UnsignedInteger | 50 |
| Integer | 40 |
| Padding | 10 |
| Unknown | 0 |

### Cross-Function Analysis Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `max_depth` | 5 | Maximum call graph traversal depth |
| `follow_forward` | true | Follow caller → callee (parameter passing) |
| `follow_backward` | true | Follow callee → caller (return values) |
| `max_functions` | 100 | Maximum functions to analyze |
| `include_indirect_calls` | false | Include indirect/virtual calls |
| `track_pointer_deltas` | true | Track ptr+const adjustments |

---

## Relationship to Suture

> fun fact, structor only exists because I wanted to peer pressure @libtero into publishing Suture to GitHub ... with success!

Structor incorporates design patterns and concepts from the [Suture](https://github.com/libtero/suture) project, a Python-based declarative AST pattern matching framework for Hex-Rays:

| Adopted Concept | Description |
|-----------------|-------------|
| Nested `AccessInfo` | Multi-level structure representation for vtable patterns |
| Type-aware conflict resolution | Priority-based type selection when accesses conflict |
| Semantic type priority scoring | More specific types preferred (vtable > funcptr > pointer > int) |
| Predicate-based filtering | `AccessPredicate` function for filtering accesses |
| Structured debug logging | `debug_log()`, `DebugScope`, `cot_name()` utilities |

The primary difference is that Suture is implemented in Python using IDA's Python API, while Structor is a native C++ plugin with Z3 integration for improved performance and constraint-based synthesis.

---

## Known Limitations

### Minimum 2 Accesses Required

Functions with only a single field access are rejected to prevent creating trivial structures from ambiguous patterns. This threshold is configurable via `min_accesses` (default: 2).

### Variable Aliasing

If a variable is assigned to a temporary before being dereferenced, accesses through the temporary are not tracked:

```c
void example(void* ptr) {
    void* temp = ptr;        // Aliasing
    int x = *(int*)temp;     // Access on 'temp', not 'ptr'
    // Synthesis on 'ptr' sees 0 accesses
}
```

**Workaround**: Run synthesis on the aliased variable (`temp`) instead, or enable cross-function analysis which may detect the alias. The alias analysis in the type inference engine can also help connect aliased variables.

### Computed Array Indices

Array accesses with computed indices are not detected as structure fields because the offset isn't constant:

```c
int value = ptr[i * 4];  // Variable index - cannot determine offset
```

### VTable Detection Limitations

VTable patterns using intermediate pointer variables may not be fully detected:

```c
void** vtable = *(void***)obj;  // Load vtable
func = vtable[1];                // Access through 'vtable', not 'obj'
func(obj);                       // Call
```

The vtable slot accesses are on `vtable`, not `obj`, so they're not counted toward `obj`'s synthesis.

### Z3 Solver Limits

- Default timeout: 5 seconds (configurable)
- Default memory limit: 256 MB (configurable)
- Maximum structure size: 64 KB
- Maximum field candidates: 1000

### Type Inference Limitations

- Polymorphic function detection is heuristic-based
- Complex indirect call patterns may not propagate types correctly
- Sum types (unions) lose some precision when converted to IDA types

---

## License

MIT
