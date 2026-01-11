#include "structor/z3/type_applicator.hpp"
#include "structor/utils.hpp"

#ifndef STRUCTOR_TESTING
#include <pro.h>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <name.hpp>
#endif

namespace structor::z3 {

// ============================================================================
// TypeApplicationResult implementation
// ============================================================================

qstring TypeApplicationResult::summary() const {
    qstring result;
    result.sprnt("Type Application Results:\n");
    result.cat_sprnt("  Total variables: %u\n", total_variables);
    result.cat_sprnt("  Applied: %u\n", applied_count);
    result.cat_sprnt("  Failed: %u\n", failed_count);
    result.cat_sprnt("  Skipped: %u\n", skipped_count);
    
    if (propagated_count > 0) {
        result.cat_sprnt("  Propagated: %u\n", propagated_count);
    }
    
    if (!applied.empty()) {
        result.cat_sprnt("\nApplied types:\n");
        for (const auto& a : applied) {
            qstring type_str = a.inferred.to_string();
            result.cat_sprnt("  %s (var %d): %s\n", 
                            a.var_name.c_str(), a.var_idx, type_str.c_str());
        }
    }
    
    if (!failed.empty()) {
        result.cat_sprnt("\nFailed types:\n");
        for (const auto& f : failed) {
            result.cat_sprnt("  %s (var %d): %s\n",
                            f.var_name.c_str(), f.var_idx, f.reason.c_str());
        }
    }
    
    if (!skipped.empty() && skipped.size() <= 10) {
        result.cat_sprnt("\nSkipped:\n");
        for (const auto& s : skipped) {
            result.cat_sprnt("  %s (var %d): %s\n",
                            s.var_name.c_str(), s.var_idx, s.reason.c_str());
        }
    } else if (!skipped.empty()) {
        result.cat_sprnt("\nSkipped: %zu variables (too many to list)\n", skipped.size());
    }
    
    return result;
}

// ============================================================================
// TypeApplicator implementation
// ============================================================================

TypeApplicator::TypeApplicator(const TypeApplicationConfig& config)
    : config_(config)
    , propagator_(Config::instance().options())
{
}

TypeApplicationResult TypeApplicator::apply(
    cfunc_t* cfunc,
    const FunctionTypeInferenceResult& inference_result)
{
    TypeApplicationResult result;
    
    if (!cfunc) {
        return result;
    }
    
    result.func_ea = cfunc->entry_ea;
    
    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars) {
        return result;
    }
    
    result.total_variables = static_cast<unsigned>(inference_result.local_types.size());
    
    // Apply each inferred type
    for (const auto& ivt : inference_result.local_types) {
        qstring reason;
        
        // Check if we should apply this type
        if (!should_apply(cfunc, ivt.var_idx, ivt.type, ivt.confidence, &reason)) {
            TypeApplicationResult::SkippedType skipped;
            skipped.var_idx = ivt.var_idx;
            skipped.var_name = ivt.var_name;
            skipped.reason = reason;
            result.skipped.push_back(std::move(skipped));
            result.skipped_count++;
            continue;
        }
        
        // Try to apply the type
        bool success = apply_variable(cfunc, ivt.var_idx, ivt.type, ivt.confidence, &reason);
        
        if (success) {
            TypeApplicationResult::AppliedType applied;
            applied.var_idx = ivt.var_idx;
            applied.var_name = ivt.var_name;
            applied.inferred = ivt.type;
            applied.applied = ivt.type.to_tinfo();
            applied.confidence = ivt.confidence;
            result.applied.push_back(std::move(applied));
            result.applied_count++;
            
            report_application(ivt.var_idx, ivt.var_name.c_str(), true, "applied");
        } else {
            TypeApplicationResult::FailedType failed;
            failed.var_idx = ivt.var_idx;
            failed.var_name = ivt.var_name;
            failed.inferred = ivt.type;
            failed.reason = reason;
            result.failed.push_back(std::move(failed));
            result.failed_count++;
            
            report_application(ivt.var_idx, ivt.var_name.c_str(), false, reason.c_str());
        }
    }
    
    // Apply function signature if configured
    if (config_.apply_signatures && inference_result.return_type.has_value()) {
        (void)apply_signature(cfunc, inference_result);
    }
    
    // Refresh decompiler if configured
    if (config_.force_refresh && result.applied_count > 0) {
        refresh_decompiler(cfunc);
    }
    
    return result;
}

bool TypeApplicator::apply_variable(
    cfunc_t* cfunc,
    int var_idx,
    const InferredType& type,
    TypeConfidence confidence,
    qstring* out_reason)
{
    if (!cfunc) {
        if (out_reason) *out_reason = "null cfunc";
        return false;
    }
    
    // Check variable bounds
    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
        if (out_reason) *out_reason = "invalid variable index";
        return false;
    }
    
    // Convert to tinfo_t
    tinfo_t ida_type = prepare_type(type, cfunc, var_idx);
    if (ida_type.empty()) {
        if (out_reason) *out_reason = "failed to convert type to tinfo_t";
        return false;
    }
    
    // Apply the type
    return apply_tinfo(cfunc, var_idx, ida_type, out_reason);
}

TypeApplicationResult TypeApplicator::apply_and_propagate(
    cfunc_t* cfunc,
    const FunctionTypeInferenceResult& inference_result)
{
    // First apply types locally
    TypeApplicationResult result = apply(cfunc, inference_result);
    
    if (!config_.propagate_types || result.applied_count == 0) {
        return result;
    }
    
    // Propagate each applied type
    for (const auto& applied : result.applied) {
        PropagationResult prop = propagator_.propagate(
            cfunc->entry_ea,
            applied.var_idx,
            applied.applied,
            PropagationDirection::Both
        );
        
        // Merge propagation results
        for (auto& site : prop.sites) {
            result.propagation.sites.push_back(std::move(site));
        }
        result.propagation.success_count += prop.success_count;
        result.propagation.failure_count += prop.failure_count;
        result.propagated_count += prop.success_count;
    }
    
    return result;
}

TypeApplicationResult TypeApplicator::infer_and_apply(
    Z3Context& ctx,
    cfunc_t* cfunc,
    const TypeInferenceConfig& inference_config)
{
    TypeInferenceEngine engine(ctx, inference_config);
    FunctionTypeInferenceResult inference_result = engine.infer_function(cfunc);
    
    if (!inference_result.success) {
        TypeApplicationResult result;
        result.func_ea = cfunc ? cfunc->entry_ea : BADADDR;
        return result;
    }
    
    if (config_.propagate_types) {
        return apply_and_propagate(cfunc, inference_result);
    } else {
        return apply(cfunc, inference_result);
    }
}

bool TypeApplicator::apply_signature(
    cfunc_t* cfunc,
    const FunctionTypeInferenceResult& inference_result)
{
    if (!cfunc) return false;
    
    // Build new function type
    tinfo_t func_type;
    if (!cfunc->get_func_type(&func_type)) {
        return false;
    }
    
    func_type_data_t ftd;
    if (!func_type.get_func_details(&ftd)) {
        return false;
    }
    
    bool modified = false;
    
    // Apply return type if inferred
    if (inference_result.return_type.has_value()) {
        tinfo_t ret = inference_result.return_type->to_tinfo();
        if (!ret.empty() && ret != ftd.rettype) {
            ftd.rettype = ret;
            modified = true;
        }
    }
    
    // Apply parameter types
    for (size_t i = 0; i < inference_result.param_types.size() && i < ftd.size(); ++i) {
        tinfo_t param = inference_result.param_types[i].to_tinfo();
        if (!param.empty() && param != ftd[i].type) {
            ftd[i].type = param;
            modified = true;
        }
    }
    
    if (!modified) {
        return true;  // Nothing to change
    }
    
    // Create new function type and apply
    tinfo_t new_func_type;
    if (!new_func_type.create_func(ftd)) {
        return false;
    }
    
    // Apply the function type using set_tinfo
    return set_tinfo(cfunc->entry_ea, &new_func_type);
}

void TypeApplicator::refresh_decompiler(cfunc_t* cfunc) {
    if (!cfunc) return;
    
#ifndef STRUCTOR_TESTING
    // Mark for regeneration
    mark_cfunc_dirty(cfunc->entry_ea);
    
    // If there's an active pseudocode view, refresh it
    vdui_t* vu = get_widget_vdui(find_widget("Pseudocode-A"));
    if (vu && vu->cfunc && vu->cfunc->entry_ea == cfunc->entry_ea) {
        vu->refresh_view(true);
    }
#endif
}

bool TypeApplicator::should_apply(
    cfunc_t* cfunc,
    int var_idx,
    const InferredType& type,
    TypeConfidence confidence,
    qstring* out_reason)
{
    // Check confidence threshold
    if (static_cast<int>(confidence) < static_cast<int>(config_.min_confidence)) {
        if (out_reason) {
            out_reason->sprnt("confidence too low (%d < %d)",
                            static_cast<int>(confidence),
                            static_cast<int>(config_.min_confidence));
        }
        return false;
    }
    
    // Check type categories
    if (type.is_pointer() && !config_.apply_pointer_types) {
        if (out_reason) *out_reason = "pointer types disabled";
        return false;
    }
    
    if (type.is_base() && !config_.apply_scalar_types) {
        if (out_reason) *out_reason = "scalar types disabled";
        return false;
    }
    
    // Check if unknown/bottom type
    if (type.is_unknown() || type.is_bottom()) {
        if (out_reason) *out_reason = "unknown or bottom type";
        return false;
    }
    
    // Check if variable already has a meaningful type
    if (!config_.overwrite_existing && has_meaningful_type(cfunc, var_idx)) {
        if (out_reason) *out_reason = "variable already has meaningful type";
        return false;
    }
    
    return true;
}

tinfo_t TypeApplicator::prepare_type(
    const InferredType& type,
    cfunc_t* cfunc,
    int var_idx)
{
    tinfo_t result = type.to_tinfo();
    
    // For pointer types, we don't need to wrap again
    // The to_tinfo() already produces the correct pointer type
    
    return result;
}

bool TypeApplicator::apply_tinfo(
    cfunc_t* cfunc,
    int var_idx,
    const tinfo_t& type,
    qstring* out_reason)
{
    if (!cfunc || type.empty()) {
        if (out_reason) *out_reason = "invalid cfunc or empty type";
        return false;
    }
    
    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
        if (out_reason) *out_reason = "invalid variable index";
        return false;
    }
    
    lvar_t& var = lvars->at(var_idx);
    
    // Prepare lvar_saved_info
    lvar_saved_info_t lsi;
    lsi.ll = var;
    lsi.type = type;
    
    // Apply the type
    if (!modify_user_lvar_info(cfunc->entry_ea, MLI_TYPE, lsi)) {
        if (out_reason) *out_reason = "modify_user_lvar_info failed";
        return false;
    }
    
    // Update the lvar directly as well
    var.set_lvar_type(type);
    
    return true;
}

bool TypeApplicator::has_meaningful_type(cfunc_t* cfunc, int var_idx) {
    if (!cfunc) return false;
    
    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
        return false;
    }
    
    const lvar_t& var = lvars->at(var_idx);
    tinfo_t type = var.type();
    
    if (type.empty()) return false;
    
    // Check if it's a generic type (void*, int, __int64, etc.)
    // These are often defaults and can be overwritten
    
    // Pointer to void is often a placeholder
    if (type.is_ptr()) {
        tinfo_t pointed = type.get_pointed_object();
        if (pointed.is_void()) {
            return false;  // void* is a placeholder
        }
    }
    
    // Check for user-defined flag
    if (var.has_user_type()) {
        return true;  // User explicitly set this type
    }
    
    // Simple integer types are often defaults
    if (type.is_scalar()) {
        // Check if it's just the default int/long type
        qstring type_str;
        type.print(&type_str);
        if (type_str == "__int64" || type_str == "int" || 
            type_str == "unsigned int" || type_str == "unsigned __int64") {
            return false;  // Likely default
        }
    }
    
    return true;  // Has a meaningful type
}

void TypeApplicator::report_application(
    int var_idx,
    const char* var_name,
    bool success,
    const char* reason)
{
    if (config_.application_callback) {
        config_.application_callback(var_idx, var_name, success, reason);
    }
}

// ============================================================================
// Convenience functions
// ============================================================================

TypeApplicationResult infer_and_apply_types(
    cfunc_t* cfunc,
    const TypeInferenceConfig& inference_config,
    const TypeApplicationConfig& application_config)
{
    if (!cfunc) {
        return TypeApplicationResult();
    }
    
    // Create Z3 context
    Z3Context ctx;
    
    // Create applicator and run
    TypeApplicator applicator(application_config);
    return applicator.infer_and_apply(ctx, cfunc, inference_config);
}

TypeApplicationResult apply_inferred_types(
    cfunc_t* cfunc,
    const FunctionTypeInferenceResult& result,
    const TypeApplicationConfig& config)
{
    TypeApplicator applicator(config);
    return applicator.apply(cfunc, result);
}

} // namespace structor::z3
