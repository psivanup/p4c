/*
Copyright 2018-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <set>
#include <unordered_map>

#include <boost/optional.hpp>

#include "frontends/common/resolveReferences/referenceMap.h"
#include "frontends/p4/fromv1.0/v1model.h"
#include "frontends/p4/typeMap.h"
#include "ir/ir.h"
#include "lib/log.h"
#include "typeSpecConverter.h"

#include "p4RuntimeArchHandler.h"
#include "p4RuntimeArchStandard.h"

namespace P4 {

/** \addtogroup control_plane
 *  @{
 */
namespace ControlPlaneAPI {

namespace Standard {

P4RuntimeArchHandlerIface*
V1ModelArchHandlerBuilder::operator()(
    ReferenceMap* refMap, TypeMap* typeMap, const IR::ToplevelBlock* evaluatedProgram) const {
    return new P4RuntimeArchHandlerV1Model(refMap, typeMap, evaluatedProgram);
}

void P4RuntimeArchHandlerV1Model::collectExternFunction(P4RuntimeSymbolTableIface* symbols,
                                                        const P4::ExternFunction* externFunction) {
    auto digest = getDigestCall(externFunction, refMap, typeMap, nullptr);
    if (digest) symbols->add(SymbolType::DIGEST(), digest->name);
}

void P4RuntimeArchHandlerV1Model::addTableProperties(const P4RuntimeSymbolTableIface& symbols,
                                                     p4configv1::P4Info* p4info,
                                                     p4configv1::Table* table,
                                                     const IR::TableBlock* tableBlock) {
    P4RuntimeArchHandlerCommon<Arch::V1MODEL>::addTableProperties(
        symbols, p4info, table, tableBlock);
    auto tableDeclaration = tableBlock->container;

    bool supportsTimeout = getSupportsTimeout(tableDeclaration);
    if (supportsTimeout) {
        table->set_idle_timeout_behavior(p4configv1::Table::NOTIFY_CONTROL);
    } else {
        table->set_idle_timeout_behavior(p4configv1::Table::NO_TIMEOUT);
    }
}

void P4RuntimeArchHandlerV1Model::addExternFunction(const P4RuntimeSymbolTableIface& symbols,
                                                    p4configv1::P4Info* p4info,
                                                    const P4::ExternFunction* externFunction) {
    auto p4RtTypeInfo = p4info->mutable_type_info();
    auto digest = getDigestCall(externFunction, refMap, typeMap, p4RtTypeInfo);
    if (digest) addDigest(symbols, p4info, *digest);
}

template <Arch arch> void
P4RuntimeArchHandlerPSAPNA<arch>::collectExternInstance(P4RuntimeSymbolTableIface* symbols,
                                                        const IR::ExternBlock* externBlock) {
    P4RuntimeArchHandlerCommon<arch>::collectExternInstance(symbols, externBlock);

    auto decl = externBlock->node->to<IR::IDeclaration>();
    if (decl == nullptr) return;
    if (externBlock->type->name == "Digest") {
        symbols->add(SymbolType::DIGEST(), decl);
    }
}

template <Arch arch> void
P4RuntimeArchHandlerPSAPNA<arch>::addTableProperties(const P4RuntimeSymbolTableIface& symbols,
                                                     p4configv1::P4Info* p4info,
                                                     p4configv1::Table* table,
                                                     const IR::TableBlock* tableBlock) {
    P4RuntimeArchHandlerCommon<arch>::addTableProperties(
        symbols, p4info, table, tableBlock);

    auto tableDeclaration = tableBlock->container;
    bool supportsTimeout = getSupportsTimeout(tableDeclaration);
    if (supportsTimeout) {
        table->set_idle_timeout_behavior(p4configv1::Table::NOTIFY_CONTROL);
    } else {
        table->set_idle_timeout_behavior(p4configv1::Table::NO_TIMEOUT);
    }
}

template <Arch arch> void
P4RuntimeArchHandlerPSAPNA<arch>::addExternInstance(const P4RuntimeSymbolTableIface& symbols,
                                                    p4configv1::P4Info* p4info,
                                                    const IR::ExternBlock* externBlock) {
    P4RuntimeArchHandlerCommon<arch>::addExternInstance(
        symbols, p4info, externBlock);

    auto decl = externBlock->node->to<IR::Declaration_Instance>();
    if (decl == nullptr) return;
    auto p4RtTypeInfo = p4info->mutable_type_info();
    if (externBlock->type->name == "Digest") {
        auto digest = getDigest(decl, p4RtTypeInfo);
        if (digest) this->addDigest(symbols, p4info, *digest);
    }
}

/// @return serialization information for the Digest extern instacne @decl
template <Arch arch> boost::optional<Digest>
P4RuntimeArchHandlerPSAPNA<arch>::getDigest(const IR::Declaration_Instance* decl,
                                            p4configv1::P4TypeInfo* p4RtTypeInfo) {
    BUG_CHECK(decl->type->is<IR::Type_Specialized>(),
              "%1%: expected Type_Specialized", decl->type);
    auto type = decl->type->to<IR::Type_Specialized>();
    BUG_CHECK(type->arguments->size() == 1, "%1%: expected one type argument", decl);
    auto typeArg = type->arguments->at(0);
    auto typeSpec = TypeSpecConverter::convert(this->refMap, this->typeMap,
                                               typeArg, p4RtTypeInfo);
    BUG_CHECK(typeSpec != nullptr,
              "P4 type %1% could not be converted to P4Info P4DataTypeSpec");

    return Digest{decl->controlPlaneName(), typeSpec, decl->to<IR::IAnnotated>()};
}

P4RuntimeArchHandlerIface*
PSAArchHandlerBuilder::operator()(
    ReferenceMap* refMap, TypeMap* typeMap, const IR::ToplevelBlock* evaluatedProgram) const {
    return new P4RuntimeArchHandlerPSA(refMap, typeMap, evaluatedProgram);
}

P4RuntimeArchHandlerIface*
PNAArchHandlerBuilder::operator()(
        ReferenceMap* refMap, TypeMap* typeMap, const IR::ToplevelBlock* evaluatedProgram) const {
    return new P4RuntimeArchHandlerPNA(refMap, typeMap, evaluatedProgram);
}

P4RuntimeArchHandlerIface*
UBPFArchHandlerBuilder::operator()(
        ReferenceMap* refMap, TypeMap* typeMap, const IR::ToplevelBlock* evaluatedProgram) const {
    return new P4RuntimeArchHandlerUBPF(refMap, typeMap, evaluatedProgram);
}

}  // namespace Standard

}  // namespace ControlPlaneAPI

/** @} */  /* end group control_plane */
}  // namespace P4
