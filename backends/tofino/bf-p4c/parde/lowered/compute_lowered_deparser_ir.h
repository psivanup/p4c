/**
 * Copyright (C) 2024 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef BACKENDS_TOFINO_BF_P4C_PARDE_LOWERED_COMPUTE_LOWERED_DEPARSER_IR_H_
#define BACKENDS_TOFINO_BF_P4C_PARDE_LOWERED_COMPUTE_LOWERED_DEPARSER_IR_H_

#include "bf-p4c/parde/allocate_parser_checksum.h"
#include "bf-p4c/parde/clot/clot_info.h"
#include "bf-p4c/parde/parde_visitor.h"

namespace Parde::Lowered {

/// \ingroup LowerDeparserIR
///
/// \brief Generates lowered deparser IR with container references.
///
/// Generate the lowered deparser IR by splitting references to fields in the
/// high-level deparser IR into references to containers.
struct ComputeLoweredDeparserIR : public DeparserInspector {
    ComputeLoweredDeparserIR(const PhvInfo &phv, const ClotInfo &clotInfo)
        : phv(phv),
          clotInfo(clotInfo),
          nextChecksumUnit(0),
          lastSharedUnit(0),
          nested_unit(0),
          normal_unit(4) {
        igLoweredDeparser = new IR::BFN::LoweredDeparser(INGRESS);
        egLoweredDeparser = new IR::BFN::LoweredDeparser(EGRESS);
    }

    /// The lowered deparser IR generated by this pass.
    IR::BFN::LoweredDeparser *igLoweredDeparser;
    IR::BFN::LoweredDeparser *egLoweredDeparser;
    // Contains checksum unit number for each checksum destination in each gress
    std::map<gress_t, std::map<const IR::BFN::EmitChecksum *, unsigned>> checksumInfo;

 private:
    /// \brief Remove guaranteed-zero fields from checksum calculations.
    ///
    /// Fields which are deparser zero candidates are guaranteed to be zero.
    /// Removing such fields from a checksum calculation will not alter the checksum.
    IR::Vector<IR::BFN::FieldLVal> removeDeparserZeroFields(
        IR::Vector<IR::BFN::FieldLVal> checksumFields);

    /// Returns lowered partial phv and clot checksum
    std::pair<IR::BFN::PartialChecksumUnitConfig *, std::vector<IR::BFN::ChecksumClotInput *>>
    getPartialUnit(const IR::BFN::EmitChecksum *emitChecksum, gress_t gress);

    /// Lowers full checksum unit
    /// First lower @p emitChecksum then lower emitChecksum->nestedChecksum
    IR::BFN::FullChecksumUnitConfig *lowerChecksum(const IR::BFN::EmitChecksum *emitChecksum,
                                                   gress_t gress);

    /// JBAYB0 can invert the output of partial checksum units and clots. But this feature
    /// exists only for full checksum unit 0 - 3. This inversion feature is needed for
    /// calculation of nested checksum. So for JBAYB0, checksum engine allocation for normal
    /// checksums (normal means not nested) starts from unit 4. If 4 - 7 engines are not free
    /// then any free engine from 0 - 3 will be allocated. For nested checksums, engine
    /// allocation starts from unit 0.
    ///
    /// For all other targets, checksum engine allocation starts from unit 0.
    unsigned int getChecksumUnit(bool nested);

    /// \brief Compute the lowered deparser IR
    ///
    /// Convers the field emits to container emits.
    bool preorder(const IR::BFN::Deparser *deparser) override;

    const PhvInfo &phv;
    const ClotInfo &clotInfo;
    unsigned nextChecksumUnit;
    unsigned lastSharedUnit;
    unsigned nested_unit;
    unsigned normal_unit;
};

}  // namespace Parde::Lowered

#endif /* BACKENDS_TOFINO_BF_P4C_PARDE_LOWERED_COMPUTE_LOWERED_DEPARSER_IR_H_ */