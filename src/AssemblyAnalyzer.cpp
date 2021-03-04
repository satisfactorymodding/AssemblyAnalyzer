#include "AssemblyAnalyzer.h"
#include <Zydis/Decoder.h>
#include <Zydis/Utils.h>

//Tests for simple thunks in "jmp RelativeAddress" form. These thunks are usually emitted when building in the debug configuration
bool IsJumpThunkInstruction(const ZydisDecodedInstruction& Instruction) {
    return Instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_JMP &&
        Instruction.operands[0].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE;
}

//Tests for simple thunks in "jmp [RIP + RelativeAddress]" form. These are usually generated to wrap bare import table functions
bool IsIndirectJumpThunkInstruction(const ZydisDecodedInstruction& Instruction) {
    return Instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_JMP &&
        Instruction.operands[0].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY &&
        Instruction.operands[0].mem.base == ZydisRegister::ZYDIS_REGISTER_RIP &&
        Instruction.operands[0].mem.index == ZydisRegister::ZYDIS_REGISTER_NONE &&
        Instruction.operands[0].mem.disp.has_displacement;
}

//basically tests for assembly sequence: mov rax, [rcx] which is used to retrieve virtual table pointer from the object pointer
bool IsFirstVirtualTableCallThunkInstruction(const ZydisDecodedInstruction& Instruction) {
    const ZydisDecodedOperand& FirstOp = Instruction.operands[0];
    const ZydisDecodedOperand& SecondOp = Instruction.operands[1];
    return Instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_MOV &&
           FirstOp.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER &&
           FirstOp.reg.value == ZydisRegister::ZYDIS_REGISTER_RAX &&
           SecondOp.type == ZydisOperandType ::ZYDIS_OPERAND_TYPE_MEMORY &&
           SecondOp.mem.type == ZydisMemoryOperandType::ZYDIS_MEMOP_TYPE_MEM &&
           SecondOp.mem.base == ZydisRegister::ZYDIS_REGISTER_RCX &&
           !SecondOp.mem.disp.has_displacement &&
           SecondOp.mem.index == ZydisRegister::ZYDIS_REGISTER_NONE;
}

//Used to detect second instruction in the virtual table call thunk, which is jmp [rax+Y] where Y is the method offset in the vtable
bool IsVirtualTableJumpThunkInstruction(const ZydisDecodedInstruction& Instruction) {
    const ZydisDecodedOperand& FirstOp = Instruction.operands[0];
    return Instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_JMP &&
           FirstOp.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY &&
           FirstOp.mem.base == ZydisRegister::ZYDIS_REGISTER_RAX &&
           FirstOp.mem.index == ZydisRegister::ZYDIS_REGISTER_NONE;
}

//Performs code discovery for the function located at the given offset, determining it's kind and real address
//by going through thunks if it's necessary and returns info about the final function
FunctionInfo DiscoverFunction(uint8_t* FunctionPtr) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    //Initialize instruction buffer with the first instruction
    ZydisDecodedInstruction Instruction;
    bool bFirstInstruction = ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, FunctionPtr, 4096, &Instruction));
    if (!bFirstInstruction) {
        //Invalid sequence - not an instruction
        return FunctionInfo{false};
    }

    //test for simple in-module jump thunk
    if (IsJumpThunkInstruction(Instruction)) {
        ZyanU64 ResultJumpAddress;
        const bool bSuccessCalculation = ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Instruction, &Instruction.operands[0], (ZyanU64) FunctionPtr, &ResultJumpAddress));
        assert(bSuccessCalculation);
        return DiscoverFunction((uint8_t*) ResultJumpAddress);
    }

    //test for indirect jump thunks, usually encountered in import table functions wrappers
    if (IsIndirectJumpThunkInstruction(Instruction)) {
        ZyanU64 ResultMemoryLocation;
        const bool bSuccessCalculation = ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Instruction, &Instruction.operands[0], (ZyanU64) FunctionPtr, &ResultMemoryLocation));
        assert(bSuccessCalculation);
        uint8_t* ResultJumpAddress = *(uint8_t**) ResultMemoryLocation;
        return DiscoverFunction(ResultJumpAddress);
    }

    //test for virtual table call thunk
    if (IsFirstVirtualTableCallThunkInstruction(Instruction)) {
        //second instruction should be jump by pointer with displacement,
        //which will be virtual table offset then
        FunctionPtr += Instruction.length;
        bool bSecondInstruction = ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, FunctionPtr, 4096, &Instruction));
        if (!bSecondInstruction) {
            //Invalid sequence - not an instruction
            return FunctionInfo{false};
        }
        //Next instruction should be: jmp qword ptr [rax+Displacement]
        if (IsVirtualTableJumpThunkInstruction(Instruction)) {
            const auto& Displacement = Instruction.operands[0].mem.disp;
            uint32_t VirtualTableOffset = Displacement.has_displacement ? (uint32_t) Displacement.value : 0;
            //Doesn't have an actual address because it is virtual
            return FunctionInfo{true, true, NULL, VirtualTableOffset};
        }
    }

    //We can assume this is correct function pointer now
    return FunctionInfo{true, false, FunctionPtr};
}