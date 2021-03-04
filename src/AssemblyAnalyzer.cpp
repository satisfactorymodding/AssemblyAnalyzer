#include "AssemblyAnalyzer.h"
#include <Zydis/Decoder.h>
#include <Zydis/Formatter.h>
#include <Zydis/Utils.h>

//Struct that holds the information about function
struct FunctionInfo {
    //Whenever pointer represents a valid function at all
    bool bIsValid;
    //Whenever this function represents a virtual function call thunk and doesn't represent the real function
    bool bIsVirtualFunction;
    //Real resolved function address, or NULL if this function represents a virtual function
    void* RealFunctionAddress;
    //Offset to the function pointer inside of the vtable, if bIsVirtualFunction is set
    uint32_t VirtualTableFunctionOffset;
};

//Tests for simple thunks in "jmp SomeRVA" form. These thunks are usually emitted when building in the debug configuration
bool IsJumpThunkInstruction(const ZydisDecodedInstruction& Instruction) {
    return Instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_JMP && Instruction.operands[0].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE;
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
FunctionInfo DiscoverRealFunctionAddress(uint8_t* FunctionPtr) {
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
        ZydisCalcAbsoluteAddress(&Instruction, &Instruction.operands[0], (ZyanU64) FunctionPtr, &ResultJumpAddress);
        return DiscoverRealFunctionAddress((uint8_t*) ResultJumpAddress);
    }

    //TODO test for import table jump: jmp cs:__imp_??0ExampleLibraryClass@@QEAA@XZ
    //TODO need to figure out how it actually looks in the Zydis representation

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

//Layout of the __DefaultConstructor functions from UE is as follows:
//mov     rcx, [rcx]
//test    rcx, rcx
//jnz     AFGBuildableFoundation::AFGBuildableFoundation(void)
//retn