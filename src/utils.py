from evm_cfg_builder import CFG


def get_contract_ir(bytecode_hex):
    cfg = CFG(bytecode_hex)
    contract_irs = {}
    for function in cfg.functions:
        irs = []
        for basic_block in function.basic_blocks:
            for ins in basic_block.instructions:
                irs.append(ins.name.replace(" ", ""))
        contract_irs[function.name] = " ".join(irs).lower()
    del cfg
    return contract_irs
