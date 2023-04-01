from evm_cfg_builder import CFG


def get_contract_ir(bytecode_hex, filter_attrs=None):
    if filter_attrs is None:
        filter_attrs = []

    cfg = CFG(bytecode_hex)
    contract_irs = {}
    for function in cfg.functions:
        if hasattr(function, "attributes") and any([attr in filter_attrs for attr in function.attributes]):
            continue

        irs = []
        for basic_block in function.basic_blocks:
            for ins in basic_block.instructions:
                irs.append(str(ins))
        contract_irs[function.name] = " ".join(irs).lower()
    del cfg
    return contract_irs


if __name__ == '__main__':
    from datasets import load_dataset

    dataset = load_dataset("mwritescode/slither-audited-smart-contracts", name="all-plain-text", cache_dir="../dataset")
    print(dataset["train"][0])

    # iterate dataset
    bytecodes = []
    for datum in dataset["train"]:
        bytecodes.append(datum["bytecode"])

    print(bytecodes[:10])
    bytecode_hex = bytecodes[1].strip()
    cfg = CFG(bytecode_hex)
    for function in cfg.functions:
        for basic_block in function.basic_blocks:
            for ins in basic_block.instructions:
                print(ins)
