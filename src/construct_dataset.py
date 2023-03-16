from multiprocessing import Pool
from copy import deepcopy
from utils import get_contract_ir

from datasets import load_dataset
from tqdm import tqdm

CHUNK_SIZE = 5000
processed_dataset_store_path = '../processed_dataset'


if __name__ == '__main__':
    pool = Pool(processes=8)

    dataset = load_dataset("mwritescode/slither-audited-smart-contracts", name="all-plain-text", cache_dir="../dataset")
    print(dataset["train"][0])
    data_to_write = []

    # iterate dataset
    all_bytecodes = []
    for datum in tqdm(dataset["train"]):
        all_bytecodes.append(deepcopy(datum["bytecode"]))

    del dataset

    results = pool.imap_unordered(get_contract_ir, all_bytecodes)
    for i in tqdm(range(len(all_bytecodes))):
        if i < 120000:
            continue

        try:
            contract_irs = results.next(timeout=10)
        except Exception as e:
            continue

        for fn_name, irs in contract_irs.items():
            data_to_write.append(irs)

        if (i + 1) % CHUNK_SIZE == 0:
            print(f"writing to file {processed_dataset_store_path}/dataset_{i // CHUNK_SIZE}.txt ...")
            with open(f"{processed_dataset_store_path}/dataset_{i // CHUNK_SIZE}.txt", 'w') as f:
                for line in data_to_write:
                    f.write(f"{line}\n")
                data_to_write.clear()

    print(f"writing to file {processed_dataset_store_path}/dataset_24.txt ...")
    with open(f"{processed_dataset_store_path}/dataset_24.txt", 'w') as f:
        for line in data_to_write:
            f.write(f"{line}\n")
        data_to_write.clear()
    pool.close()
    pool.terminate()
