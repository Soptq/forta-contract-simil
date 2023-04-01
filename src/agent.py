import re
import faiss
import numpy as np
import rlp
import forta_agent
from forta_agent import Finding, FindingType, FindingSeverity, Web3, get_web3_provider, Label, EntityType
import cachetools
from gensim.models import Doc2Vec
import hashlib
from copy import deepcopy

from src.utils import get_contract_ir

web3 = get_web3_provider()
dimension = 100
k = 5
threshold = 0.75

model = Doc2Vec.load("src/doc2vec.model")
simil = faiss.IndexFlatIP(100)
simil_index = []
cached_contract_creations = cachetools.TTLCache(maxsize=2 ** 20, ttl=60 * 60 * 24 * 7)
scammers = []


def calc_contract_address(address, nonce):
    address_bytes = bytes.fromhex(address[2:].lower())
    return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


def handle_transaction(transaction_event):
    findings = []

    # only process contract creation transactions
    if transaction_event.to is not None:
        return findings

    creator = transaction_event.from_.lower().strip()
    contract_address = calc_contract_address(transaction_event.from_, transaction_event.transaction.nonce).lower().strip()
    if creator not in cached_contract_creations:
        cached_contract_creations[creator] = [contract_address]
    else:
        cached_contract_creations[creator].append(contract_address)

    print(f"[{simil.ntotal}] Processing newly created contract: {contract_address}")
    if simil.ntotal == 0:
        return findings

    # detect similarities
    bytecode_hex = web3.eth.get_code(Web3.toChecksumAddress(contract_address)).hex()
    try:
        contract_irs = get_contract_ir(bytecode_hex, filter_attrs=["pure"])
    except:
        print("Unable to get contract IRs for contract: ", contract_address)
        return findings

    vectors = []
    for function_irs in contract_irs.values():
        tokens = function_irs.split(" ")
        vectors.append(model.infer_vector(tokens))
    query = np.array(vectors)
    sha = hashlib.sha256()
    sha.update(str(vectors).encode())
    query_norm = query / np.linalg.norm(query, axis=1)[:, None]
    sim, ind = simil.search(query_norm, 1)
    scammer_ids = list(set([simil_index[i] for i in ind[:, 0]]))

    most_similar_scammer = None
    most_similar_scammer_score = 0.
    for scammer_id in scammer_ids:
        scammer = scammers[scammer_id]
        faiss_id_range = scammer["faiss_id_range"]
        sim, ind = simil.search(
            query_norm,
            faiss_id_range[1] - faiss_id_range[0],
            params=faiss.SearchParameters(
                sel=faiss.IDSelectorRange(faiss_id_range[0], faiss_id_range[1])
            )
        )
        sim_unsorted = deepcopy(sim)
        ind_argsort = np.argsort(ind, axis=1)
        for i in range(sim_unsorted.shape[0]):
            sim_unsorted[i] = sim[i, ind_argsort[i, :]]

        top_sim_target2from = sim_unsorted.max(axis=1)
        average_sim_target2from = sim_unsorted.mean(axis=1)
        top_sim_from2target = sim_unsorted.max(axis=0)
        average_sim_from2target = sim_unsorted.mean(axis=0)

        top_prob_target2from = 1. / (1. + np.exp(-k * top_sim_target2from))
        average_prob_target2from = 1. / (1. + np.exp(-k * average_sim_target2from))
        prob_base_target2from = np.sum(np.log(1.0 / average_prob_target2from))
        prob_top_target2from = np.sum(np.log(top_prob_target2from / average_prob_target2from))

        top_prob_from2target = 1. / (1. + np.exp(-k * top_sim_from2target))
        average_prob_from2target = 1. / (1. + np.exp(-k * average_sim_from2target))
        prob_base_from2target = np.sum(np.log(1.0 / average_prob_from2target))
        prob_top_from2target = np.sum(np.log(top_prob_from2target / average_prob_from2target))

        # score = prob_top_target2from / (2 * prob_base_target2from) + prob_top_from2target / (2 * prob_base_from2target)
        score = (prob_top_target2from + prob_top_from2target) / (prob_base_target2from + prob_base_from2target)
        if score > most_similar_scammer_score:
            most_similar_scammer = scammer
            most_similar_scammer_score = score
    print("score: ", most_similar_scammer_score)
    print("scammer: ", most_similar_scammer)

    if most_similar_scammer_score > threshold:
        confidence = float((most_similar_scammer_score - threshold) / (1. - threshold))
        findings.append(Finding({
            'name': f'similar scam contract detected',
            'description': f'{creator} created contract {contract_address}. It is similar to scam contract {most_similar_scammer["contract_address"]} created by {most_similar_scammer["creator"]}',
            'alert_id': 'NEW-SCAMMER-CONTRACT-CODE-HASH',
            'severity': FindingSeverity.Medium,
            'type': FindingType.Suspicious,
            'metadata': {
                'alert_hash': most_similar_scammer["alert_hash"],
                'new_scammer_eoa': creator,
                'new_scammer_contract_address': contract_address,
                'scammer_eoa': most_similar_scammer["creator"],
                'scammer_contract_address': most_similar_scammer["contract_address"],
                'similarity_score': float(most_similar_scammer_score),
                'similarity_hash': sha.hexdigest(),
            },
            "labels": [
                Label({
                    "entity": creator,
                    "entity_type": EntityType.Address,
                    "label": "scam",
                    "confidence": confidence
                }),
                Label({
                    "entity": contract_address,
                    "entity_type": EntityType.Address,
                    "label": "scam",
                    "confidence": confidence
                }),
            ]
        }))

    return findings


def initialize():
    # do some initialization on startup e.g. fetch data
    return {
        "alertConfig": {
            "subscriptions": [{
                "botId": "0xf715450e392acb385eabdb8fc94278b3821d2c9a148de777726673895c7283a0",
            }, {
                "botId": "0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23",
            }, {
                "botId": "0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1",
            }],
        }
    }


# def handle_block(block_event):
#     findings = []
#     # detect some block condition
#     return findings

def handle_alert(alert_event: forta_agent.alert_event.AlertEvent):
    findings = []
    # detect some alert condition
    description = alert_event.alert.description
    # extract ethereum EOA from the description
    attacker = re.findall(pattern='0x[a-fA-F0-9]{40} ', string=description)[0].lower().strip()
    # add contracts to the index
    if attacker in cached_contract_creations:
        created_contracts = cached_contract_creations.get(attacker)
        for contract_address in created_contracts:
            print(f"Processing attacker's contract: ", contract_address)
            bytecode_hex = web3.eth.get_code(Web3.toChecksumAddress(contract_address)).hex()
            try:
                contract_irs = get_contract_ir(bytecode_hex, filter_attrs=["pure"])
            except:
                print("Unable to get contract IRs for contract: ", contract_address)
                continue

            new_scammer_id = len(scammers)
            new_scammer = {
                "creator": attacker,
                "contract_address": contract_address,
                "faiss_id_range": [len(simil_index), len(simil_index) + len(contract_irs)],
                "alert_hash": alert_event.hash,
            }
            scammers.append(new_scammer)

            vectors = []
            for function_irs in contract_irs.values():
                simil_index.append(new_scammer_id)
                tokens = function_irs.split(" ")
                vector = model.infer_vector(tokens)
                vectors.append(vector)
            # normalize vectors row-wise
            vectors_norm = np.array(vectors) / np.linalg.norm(vectors, axis=1)[:, None]
            simil.add(vectors_norm)
        cached_contract_creations.pop(attacker)

    return findings
