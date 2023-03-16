# Similar Scam Contract Detector

## Description

This agent detects the creation of scam contracts based on bytecode similarities to known scam contracts provided by other forta bots like bot 0xf715450e392acb385eabdb8fc94278b3821d2c9a148de777726673895c7283a0.

## How does it work?
This bot will listen to every contract creation event and retrieve the runtime bytecode of the created contract. Then a CFG of the bytecode will be built, and instructions of every function will be extracted to be vectorized using doc2vec model. Finally, the vectorized function features of the contract will be compared with the vectorized function features of the known scam contracts using FAISS. That is, this bot perform function-level semantic similarity detection.

When calculating the similarity between contracts, we define the similarity of contract $C_1$ and $C_2$ equals:

$$Sim(C_1, C_2) = \sum_{f_i \in C_1} log \frac{P(f_i, f_2^*)}{P(f_i, \bar{f_2})},$$

where $f_i$ represents $C_1$'s $i$-th function, $f_2^\*$ represents $C_2$'s most similar function to $f_1$, and $\bar{f_2}$ represents the mean of $C_2$'s all functions. $P(f_i, f_2^\*)$ and $P(f_i, \bar{f_2})$ are the probabilities of $f_i$ being semantically similar to $f_2^\*$ and $\bar{f_2}$ respectively. The probability $P(\cdot)$ is calculated by:

$$P(f_i, f_j) = \frac{1}{1 + e^{-k * cos(f_i, f_2)}},$$

where $k$ is a hyperparameter and $cos(\cdot, \cdot)$ is the cosine similarity between two vectors.

When calculating the confidence of the prediction, we first calculate the threshold of the similarity score as:

$$t = \frac{\lambda Sim(C_1, C_1) - Sim(C_1, C_2)}{\lambda Sim(C_1, C_1)}$$

Then, the confidence score will be calculated as $\frac{Sim(C_1, C_2) - t}{Sim(C_1, C_2)}$

## Supported Chains

All chains that Forta support

## Alerts

- NEW-SCAMMER-CONTRACT-CODE-HASH
  - Fired when a similar contract is identified based on the code similarity hash
  - Severity is always set to "medium"
  - Type is always set to "suspicious"
  - Metadata:
    - `alert_hash` - the alert hash from the handleAlert function that brought this scammer into scope (so the scammer contract that the new scammer contract is similar to)
    - `new_scammer_eoa` - the EOA that created the new scammer contract
    - `new_scammer_contract_address` - the address of the new scammer contract
    - `scammer_eoa` - the EOA that created the original scammer contract
    - `scammer_contract_address` - the original scammer contract
    - `similarity_score` - score that expresses the similarity between the original scammer contract and the new scammer contract identified
    - `similarity_hash` - the similarity hash for grouping the two contracts together
  - Labels
    - New scammer EOA will be set as `scam`
    - New scammer contract address will be set as `scam`
    - confidence will be calculated by the above mentioned equation.

## Test Data

```shell
npm run sequence tx0x77ef021978dc893297a77a51990efab1ef9234006a1d97bb78678354d92de632,0xe350cf63228ae2277b0e5b49089c6f255acd481cea19892749357fe74edbd0f7,tx0xa2819befc5c19c3a51fbbea8557e4dfebd2be41cdd7359462c18027a364e7fae,0xc3b228892e92ebf86f7e71bc202279a0a4863ca83f73fa7c8df9a592a59943cb,tx0x77ef021978dc893297a77a51990efab1ef9234006a1d97bb78678354d92de632
```

The above test script should raise alerts two times, one for the second transaction (starts with `tx`) and one for the third transaction.

## Train the model

The model will be trained on `slither-audited-smart-contracts` dataset. After processing there will be more than 2,000,000 function instructions for our model to learn unsupervisedly. The training process takes roughly 1 hour on M1 Max.

```shell
python construct_dataset.py && python train.py
```
