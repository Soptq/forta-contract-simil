import logging
import os
import gensim
import collections
import random

from tqdm import tqdm

logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s', level=logging.INFO)


def read_corpus(fpath, tokens_only=False):
    for filename in os.listdir(fpath):
        if not filename.endswith(".txt"):
            continue
        fname = os.path.join(fpath, filename)
        with open(fname) as f:
            for i, line in tqdm(enumerate(f)):
                tokens = line.split(" ")
                if tokens_only:
                    yield tokens
                else:
                    # For training data, add tags
                    yield gensim.models.doc2vec.TaggedDocument(tokens, [i])


train_corpus = list(read_corpus("../processed_dataset"))

model = gensim.models.doc2vec.Doc2Vec(
    vector_size=100,
    min_count=1,
    workers=8,
    dm=0,
    epochs=100,
    min_alpha=0.025,
    alpha=0.0001,
    window=15,
    hs=1,
    negative=0,
    sample=0.
)
model.build_vocab(train_corpus)
model.train(train_corpus, total_examples=model.corpus_count, epochs=model.epochs)
model.save("doc2vec.model")

# assessment
ranks = []
second_ranks = []
for doc_id in tqdm(range(len(train_corpus[:1000]))):
    inferred_vector = model.infer_vector(train_corpus[doc_id].words)
    sims = model.dv.most_similar([inferred_vector], topn=len(model.dv))
    rank = [docid for docid, sim in sims].index(doc_id)
    ranks.append(rank)

    second_ranks.append(sims[1])
counter = collections.Counter(ranks)
print(counter)

doc_id = random.randint(0, len(train_corpus[:1000]) - 1)

# Compare and print the second-most-similar document
print('Train Document ({}): «{}»\n'.format(doc_id, ' '.join(train_corpus[doc_id].words)))
sim_id = second_ranks[doc_id]
print('Similar Document {}: «{}»\n'.format(sim_id, ' '.join(train_corpus[sim_id[0]].words)))
