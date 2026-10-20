"""Small bilingual bag-of-words baseline, trained only on labelled local fixtures."""
import json
import math
import re
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path

class Text(HTMLParser):
    def __init__(self): super().__init__(); self.parts=[]; self.hidden=0
    def handle_starttag(self,tag,attrs):
        if tag in ('script','style'): self.hidden+=1
    def handle_endtag(self,tag):
        if tag in ('script','style'): self.hidden=max(0,self.hidden-1)
    def handle_data(self,data):
        if not self.hidden: self.parts.append(data)

def tokens(text):
    p=Text(); p.feed(text)
    return re.findall(r'[^\W\d_]{2,}', ' '.join(p.parts).lower(), re.UNICODE)

def dataset(): return json.loads((Path(__file__).resolve().parents[1]/'fixtures/pages.json').read_text())

def classify(text):
    train=[x for x in dataset() if x['split']=='train']
    counts={label:Counter(t for row in train if row['label']==label for t in tokens(row['text'])) for label in ('benign','suspicious')}
    vocab=set(counts['benign']) | set(counts['suspicious'])
    words=tokens(text)
    if not words: return {'label':'unknown','score':None,'reasons':['No readable page text'], 'model':'naive-bayes-fixture-v1'}
    scores={}
    for label in counts:
        scores[label]=math.log(sum(x['label']==label for x in train)/len(train))
        scores[label]+=sum(math.log((counts[label][w]+1)/(sum(counts[label].values())+len(vocab))) for w in words if w in vocab)
    delta=max(-700,min(700,scores['benign']-scores['suspicious']))
    probability=1/(1+math.exp(delta))
    clues=sorted(set(words)&set(counts['suspicious']),key=lambda w:counts['suspicious'][w]-counts['benign'][w],reverse=True)[:6]
    return {'label':'suspicious' if probability>=0.5 else 'benign','score':round(probability,4),'reasons':clues,'model':'naive-bayes-fixture-v1','caution':'Uncalibrated synthetic-training score; not a probability of real-world fraud'}

def metrics(rows):
    counts={k:0 for k in ('tp','fp','tn','fn')}
    for truth,pred in rows:
        if truth not in ('suspicious','benign') or pred not in ('suspicious','benign'): raise ValueError('Labels must be suspicious or benign')
        counts['tp' if truth=='suspicious' and pred=='suspicious' else 'fn' if truth=='suspicious' else 'fp' if pred=='suspicious' else 'tn']+=1
    tp,fp,tn,fn=(counts[k] for k in ('tp','fp','tn','fn'))
    return dict(counts,n=len(rows),precision=round(tp/(tp+fp),4) if tp+fp else None,recall=round(tp/(tp+fn),4) if tp+fn else None,accuracy=round((tp+tn)/len(rows),4) if rows else None)

def evaluate():
    test=[x for x in dataset() if x['split']=='test']
    predictions=[dict(id=x['id'],truth=x['label'],prediction=classify(x['text'])['label']) for x in test]
    return dict(metrics=metrics([(x['truth'],x['prediction']) for x in predictions]), predictions=predictions, provenance='Authored synthetic held-out fixtures; no real-world validity estimate', training_count=sum(x['split']=='train' for x in dataset()), model='naive-bayes-fixture-v1')
