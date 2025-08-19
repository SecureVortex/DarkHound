import spacy

# Load a small spaCy model for demo
nlp = spacy.blank("en")
if not nlp.has_pipe("ner"):
    ner = nlp.create_pipe("ner")
    nlp.add_pipe("ner")

def analyze_text(text):
    doc = nlp(text)
    entities = {ent.label_: ent.text for ent in doc.ents}
    return entities