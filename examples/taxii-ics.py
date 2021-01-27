import logging
from attackmodel import rdf

logging.basicConfig(level=logging.INFO)

# Create the empty RDF model
model = rdf.AttackModel()
# Load only the ICS collection
model.load_taxii(groups=[rdf.ICS])
# Convert the data to a model with subgraph reification
model.convert(
    subgraph_reification=True,
    old_school_reification=False
)
# Write the data to a Notation3 file (Note that many programs struggle with that format)
with open('ics-attack.n3', 'w') as outfile:
    outfile.write(model.graph.serialize(format="n3", encoding='utf-8').decode('utf-8'))

# Write the data to a NQuads file, that is more widely supported
with open('ics-attack.nquads', 'w') as outfile:
    outfile.write(model.graph.serialize(format="nquads", encoding='utf-8').decode('utf-8'))

# Convert the data to a model with the classical reification
model.convert(
    subgraph_reification=False,
    old_school_reification=True
)
# Write the data to a Turtle file
with open('ics-attack.ttl', 'w') as outfile:
    outfile.write(model.graph.serialize(format="turtle", encoding='utf-8').decode('utf-8'))
