from attackmodel import rdf

model = rdf.AttackModel()
model.load_taxii(groups=[rdf.Enterprise])

model.convert(
    subgraph_reification=True,
    old_school_reification=False
)
with open('enterprise-attack.n3', 'w') as outfile:
    outfile.write(model.graph.serialize(format="n3", encoding='utf-8').decode('utf-8'))

model.convert(
    subgraph_reification=False,
    old_school_reification=True
)
with open('enterprise-attack.ttl', 'w') as outfile:
    outfile.write(model.graph.serialize(format="turtle", encoding='utf-8').decode('utf-8'))
