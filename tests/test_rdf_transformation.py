import pytest
from attackcti import rdf
from rdflib.plugins.sparql import prepareQuery
from rdflib.namespace import RDF, RDFS, XSD, DC, DCTERMS, FOAF, SKOS

def get_model(infile, title, rdf_class):
    model = rdf.AttackModel()
    model.load_stix(file_name=infile, url="file://"+infile, title=title, rdf_class=rdf_class)
    model.convert()
    return model
    
@pytest.fixture()
def attack_pattern():
    yield get_model(infile='tests/data/attack-pattern-1.json', title='attack-pattern-1', rdf_class=rdf.CTI['EnterpriseCatalog'])

@pytest.fixture()
def intrusion_set():
    yield get_model(infile='tests/data/intrusion-set-1.json', title='intrusion-set-1', rdf_class=rdf.CTI['EnterpriseCatalog'])

@pytest.fixture()
def relationship():
    yield get_model(infile='tests/data/relationship-1.json', title='relationship-1', rdf_class=rdf.CTI['EnterpriseCatalog'])

@pytest.fixture()
def course_of_action():
    yield get_model(infile='tests/data/course-of-action-1.json', title='course-of-action-1', rdf_class=rdf.CTI['EnterpriseCatalog'])

@pytest.fixture()
def pre():
    yield get_model(infile='tests/data/pre-1.json', title='pre-1', rdf_class=rdf.CTI['PreCatalog'])

def ask(model, asking):
    pq = prepareQuery(
        "ASK { " + asking + " }", 
        initNs = { "cti": rdf.CTI, "dcterms": DCTERMS, "dc": DC, "attack": model.ns, "core": rdf.CORE, "foaf": FOAF, "skos": SKOS })
    return model.graph.query(pq)

########

def test_exists_enterprise_catalog_id(attack_pattern):
    qres = ask(attack_pattern, "?subject a cti:EnterpriseCatalog .")
    assert bool(qres)


def test_attack_pattern_id(attack_pattern):
    qres = ask(attack_pattern, "?subject a cti:AttackPattern; dcterms:identifier \"attack-pattern--2b742742-28c3-4e1b-bab7-8350d6300fa7\" .")
    assert bool(qres)

def test_attack_pattern_created(attack_pattern):
    qres = ask(attack_pattern, "?subject a cti:AttackPattern; dcterms:created \"2020-03-02T19:15:44.182000+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_attack_pattern_creator(attack_pattern):
    qres = ask(attack_pattern, "?subject a cti:AttackPattern; dcterms:creator attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 .")
    assert bool(qres)

def test_attack_pattern_modifed(attack_pattern):
    qres = ask(attack_pattern, "?subject a cti:AttackPattern; dcterms:modified \"2020-10-18T01:53:39.818000+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_attack_pattern_rights(attack_pattern):
    qres = ask(attack_pattern, "?subject a cti:AttackPattern; dcterms:rights attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 .")
    assert bool(qres)

def test_attack_pattern_title(attack_pattern):
    qres = ask(attack_pattern, "?subject a cti:AttackPattern; skos:prefLabel \"Spearphishing Link\" .")
    assert bool(qres)

def test_attack_pattern_references_1(attack_pattern):
    qres = ask(attack_pattern, "?subject a cti:AttackPattern; dcterms:references attack:ref_68633290849cc1e088bf2f49788d0f159e24afd60038d6ccaca5adfb977a07ac .")
    assert bool(qres)

def test_attack_pattern_references_2(attack_pattern):
    qres = ask(attack_pattern, "?subject a cti:AttackPattern; dcterms:references attack:ref_adec923c37ebdc6f054399e252eb9e8de7caaded59bf5466ac5242f81857233f .")
    assert bool(qres)
    
def test_attack_pattern_references_3(attack_pattern):
    qres = ask(attack_pattern, "?subject a cti:AttackPattern; dcterms:references attack:ref_e6686c72e4cfda456dd06fa2fb3c02356d1df27fad1542713cc3f9b116420d96 .")
    assert bool(qres)
    
def test_attack_pattern_description(attack_pattern):
    qres = ask(attack_pattern, "?subject a cti:AttackPattern; skos:definition ?description .")
    assert bool(qres)


def test_ref_1(attack_pattern):
    qres = ask(attack_pattern, "attack:ref_68633290849cc1e088bf2f49788d0f159e24afd60038d6ccaca5adfb977a07ac a dcterms:BibliographicResource.")
    assert bool(qres)

def test_ref_1_ext_id(attack_pattern):
    qres = ask(attack_pattern, "attack:ref_68633290849cc1e088bf2f49788d0f159e24afd60038d6ccaca5adfb977a07ac a dcterms:BibliographicResource; core:externalID \"CAPEC-163\".")
    assert bool(qres)

def test_ref_1_refsource(attack_pattern):
    qres = ask(attack_pattern, "attack:ref_68633290849cc1e088bf2f49788d0f159e24afd60038d6ccaca5adfb977a07ac a dcterms:BibliographicResource; cti:referenceSource \"capec\".")
    assert bool(qres)

def test_ref_1_id(attack_pattern):
    qres = ask(attack_pattern, "attack:ref_68633290849cc1e088bf2f49788d0f159e24afd60038d6ccaca5adfb977a07ac a dcterms:BibliographicResource; dcterms:identifier \"capec--capec-163\"^^xsd:NMTOKEN.")
    assert bool(qres)

def test_ref_1_source(attack_pattern):
    qres = ask(attack_pattern, "attack:ref_68633290849cc1e088bf2f49788d0f159e24afd60038d6ccaca5adfb977a07ac a dcterms:BibliographicResource; dcterms:source \"https://capec.mitre.org/data/definitions/163.html\"^^xsd:anyURI.")
    assert bool(qres)


def test_ref_2(attack_pattern):
    qres = ask(attack_pattern, "attack:ref_adec923c37ebdc6f054399e252eb9e8de7caaded59bf5466ac5242f81857233f a dcterms:BibliographicResource.")
    assert bool(qres)

def test_ref_2_ext_id(attack_pattern):
    qres = ask(attack_pattern, "attack:ref_adec923c37ebdc6f054399e252eb9e8de7caaded59bf5466ac5242f81857233f a dcterms:BibliographicResource; core:externalID \"T1566.002\".")
    assert bool(qres)

def test_ref_2_refsource(attack_pattern):
    qres = ask(attack_pattern, "attack:ref_adec923c37ebdc6f054399e252eb9e8de7caaded59bf5466ac5242f81857233f a dcterms:BibliographicResource; cti:referenceSource \"mitre-attack\".")
    assert bool(qres)

def test_ref_2_id(attack_pattern):
    qres = ask(attack_pattern, "attack:ref_adec923c37ebdc6f054399e252eb9e8de7caaded59bf5466ac5242f81857233f a dcterms:BibliographicResource; dcterms:identifier \"mitre-attack--t1566.002\"^^xsd:NMTOKEN.")
    assert bool(qres)

def test_ref_2_source(attack_pattern):
    qres = ask(attack_pattern, "attack:ref_adec923c37ebdc6f054399e252eb9e8de7caaded59bf5466ac5242f81857233f a dcterms:BibliographicResource; dcterms:source \"https://attack.mitre.org/techniques/T1566/002\"^^xsd:anyURI.")
    assert bool(qres)


def test_ref_3(attack_pattern):
    qres = ask(attack_pattern, "attack:ref_e6686c72e4cfda456dd06fa2fb3c02356d1df27fad1542713cc3f9b116420d96 a dcterms:BibliographicResource.")
    assert bool(qres)

def test_ref_3_bib(attack_pattern):
    qres = ask(attack_pattern, "attack:ref_e6686c72e4cfda456dd06fa2fb3c02356d1df27fad1542713cc3f9b116420d96 a dcterms:BibliographicResource; dcterms:bibliographicCitation \"Hacquebord, F.. (2017, April 25). Pawn Storm Abuses Open Authentication in Advanced Social Engineering Attacks. Retrieved October 4, 2019.\".")
    assert bool(qres)

def test_ref_3_refsource(attack_pattern):
    qres = ask(attack_pattern, "attack:ref_e6686c72e4cfda456dd06fa2fb3c02356d1df27fad1542713cc3f9b116420d96 a dcterms:BibliographicResource; cti:referenceSource \"Trend Micro Pawn Storm OAuth 2017\".")
    assert bool(qres)

def test_ref_3_id(attack_pattern):
    qres = ask(attack_pattern, "attack:ref_e6686c72e4cfda456dd06fa2fb3c02356d1df27fad1542713cc3f9b116420d96 a dcterms:BibliographicResource; dcterms:identifier \"trend-micro-pawn-storm-oauth-2017\"^^xsd:NMTOKEN.")
    assert bool(qres)

def test_ref_3_source(attack_pattern):
    qres = ask(attack_pattern, "attack:ref_e6686c72e4cfda456dd06fa2fb3c02356d1df27fad1542713cc3f9b116420d96 a dcterms:BibliographicResource; dcterms:source \"https://blog.trendmicro.com/trendlabs-security-intelligence/pawn-storm-abuses-open-authentication-advanced-social-engineering-attacks\"^^xsd:anyURI.")
    assert bool(qres)


def test_identity(attack_pattern):
    qres = ask(attack_pattern, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization .")
    assert bool(qres)

def test_identity_created(attack_pattern):
    qres = ask(attack_pattern, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:created \"2017-06-01T00:00:00+00:00\"^^xsd:dateTime.")
    assert bool(qres)

def test_identity_identifier(attack_pattern):
    qres = ask(attack_pattern, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:identifier \"identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5\".")
    assert bool(qres)

def test_identity_modified(attack_pattern):
    qres = ask(attack_pattern, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:modified \"2017-06-01T00:00:00+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_identity_rights(attack_pattern):
    qres = ask(attack_pattern, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:rights attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168.")
    assert bool(qres)

def test_identity_title(attack_pattern):
    qres = ask(attack_pattern, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; skos:prefLabel \"The MITRE Corporation\" .")
    assert bool(qres)


def test_marking(attack_pattern):
    qres = ask(attack_pattern, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement .")
    assert bool(qres)

def test_marking_rights(attack_pattern):
    qres = ask(attack_pattern, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dc:rights \"Copyright 2015-2020, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.\" .")
    assert bool(qres)

def test_marking_rights_statement(attack_pattern):
    qres = ask(attack_pattern, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dcterms:created \"2017-06-01T00:00:00+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_marking_creator(attack_pattern):
    qres = ask(attack_pattern, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dcterms:creator attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 .")
    assert bool(qres)

def test_marking_id(attack_pattern):
    qres = ask(attack_pattern, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dcterms:identifier \"marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168\" .")
    assert bool(qres)

##


def test_intrusion_set_0(intrusion_set):
    qres = ask(intrusion_set, "attack:intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662 a cti:IntrusionSet .")
    assert bool(qres)

def test_intrusion_set_1(intrusion_set):
    qres = ask(intrusion_set, "attack:intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662 a cti:IntrusionSet; dcterms:created \"2017-05-31T21:31:47.955000+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_intrusion_set_2(intrusion_set):
    qres = ask(intrusion_set, "attack:intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662 a cti:IntrusionSet; dcterms:creator attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 .")
    assert bool(qres)

def test_intrusion_set_3(intrusion_set):
    qres = ask(intrusion_set, "attack:intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662 a cti:IntrusionSet; skos:definition \"[APT1](https://attack.mitre.org/groups/G0006) is a Chinese threat group that has been attributed to the 2nd Bureau of the People’s Liberation Army (PLA) General Staff Department’s (GSD) 3rd Department, commonly known by its Military Unit Cover Designator (MUCD) as Unit 61398. (Citation: Mandiant APT1)\" .")
    assert bool(qres)

def test_intrusion_set_4(intrusion_set):
    qres = ask(intrusion_set, "attack:intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662 a cti:IntrusionSet; dcterms:identifier \"intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662\" .")
    assert bool(qres)

def test_intrusion_set_5(intrusion_set):
    qres = ask(intrusion_set, "attack:intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662 a cti:IntrusionSet; dcterms:modified \"2020-10-22T18:35:55.290000+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_intrusion_set_6(intrusion_set):
    qres = ask(intrusion_set, "attack:intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662 a cti:IntrusionSet; dcterms:references attack:ref_0558bfef1eddacb157bc5a88a175f04d216e2085bbf939e6607cdd971d6ed47b .")
    assert bool(qres)

def test_intrusion_set_7(intrusion_set):
    qres = ask(intrusion_set, "attack:intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662 a cti:IntrusionSet; dcterms:references attack:ref_26f4364de3ca2f5fc60ee8d1ca65f762a76349c58549a48730b6f85e8870e2b3 .")
    assert bool(qres)

def test_intrusion_set_8(intrusion_set):
    qres = ask(intrusion_set, "attack:intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662 a cti:IntrusionSet; dcterms:references attack:ref_62d45302b09f01d123c39945b81cc543b5fc4e9140da4dcf2b104c5267aa4ad8.")
    assert bool(qres)

def test_intrusion_set_9(intrusion_set):
    qres = ask(intrusion_set, "attack:intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662 a cti:IntrusionSet; dcterms:references attack:ref_65dd33aa6c6f7c1514b96641e57344ca19f5cd06e50a0689c90b44e88ddf0545 .")
    assert bool(qres)

def test_intrusion_set_10(intrusion_set):
    qres = ask(intrusion_set, "attack:intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662 a cti:IntrusionSet; dcterms:references attack:ref_760f53abb9bccf4b1f43fef0756d620c65579589e981699462d8233d8e4187bb .")
    assert bool(qres)

def test_intrusion_set_11(intrusion_set):
    qres = ask(intrusion_set, "attack:intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662 a cti:IntrusionSet; dcterms:references attack:ref_7617d39b304c1ef73796e8c755992fd9f756dc7dd1dede37ecf61a9045a8a9f7 .")
    assert bool(qres)

def test_intrusion_set_12(intrusion_set):
    qres = ask(intrusion_set, "attack:intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662 a cti:IntrusionSet; dcterms:references attack:ref_8c47999bd05fc33de7c7a7f07a4ef43a471173a4a37fba16414a8ce7e07c221f .")
    assert bool(qres)

def test_intrusion_set_13(intrusion_set):
    qres = ask(intrusion_set, "attack:intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662 a cti:IntrusionSet; dcterms:rights attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 .")
    assert bool(qres)

def test_intrusion_set_14(intrusion_set):
    qres = ask(intrusion_set, "attack:intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662 a cti:IntrusionSet; skos:prefLabel \"APT1\" .")
    assert bool(qres)



def test_intrusion_set_15(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_0558bfef1eddacb157bc5a88a175f04d216e2085bbf939e6607cdd971d6ed47b a dcterms:BibliographicResource .")
    assert bool(qres)

def test_intrusion_set_16(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_0558bfef1eddacb157bc5a88a175f04d216e2085bbf939e6607cdd971d6ed47b a dcterms:BibliographicResource; cti:referenceSource \"Mandiant APT1\" .")
    assert bool(qres)

def test_intrusion_set_17(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_0558bfef1eddacb157bc5a88a175f04d216e2085bbf939e6607cdd971d6ed47b a dcterms:BibliographicResource; dcterms:bibliographicCitation \"Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.\" .")
    assert bool(qres)

def test_intrusion_set_18(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_0558bfef1eddacb157bc5a88a175f04d216e2085bbf939e6607cdd971d6ed47b a dcterms:BibliographicResource; dcterms:identifier \"mandiant-apt1\"^^xsd:NMTOKEN .")
    assert bool(qres)

def test_intrusion_set_19(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_0558bfef1eddacb157bc5a88a175f04d216e2085bbf939e6607cdd971d6ed47b a dcterms:BibliographicResource; dcterms:source \"https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf\"^^xsd:anyURI .")
    assert bool(qres)



def test_intrusion_set_20(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_26f4364de3ca2f5fc60ee8d1ca65f762a76349c58549a48730b6f85e8870e2b3 a dcterms:BibliographicResource .")
    assert bool(qres)

def test_intrusion_set_21(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_26f4364de3ca2f5fc60ee8d1ca65f762a76349c58549a48730b6f85e8870e2b3 a dcterms:BibliographicResource; cti:referenceSource \"CrowdStrike Putter Panda\" .")
    assert bool(qres)

def test_intrusion_set_22(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_26f4364de3ca2f5fc60ee8d1ca65f762a76349c58549a48730b6f85e8870e2b3 a dcterms:BibliographicResource; dcterms:bibliographicCitation \"Crowdstrike Global Intelligence Team. (2014, June 9). CrowdStrike Intelligence Report: Putter Panda. Retrieved January 22, 2016.\" .")
    assert bool(qres)

def test_intrusion_set_23(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_26f4364de3ca2f5fc60ee8d1ca65f762a76349c58549a48730b6f85e8870e2b3 a dcterms:BibliographicResource; dcterms:identifier \"crowdstrike-putter-panda\"^^xsd:NMTOKEN .")
    assert bool(qres)

def test_intrusion_set_24(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_26f4364de3ca2f5fc60ee8d1ca65f762a76349c58549a48730b6f85e8870e2b3 a dcterms:BibliographicResource; dcterms:source \"http://cdn0.vox-cdn.com/assets/4589853/crowdstrike-intelligence-report-putter-panda.original.pdf\"^^xsd:anyURI .")
    assert bool(qres)


def test_intrusion_set_25(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_62d45302b09f01d123c39945b81cc543b5fc4e9140da4dcf2b104c5267aa4ad8 a dcterms:BibliographicResource .")
    assert bool(qres)

def test_intrusion_set_26(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_62d45302b09f01d123c39945b81cc543b5fc4e9140da4dcf2b104c5267aa4ad8 a dcterms:BibliographicResource; cti:referenceSource \"Comment Panda\" .")
    assert bool(qres)

def test_intrusion_set_27(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_62d45302b09f01d123c39945b81cc543b5fc4e9140da4dcf2b104c5267aa4ad8 a dcterms:BibliographicResource; dcterms:bibliographicCitation \"(Citation: CrowdStrike Putter Panda)\" .")
    assert bool(qres)

def test_intrusion_set_28(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_62d45302b09f01d123c39945b81cc543b5fc4e9140da4dcf2b104c5267aa4ad8 a dcterms:BibliographicResource; dcterms:identifier \"comment-panda\"^^xsd:NMTOKEN .")
    assert bool(qres)


def test_intrusion_set_29(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_65dd33aa6c6f7c1514b96641e57344ca19f5cd06e50a0689c90b44e88ddf0545 a dcterms:BibliographicResource .")
    assert bool(qres)

def test_intrusion_set_30(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_65dd33aa6c6f7c1514b96641e57344ca19f5cd06e50a0689c90b44e88ddf0545 a dcterms:BibliographicResource; cti:referenceSource \"Comment Group\" .")
    assert bool(qres)

def test_intrusion_set_31(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_65dd33aa6c6f7c1514b96641e57344ca19f5cd06e50a0689c90b44e88ddf0545 a dcterms:BibliographicResource; dcterms:bibliographicCitation \"(Citation: Mandiant APT1)\" .")
    assert bool(qres)

def test_intrusion_set_32(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_65dd33aa6c6f7c1514b96641e57344ca19f5cd06e50a0689c90b44e88ddf0545 a dcterms:BibliographicResource; dcterms:identifier \"comment-group\"^^xsd:NMTOKEN .")
    assert bool(qres)


def test_intrusion_set_33(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_760f53abb9bccf4b1f43fef0756d620c65579589e981699462d8233d8e4187bb a dcterms:BibliographicResource .")
    assert bool(qres)

def test_intrusion_set_34(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_760f53abb9bccf4b1f43fef0756d620c65579589e981699462d8233d8e4187bb a dcterms:BibliographicResource; cti:referenceSource \"Comment Crew\" .")
    assert bool(qres)

def test_intrusion_set_35(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_760f53abb9bccf4b1f43fef0756d620c65579589e981699462d8233d8e4187bb a dcterms:BibliographicResource; dcterms:bibliographicCitation \"(Citation: Mandiant APT1)\" .")
    assert bool(qres)

def test_intrusion_set_36(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_760f53abb9bccf4b1f43fef0756d620c65579589e981699462d8233d8e4187bb a dcterms:BibliographicResource; dcterms:identifier \"comment-crew\"^^xsd:NMTOKEN.")
    assert bool(qres)


def test_intrusion_set_37(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_7617d39b304c1ef73796e8c755992fd9f756dc7dd1dede37ecf61a9045a8a9f7 a dcterms:BibliographicResource .")
    assert bool(qres)

def test_intrusion_set_38(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_7617d39b304c1ef73796e8c755992fd9f756dc7dd1dede37ecf61a9045a8a9f7 a dcterms:BibliographicResource; core:externalID \"G0006\" .")
    assert bool(qres)

def test_intrusion_set_39(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_7617d39b304c1ef73796e8c755992fd9f756dc7dd1dede37ecf61a9045a8a9f7 a dcterms:BibliographicResource; cti:referenceSource \"mitre-attack\" .")
    assert bool(qres)

def test_intrusion_set_40(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_7617d39b304c1ef73796e8c755992fd9f756dc7dd1dede37ecf61a9045a8a9f7 a dcterms:BibliographicResource; dcterms:identifier \"mitre-attack--g0006\"^^xsd:NMTOKEN .")
    assert bool(qres)

def test_intrusion_set_41(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_7617d39b304c1ef73796e8c755992fd9f756dc7dd1dede37ecf61a9045a8a9f7 a dcterms:BibliographicResource; dcterms:source \"https://attack.mitre.org/groups/G0006\"^^xsd:anyURI .")
    assert bool(qres)


def test_intrusion_set_42(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_8c47999bd05fc33de7c7a7f07a4ef43a471173a4a37fba16414a8ce7e07c221f a dcterms:BibliographicResource .")
    assert bool(qres)

def test_intrusion_set_43(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_8c47999bd05fc33de7c7a7f07a4ef43a471173a4a37fba16414a8ce7e07c221f a dcterms:BibliographicResource; cti:referenceSource \"APT1\" .")
    assert bool(qres)

def test_intrusion_set_44(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_8c47999bd05fc33de7c7a7f07a4ef43a471173a4a37fba16414a8ce7e07c221f a dcterms:BibliographicResource; dcterms:bibliographicCitation \"(Citation: Mandiant APT1)\" .")
    assert bool(qres)

def test_intrusion_set_45(intrusion_set):
    qres = ask(intrusion_set, "attack:ref_8c47999bd05fc33de7c7a7f07a4ef43a471173a4a37fba16414a8ce7e07c221f a dcterms:BibliographicResource; dcterms:identifier \"apt1\"^^xsd:NMTOKEN .")
    assert bool(qres)


def test_intrusion_set_46(intrusion_set):
    qres = ask(intrusion_set, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization .")
    assert bool(qres)

def test_intrusion_set_47(intrusion_set):
    qres = ask(intrusion_set, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:created \"2017-06-01T00:00:00+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_intrusion_set_48(intrusion_set):
    qres = ask(intrusion_set, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:identifier \"identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5\" .")
    assert bool(qres)

def test_intrusion_set_49(intrusion_set):
    qres = ask(intrusion_set, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:modified \"2017-06-01T00:00:00+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_intrusion_set_50(intrusion_set):
    qres = ask(intrusion_set, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:rights attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 .")
    assert bool(qres)

def test_intrusion_set_51(intrusion_set):
    qres = ask(intrusion_set, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; skos:prefLabel \"The MITRE Corporation\" .")
    assert bool(qres)


def test_intrusion_set_52(intrusion_set):
    qres = ask(intrusion_set, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement .")
    assert bool(qres)

def test_intrusion_set_53(intrusion_set):
    qres = ask(intrusion_set, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dc:rights \"Copyright 2015-2020, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.\" .")
    assert bool(qres)

def test_intrusion_set_54(intrusion_set):
    qres = ask(intrusion_set, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dcterms:created \"2017-06-01T00:00:00+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_intrusion_set_55(intrusion_set):
    qres = ask(intrusion_set, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dcterms:creator attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 .")
    assert bool(qres)

def test_intrusion_set_56(intrusion_set):
    qres = ask(intrusion_set, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dcterms:identifier \"marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168\" .")
    assert bool(qres)


def test_pre_0(pre):
    qres = ask(pre, "attack:attack-pattern--0458aab9-ad42-4eac-9e22-706a95bafee2 a cti:AttackPattern .")
    assert bool(qres)

def test_pre_1(pre):
    qres = ask(pre, "attack:attack-pattern--0458aab9-ad42-4eac-9e22-706a95bafee2 a cti:AttackPattern; cti:killChainPhase attack:kill-chain-phase__mitre-attack__resource-development .")
    assert bool(qres)

def test_pre_2(pre):
    qres = ask(pre, "attack:attack-pattern--0458aab9-ad42-4eac-9e22-706a95bafee2 a cti:AttackPattern; dcterms:created \"2020-09-30T16:37:40.271000+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_pre_3(pre):
    qres = ask(pre, "attack:attack-pattern--0458aab9-ad42-4eac-9e22-706a95bafee2 a cti:AttackPattern; dcterms:creator attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 .")
    assert bool(qres)

def test_pre_4(pre):
    qres = ask(pre, "attack:attack-pattern--0458aab9-ad42-4eac-9e22-706a95bafee2 a cti:AttackPattern; skos:definition ?description .")
    assert bool(qres)

def test_pre_5(pre):
    qres = ask(pre, "attack:attack-pattern--0458aab9-ad42-4eac-9e22-706a95bafee2 a cti:AttackPattern; dcterms:identifier \"attack-pattern--0458aab9-ad42-4eac-9e22-706a95bafee2\" .")
    assert bool(qres)

def test_pre_6(pre):
    qres = ask(pre, "attack:attack-pattern--0458aab9-ad42-4eac-9e22-706a95bafee2 a cti:AttackPattern; dcterms:modified \"2020-10-22T17:59:17.606000+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_pre_7(pre):
    qres = ask(pre, "attack:attack-pattern--0458aab9-ad42-4eac-9e22-706a95bafee2 a cti:AttackPattern; dcterms:references attack:ref_b2dc9c5822dfceab09c60c02ac3e77b2101c14c03ff1152315789dec1e42a22c .")
    assert bool(qres)

def test_pre_8(pre):
    qres = ask(pre, "attack:attack-pattern--0458aab9-ad42-4eac-9e22-706a95bafee2 a cti:AttackPattern; dcterms:references attack:ref_ecc452824f05f3b2cfba1d9dab904885b6bb2b0fdd87ec1775571928ee8e65dd .")
    assert bool(qres)

def test_pre_9(pre):
    qres = ask(pre, "attack:attack-pattern--0458aab9-ad42-4eac-9e22-706a95bafee2 a cti:AttackPattern; dcterms:rights attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 .")
    assert bool(qres)

def test_pre_10(pre):
    qres = ask(pre, "attack:attack-pattern--0458aab9-ad42-4eac-9e22-706a95bafee2 a cti:AttackPattern; skos:prefLabel \"Acquire Infrastructure\" .")
    assert bool(qres)


def test_pre_11(pre):
    qres = ask(pre, "attack:kill-chain-phase__mitre-attack__resource-development a cti:KillChainPhase .")
    assert bool(qres)

def test_pre_12(pre):
    qres = ask(pre, "attack:kill-chain-phase__mitre-attack__resource-development a cti:KillChainPhase; cti:killChainName \"mitre-attack\" .")
    assert bool(qres)

def test_pre_13(pre):
    qres = ask(pre, "attack:kill-chain-phase__mitre-attack__resource-development a cti:KillChainPhase; skos:prefLabel \"resource-development\" .")
    assert bool(qres)


def test_pre_14(pre):
    qres = ask(pre, "attack:ref_b2dc9c5822dfceab09c60c02ac3e77b2101c14c03ff1152315789dec1e42a22c a dcterms:BibliographicResource .")
    assert bool(qres)

def test_pre_15(pre):
    qres = ask(pre, "attack:ref_b2dc9c5822dfceab09c60c02ac3e77b2101c14c03ff1152315789dec1e42a22c a dcterms:BibliographicResource; core:externalID \"T1583\" .")
    assert bool(qres)

def test_pre_16(pre):
    qres = ask(pre, "attack:ref_b2dc9c5822dfceab09c60c02ac3e77b2101c14c03ff1152315789dec1e42a22c a dcterms:BibliographicResource; cti:referenceSource \"mitre-attack\" .")
    assert bool(qres)

def test_pre_17(pre):
    qres = ask(pre, "attack:ref_b2dc9c5822dfceab09c60c02ac3e77b2101c14c03ff1152315789dec1e42a22c a dcterms:BibliographicResource; dcterms:identifier \"mitre-attack--t1583\"^^xsd:NMTOKEN .")
    assert bool(qres)

def test_pre_18(pre):
    qres = ask(pre, "attack:ref_b2dc9c5822dfceab09c60c02ac3e77b2101c14c03ff1152315789dec1e42a22c a dcterms:BibliographicResource; dcterms:source \"https://attack.mitre.org/techniques/T1583\"^^xsd:anyURI .")
    assert bool(qres)


def test_pre_19(pre):
    qres = ask(pre, "attack:ref_ecc452824f05f3b2cfba1d9dab904885b6bb2b0fdd87ec1775571928ee8e65dd a dcterms:BibliographicResource .")
    assert bool(qres)

def test_pre_20(pre):
    qres = ask(pre, "attack:ref_ecc452824f05f3b2cfba1d9dab904885b6bb2b0fdd87ec1775571928ee8e65dd a dcterms:BibliographicResource; cti:referenceSource \"TrendmicroHideoutsLease\" .")
    assert bool(qres)

def test_pre_21(pre):
    qres = ask(pre, "attack:ref_ecc452824f05f3b2cfba1d9dab904885b6bb2b0fdd87ec1775571928ee8e65dd a dcterms:BibliographicResource; dcterms:bibliographicCitation \"Max Goncharov. (2015, July 15). Criminal Hideouts for Lease: Bulletproof Hosting Services. Retrieved March 6, 2017.\" .")
    assert bool(qres)

def test_pre_22(pre):
    qres = ask(pre, "attack:ref_ecc452824f05f3b2cfba1d9dab904885b6bb2b0fdd87ec1775571928ee8e65dd a dcterms:BibliographicResource; dcterms:identifier \"trendmicrohideoutslease\"^^xsd:NMTOKEN .")
    assert bool(qres)

def test_pre_23(pre):
    qres = ask(pre, "attack:ref_ecc452824f05f3b2cfba1d9dab904885b6bb2b0fdd87ec1775571928ee8e65dd a dcterms:BibliographicResource; dcterms:source \"https://documents.trendmicro.com/assets/wp/wp-criminal-hideouts-for-lease.pdf\"^^xsd:anyURI .")
    assert bool(qres)


def test_pre_24(pre):
    qres = ask(pre, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization .")
    assert bool(qres)

def test_pre_25(pre):
    qres = ask(pre, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:created \"2017-06-01T00:00:00+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_pre_26(pre):
    qres = ask(pre, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:identifier \"identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5\" .")
    assert bool(qres)

def test_pre_27(pre):
    qres = ask(pre, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:modified \"2017-06-01T00:00:00+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_pre_28(pre):
    qres = ask(pre, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:rights attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 .")
    assert bool(qres)

def test_pre_29(pre):
    qres = ask(pre, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; skos:prefLabel \"The MITRE Corporation\" .")
    assert bool(qres)


def test_pre_30(pre):
    qres = ask(pre, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement .")
    assert bool(qres)

def test_pre_31(pre):
    qres = ask(pre, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dc:rights \"Copyright 2015-2020, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.\" .")
    assert bool(qres)

def test_pre_32(pre):
    qres = ask(pre, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dcterms:created \"2017-06-01T00:00:00+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_pre_33(pre):
    qres = ask(pre, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dcterms:creator attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 .")
    assert bool(qres)

def test_pre_34(pre):
    qres = ask(pre, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dcterms:identifier \"marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168\" .")
    assert bool(qres)


def test_coa_0(course_of_action):
    qres = ask(course_of_action, "attack:course-of-action--3e9f8875-d2f7-4380-a578-84393bd3b025 a cti:CourseOfAction .")
    assert bool(qres)

def test_coa_1(course_of_action):
    qres = ask(course_of_action, "attack:course-of-action--3e9f8875-d2f7-4380-a578-84393bd3b025 a cti:CourseOfAction; cti:deprecated true .")
    assert bool(qres)

def test_coa_2(course_of_action):
    qres = ask(course_of_action, "attack:course-of-action--3e9f8875-d2f7-4380-a578-84393bd3b025 a cti:CourseOfAction; dcterms:created \"2018-10-17T00:14:20.652000+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_coa_3(course_of_action):
    qres = ask(course_of_action, "attack:course-of-action--3e9f8875-d2f7-4380-a578-84393bd3b025 a cti:CourseOfAction; dcterms:creator attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 .")
    assert bool(qres)

def test_coa_4(course_of_action):
    qres = ask(course_of_action, "attack:course-of-action--3e9f8875-d2f7-4380-a578-84393bd3b025 a cti:CourseOfAction; skos:definition ?description .")
    assert bool(qres)

def test_coa_5(course_of_action):
    qres = ask(course_of_action, "attack:course-of-action--3e9f8875-d2f7-4380-a578-84393bd3b025 a cti:CourseOfAction; dcterms:identifier \"course-of-action--3e9f8875-d2f7-4380-a578-84393bd3b025\" .")
    assert bool(qres)

def test_coa_6(course_of_action):
    qres = ask(course_of_action, "attack:course-of-action--3e9f8875-d2f7-4380-a578-84393bd3b025 a cti:CourseOfAction; dcterms:modified \"2020-01-17T16:46:19.274000+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_coa_7(course_of_action):
    qres = ask(course_of_action, "attack:course-of-action--3e9f8875-d2f7-4380-a578-84393bd3b025 a cti:CourseOfAction; dcterms:references attack:ref_10cd53276fa4a04c57a6245455d530c7351fb0f1ff953f934da3a351d236063d .")
    assert bool(qres)

def test_coa_8(course_of_action):
    qres = ask(course_of_action, "attack:course-of-action--3e9f8875-d2f7-4380-a578-84393bd3b025 a cti:CourseOfAction; dcterms:references attack:ref_5837614f71ddb654ecc9b572035f894bdfbf4af1d7219e61a150bf51d21487fe .")
    assert bool(qres)

def test_coa_9(course_of_action):
    qres = ask(course_of_action, "attack:course-of-action--3e9f8875-d2f7-4380-a578-84393bd3b025 a cti:CourseOfAction; dcterms:rights attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 .")
    assert bool(qres)

def test_coa_10(course_of_action):
    qres = ask(course_of_action, "attack:course-of-action--3e9f8875-d2f7-4380-a578-84393bd3b025 a cti:CourseOfAction; skos:prefLabel \"Windows Remote Management Mitigation\" .")
    assert bool(qres)


def test_coa_11(course_of_action):
    qres = ask(course_of_action, "attack:ref_10cd53276fa4a04c57a6245455d530c7351fb0f1ff953f934da3a351d236063d a dcterms:BibliographicResource .")
    assert bool(qres)

def test_coa_12(course_of_action):
    qres = ask(course_of_action, "attack:ref_10cd53276fa4a04c57a6245455d530c7351fb0f1ff953f934da3a351d236063d a dcterms:BibliographicResource; core:externalID \"T1028\" .")
    assert bool(qres)

def test_coa_13(course_of_action):
    qres = ask(course_of_action, "attack:ref_10cd53276fa4a04c57a6245455d530c7351fb0f1ff953f934da3a351d236063d a dcterms:BibliographicResource; cti:referenceSource \"mitre-attack\" .")
    assert bool(qres)

def test_coa_14(course_of_action):
    qres = ask(course_of_action, "attack:ref_10cd53276fa4a04c57a6245455d530c7351fb0f1ff953f934da3a351d236063d a dcterms:BibliographicResource; dcterms:identifier \"mitre-attack--t1028\"^^xsd:NMTOKEN .")
    assert bool(qres)

def test_coa_15(course_of_action):
    qres = ask(course_of_action, "attack:ref_10cd53276fa4a04c57a6245455d530c7351fb0f1ff953f934da3a351d236063d a dcterms:BibliographicResource; dcterms:source \"https://attack.mitre.org/mitigations/T1028\"^^xsd:anyURI .")
    assert bool(qres)


def test_coa_21(course_of_action):
    qres = ask(course_of_action, "attack:ref_5837614f71ddb654ecc9b572035f894bdfbf4af1d7219e61a150bf51d21487fe a dcterms:BibliographicResource ." )
    assert bool(qres)

def test_coa_22(course_of_action):
    qres = ask(course_of_action, "attack:ref_5837614f71ddb654ecc9b572035f894bdfbf4af1d7219e61a150bf51d21487fe a dcterms:BibliographicResource; cti:referenceSource \"NSA Spotting\" ." )
    assert bool(qres)

def test_coa_23(course_of_action):
    qres = ask(course_of_action, "attack:ref_5837614f71ddb654ecc9b572035f894bdfbf4af1d7219e61a150bf51d21487fe a dcterms:BibliographicResource; dcterms:bibliographicCitation \"National Security Agency/Central Security Service Information Assurance Directorate. (2015, August 7). Spotting the Adversary with Windows Event Log Monitoring. Retrieved September 6, 2018.\" ." )
    assert bool(qres)

def test_coa_24(course_of_action):
    qres = ask(course_of_action, "attack:ref_5837614f71ddb654ecc9b572035f894bdfbf4af1d7219e61a150bf51d21487fe a dcterms:BibliographicResource; dcterms:identifier \"nsa-spotting\"^^xsd:NMTOKEN ." )
    assert bool(qres)

def test_coa_25(course_of_action):
    qres = ask(course_of_action, "attack:ref_5837614f71ddb654ecc9b572035f894bdfbf4af1d7219e61a150bf51d21487fe a dcterms:BibliographicResource; dcterms:source \"https://apps.nsa.gov/iaarchive/library/reports/spotting-the-adversary-with-windows-event-log-monitoring.cfm\"^^xsd:anyURI ." )
    assert bool(qres)


def test_coa_31(course_of_action):
    qres = ask(course_of_action, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization .")
    assert bool(qres)

def test_coa_32(course_of_action):
    qres = ask(course_of_action, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:created \"2017-06-01T00:00:00+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_coa_33(course_of_action):
    qres = ask(course_of_action, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:identifier \"identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5\" .")
    assert bool(qres)

def test_coa_34(course_of_action):
    qres = ask(course_of_action, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:modified \"2017-06-01T00:00:00+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_coa_35(course_of_action):
    qres = ask(course_of_action, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:rights attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 .")
    assert bool(qres)

def test_coa_36(course_of_action):
    qres = ask(course_of_action, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; skos:prefLabel \"The MITRE Corporation\" .")
    assert bool(qres)


def test_coa_41(course_of_action):
    qres = ask(course_of_action, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement .")
    assert bool(qres)

def test_coa_42(course_of_action):
    qres = ask(course_of_action, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dc:rights \"Copyright 2015-2020, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.\" .")
    assert bool(qres)

def test_coa_43(course_of_action):
    qres = ask(course_of_action, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dcterms:created \"2017-06-01T00:00:00+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_coa_44(course_of_action):
    qres = ask(course_of_action, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dcterms:creator attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 .")
    assert bool(qres)

def test_coa_45(course_of_action):
    qres = ask(course_of_action, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dcterms:identifier \"marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168\" .")
    assert bool(qres)


def test_relationship_0(relationship):
    qres = ask(relationship, "attack:ref_5101a421f9327bed0ca06ada8de2016b3a8ec1acc194803605b22ece0bd320d0 a dcterms:BibliographicResource .")
    assert bool(qres)

def test_relationship_1(relationship):
    qres = ask(relationship, "attack:ref_5101a421f9327bed0ca06ada8de2016b3a8ec1acc194803605b22ece0bd320d0 a dcterms:BibliographicResource; core:externalID \"T1094\" .")
    assert bool(qres)

def test_relationship_2(relationship):
    qres = ask(relationship, "attack:ref_5101a421f9327bed0ca06ada8de2016b3a8ec1acc194803605b22ece0bd320d0 a dcterms:BibliographicResource; cti:referenceSource \"mitre-attack\" .")
    assert bool(qres)

def test_relationship_3(relationship):
    qres = ask(relationship, "attack:ref_5101a421f9327bed0ca06ada8de2016b3a8ec1acc194803605b22ece0bd320d0 a dcterms:BibliographicResource; dcterms:identifier \"mitre-attack--t1094\"^^xsd:NMTOKEN .")
    assert bool(qres)

def test_relationship_4(relationship):
    qres = ask(relationship, "attack:ref_5101a421f9327bed0ca06ada8de2016b3a8ec1acc194803605b22ece0bd320d0 a dcterms:BibliographicResource; dcterms:source \"https://attack.mitre.org/techniques/T1094\"^^xsd:anyURI .")
    assert bool(qres)


def test_relationship_11(relationship):
    qres = ask(relationship, "attack:ref_6157d34c0500043adb0a408315fa796dc0803c8d63795bddb5ceea09f0d86844 a dcterms:BibliographicResource .")
    assert bool(qres)

def test_relationship_12(relationship):
    qres = ask(relationship, "attack:ref_6157d34c0500043adb0a408315fa796dc0803c8d63795bddb5ceea09f0d86844 a dcterms:BibliographicResource; core:externalID \"S0084\" .")
    assert bool(qres)

def test_relationship_13(relationship):
    qres = ask(relationship, "attack:ref_6157d34c0500043adb0a408315fa796dc0803c8d63795bddb5ceea09f0d86844 a dcterms:BibliographicResource; cti:referenceSource \"mitre-attack\" .")
    assert bool(qres)

def test_relationship_14(relationship):
    qres = ask(relationship, "attack:ref_6157d34c0500043adb0a408315fa796dc0803c8d63795bddb5ceea09f0d86844 a dcterms:BibliographicResource; dcterms:identifier \"mitre-attack--s0084\"^^xsd:NMTOKEN .")
    assert bool(qres)

def test_relationship_15(relationship):
    qres = ask(relationship, "attack:ref_6157d34c0500043adb0a408315fa796dc0803c8d63795bddb5ceea09f0d86844 a dcterms:BibliographicResource; dcterms:source \"https://attack.mitre.org/software/S0084\"^^xsd:anyURI.")
    assert bool(qres)


def test_relationship_21(relationship):
    qres = ask(relationship, "attack:ref_73df1a62ded98a7662059dc6d43efac817cfebe68c03dd6b38a3dba47fa0d68f a dcterms:BibliographicResource .")
    assert bool(qres)

def test_relationship_22(relationship):
    qres = ask(relationship, "attack:ref_73df1a62ded98a7662059dc6d43efac817cfebe68c03dd6b38a3dba47fa0d68f a dcterms:BibliographicResource; cti:referenceSource \"University of Birmingham C2\" .")
    assert bool(qres)

def test_relationship_23(relationship):
    qres = ask(relationship, "attack:ref_73df1a62ded98a7662059dc6d43efac817cfebe68c03dd6b38a3dba47fa0d68f a dcterms:BibliographicResource; dcterms:bibliographicCitation \"Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.\" .")
    assert bool(qres)

def test_relationship_24(relationship):
    qres = ask(relationship, "attack:ref_73df1a62ded98a7662059dc6d43efac817cfebe68c03dd6b38a3dba47fa0d68f a dcterms:BibliographicResource; dcterms:identifier \"university-of-birmingham-c2\"^^xsd:NMTOKEN .")
    assert bool(qres)

def test_relationship_25(relationship):
    qres = ask(relationship, "attack:ref_73df1a62ded98a7662059dc6d43efac817cfebe68c03dd6b38a3dba47fa0d68f a dcterms:BibliographicResource; dcterms:source \"https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf\"^^xsd:anyURI .")
    assert bool(qres)


def test_relationship_31(relationship):
    qres = ask(relationship, "attack:relationship--00b84a9d-8f8c-4b12-9522-ce2d1a324c25 a cti:UsesRelationship .")
    assert bool(qres)

def test_relationship_32(relationship):
    qres = ask(relationship, "attack:relationship--00b84a9d-8f8c-4b12-9522-ce2d1a324c25 a cti:UsesRelationship; cti:relationSource attack:malware--e1161124-f22e-487f-9d5f-ed8efc8dcd61 .")
    assert bool(qres)

def test_relationship_33(relationship):
    qres = ask(relationship, "attack:relationship--00b84a9d-8f8c-4b12-9522-ce2d1a324c25 a cti:UsesRelationship; cti:relationTarget attack:attack-pattern--f72eb8a8-cd4c-461d-a814-3f862befbf00 .")
    assert bool(qres)

def test_relationship_34(relationship):
    qres = ask(relationship, "attack:relationship--00b84a9d-8f8c-4b12-9522-ce2d1a324c25 a cti:UsesRelationship; dcterms:created \"2018-10-17T00:14:20.652000+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_relationship_35(relationship):
    qres = ask(relationship, "attack:relationship--00b84a9d-8f8c-4b12-9522-ce2d1a324c25 a cti:UsesRelationship; dcterms:creator attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 .")
    assert bool(qres)

def test_relationship_36(relationship):
    qres = ask(relationship, "attack:relationship--00b84a9d-8f8c-4b12-9522-ce2d1a324c25 a cti:UsesRelationship; skos:definition \"[Mis-Type](https://attack.mitre.org/software/S0084) network traffic can communicate over a raw socket.(Citation: Cylance Dust Storm)\" .")
    assert bool(qres)

def test_relationship_37(relationship):
    qres = ask(relationship, "attack:relationship--00b84a9d-8f8c-4b12-9522-ce2d1a324c25 a cti:UsesRelationship; dcterms:identifier \"relationship--00b84a9d-8f8c-4b12-9522-ce2d1a324c25\" .")
    assert bool(qres)

def test_relationship_38(relationship):
    qres = ask(relationship, "attack:relationship--00b84a9d-8f8c-4b12-9522-ce2d1a324c25 a cti:UsesRelationship; dcterms:modified \"2020-02-11T16:23:56.676000+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_relationship_39(relationship):
    qres = ask(relationship, "attack:relationship--00b84a9d-8f8c-4b12-9522-ce2d1a324c25 a cti:UsesRelationship; dcterms:references attack:ref_8b666ea9985076cf3d380ce602ffb3056179cbafbe914fb4df991b71ac7d9506 .")
    assert bool(qres)

def test_relationship_40(relationship):
    qres = ask(relationship, "attack:relationship--00b84a9d-8f8c-4b12-9522-ce2d1a324c25 a cti:UsesRelationship; dcterms:rights attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 .")
    assert bool(qres)

     
def test_relationship_51(relationship):
    qres = ask(relationship, "attack:ref_8b666ea9985076cf3d380ce602ffb3056179cbafbe914fb4df991b71ac7d9506 a dcterms:BibliographicResource .")
    assert bool(qres)

def test_relationship_52(relationship):
    qres = ask(relationship, "attack:ref_8b666ea9985076cf3d380ce602ffb3056179cbafbe914fb4df991b71ac7d9506 a dcterms:BibliographicResource; cti:referenceSource \"Cylance Dust Storm\" .")
    assert bool(qres)

def test_relationship_53(relationship):
    qres = ask(relationship, "attack:ref_8b666ea9985076cf3d380ce602ffb3056179cbafbe914fb4df991b71ac7d9506 a dcterms:BibliographicResource; dcterms:bibliographicCitation \"Gross, J. (2016, February 23). Operation Dust Storm. Retrieved September 19, 2017.\" .")
    assert bool(qres)

def test_relationship_54(relationship):
    qres = ask(relationship, "attack:ref_8b666ea9985076cf3d380ce602ffb3056179cbafbe914fb4df991b71ac7d9506 a dcterms:BibliographicResource; dcterms:identifier \"cylance-dust-storm\"^^xsd:NMTOKEN .")
    assert bool(qres)

def test_relationship_55(relationship):
    qres = ask(relationship, "attack:ref_8b666ea9985076cf3d380ce602ffb3056179cbafbe914fb4df991b71ac7d9506 a dcterms:BibliographicResource; dcterms:source \"https://www.cylance.com/content/dam/cylance/pdfs/reports/Op_Dust_Storm_Report.pdf\"^^xsd:anyURI .")
    assert bool(qres)

    
def test_relationship_61(relationship):
    qres = ask(relationship, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization .")
    assert bool(qres)

def test_relationship_62(relationship):
    qres = ask(relationship, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:created \"2017-06-01T00:00:00+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_relationship_63(relationship):
    qres = ask(relationship, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:identifier \"identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5\" .")
    assert bool(qres)

def test_relationship_64(relationship):
    qres = ask(relationship, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:modified \"2017-06-01T00:00:00+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_relationship_65(relationship):
    qres = ask(relationship, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; dcterms:rights attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 .")
    assert bool(qres)

def test_relationship_66(relationship):
    qres = ask(relationship, "attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 a foaf:Organization; skos:prefLabel \"The MITRE Corporation\" .")
    assert bool(qres)


def test_relationship_71(relationship):
    qres = ask(relationship, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement .")
    assert bool(qres)

def test_relationship_72(relationship):
    qres = ask(relationship, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dc:rights \"Copyright 2015-2020, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.\" .")
    assert bool(qres)

def test_relationship_73(relationship):
    qres = ask(relationship, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dcterms:created \"2017-06-01T00:00:00+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_relationship_74(relationship):
    qres = ask(relationship, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dcterms:creator attack:identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5 .")
    assert bool(qres)

def test_relationship_75(relationship):
    qres = ask(relationship, "attack:marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 a dcterms:RightsStatement; dcterms:identifier \"marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168\" .")
    assert bool(qres)


def test_relationship_81(relationship):
    qres = ask(relationship, "attack:attack-pattern--f72eb8a8-cd4c-461d-a814-3f862befbf00 a cti:AttackPattern .")
    assert bool(qres)

def test_relationship_82(relationship):
    qres = ask(relationship, "attack:attack-pattern--f72eb8a8-cd4c-461d-a814-3f862befbf00 a cti:AttackPattern; cti:revoked true .")
    assert bool(qres)

def test_relationship_83(relationship):
    qres = ask(relationship, "attack:attack-pattern--f72eb8a8-cd4c-461d-a814-3f862befbf00 a cti:AttackPattern; dcterms:created \"2017-05-31T21:31:10.314000+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_relationship_84(relationship):
    qres = ask(relationship, "attack:attack-pattern--f72eb8a8-cd4c-461d-a814-3f862befbf00 a cti:AttackPattern; dcterms:identifier \"attack-pattern--f72eb8a8-cd4c-461d-a814-3f862befbf00\" .")
    assert bool(qres)

def test_relationship_85(relationship):
    qres = ask(relationship, "attack:attack-pattern--f72eb8a8-cd4c-461d-a814-3f862befbf00 a cti:AttackPattern; dcterms:modified \"2020-03-20T19:03:04.295000+00:00\"^^xsd:dateTime .")
    assert bool(qres)

def test_relationship_86(relationship):
    qres = ask(relationship, "attack:attack-pattern--f72eb8a8-cd4c-461d-a814-3f862befbf00 a cti:AttackPattern; dcterms:references attack:ref_5101a421f9327bed0ca06ada8de2016b3a8ec1acc194803605b22ece0bd320d0 .")
    assert bool(qres)

def test_relationship_87(relationship):
    qres = ask(relationship, "attack:attack-pattern--f72eb8a8-cd4c-461d-a814-3f862befbf00 a cti:AttackPattern; dcterms:references attack:ref_73df1a62ded98a7662059dc6d43efac817cfebe68c03dd6b38a3dba47fa0d68f .")
    assert bool(qres)

def test_relationship_88(relationship):
    qres = ask(relationship, "attack:attack-pattern--f72eb8a8-cd4c-461d-a814-3f862befbf00 a cti:AttackPattern; skos:prefLabel \"Custom Command and Control Protocol\" .")
    assert bool(qres)

#def test_relationship_91(relationship):
#    qres = ask(relationship, "?g a cti:RelationshipGraph")
#    assert bool(qres)


#SELECT ?g ?s ?p ?o
#WHERE {
#    GRAPH ?g {
#        ?s ?p ?o
#    } .
#    ?g a cti:RelationshipGraph .
#}
#def test_relationship_92(relationship):
#    qres = ask(relationship, "{ attack:malware--e1161124-f22e-487f-9d5f-ed8efc8dcd61 cti:uses attack:attack-pattern--f72eb8a8-cd4c-461d-a814-3f862befbf00 . } dcterms:created \"2018-10-17T00:14:20.652000+00:00\"^^xsd:dateTime")
#    assert bool(qres)

