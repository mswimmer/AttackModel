import hashlib
import logging
from rdflib import URIRef, BNode, Literal, ConjunctiveGraph, Graph, Namespace
from rdflib.namespace import RDF, RDFS, XSD, DC, DCTERMS, FOAF, SKOS
from rdflib.plugins.memory import IOMemory
from rdflib.plugins.sparql import prepareQuery
import stix2
from taxii2client.v20 import Server, Collection

logging.basicConfig(level=logging.DEBUG)

CORE = Namespace("http://ontologies.ti-semantics.com/core#")
CTI = Namespace("http://ontologies.ti-semantics.com/cti#")
XCTI = Namespace("http://attack.mitre.org/cti-extension#")
PLATFORM = Namespace("http://ontologies.ti-semantics.com/platform#")
SCORE = Namespace("http://ontologies.ti-semantics.com/score#")

#Enterprise = '"Enterprise ATT&CK"'
#Mobile = 'Mobile ATT&CK'
#ICS = 'ICS ATT&CK'
Enterprise = 'Enterprise ATT&CK'
Mobile = 'Mobile ATT&CK'
ICS = 'ICS ATT&CK'

def isin(key, collection):
    return key in collection and collection[key]

class AttackModel():
    def __init__(self, store=IOMemory(), namespace='https://attack.mitre.org/', prefix='attack', log_level=logging.INFO):
        logging.basicConfig(level=log_level)
        self.store=store
        self.graph = ConjunctiveGraph(identifier=URIRef('https://attack.mitre.org/'), store=store)
        self.graph.bind('dcterms', DCTERMS)
        self.graph.bind('dc', DC)
        self.graph.bind('foaf', FOAF)
        self.graph.bind('skos', SKOS)
        self.graph.bind('core', CORE)
        self.graph.bind('score', SCORE)
        self.graph.bind('plat', PLATFORM)
        self.graph.bind('rdf', RDF)
        self.graph.bind('cti', CTI)
        self.graph.bind('xcti', XCTI)
        self.collections = list()
        self.ns = Namespace(namespace)
        self.graph.bind(prefix, self.ns)
        #logging.debug("Initial graph size: %d" % len(self.graph))
        #self.graph.remove( (None, None, None) )
        #logging.debug("Cleaned graph size: %d" % len(self.graph))

    def load_taxii(self, groups=None):
        # TODO: pass the taxii server in as a parameter so that it can be configured
        server = Server("https://cti-taxii.mitre.org/taxii/")
        api_root = server.api_roots[0]
        if not groups:
            groups = [Enterprise, Mobile, ICS]
        groups = [g.lower() for g in groups]
        logging.debug("Groups to collect from:"+str(groups))
        collection_classes = {Enterprise: CTI.EnterpriseCatalog, Mobile: CTI.MobileCatalog, ICS: CTI.ICSCatalog}
        #logging.debug(api_root.collections)
        for c in api_root.collections:
            logging.debug(c.title + ": " + c.url)
            collection_objects = Collection(c.url).get_objects()
            logging.debug("Size: %d" % len(collection_objects) )
            
            if c.title.lower() in groups:
                logging.debug("Collecting data from: "+ c.title)
                self.collections.append(
                    {
                        'collection': collection_objects,
                        'url': c.url,
                        'title': c.title,
                        'class': collection_classes[c.title],
                        'graph': Graph(store=self.store, identifier=c.url) 
                    }
                )
            #elif c.title == "Mobile ATT&CK":
            #    self.collections.append(
            #        {
            #            'collection': collection_objects, 
            #            'url': c.url, 
            #            'title': c.title, 
            #            'class': CTI.MobileCatalog, 
            #            'graph': Graph(store=self.store, identifier=c.url) 
            #        }
            #    )
            #elif c.title == "ICS ATT&CK":
            #    self.collections.append(
            #        {
            #            'collection': collection_objects, 
            #            'url': c.url, 
            #            'title': c.title, 
            #            'class': CTI.ICSCatalog, 
            ##            'graph': Graph(store=self.store, identifier=c.url) 
            #        }
            #    )
            #elif c.title == "PRE-ATT&CK":
            #    # This is now defunct
            #    pass
            #else:
            #    logging.warning("Unknown collection `%s`" % c.title)

    def load_stix(self, file_name=None, url=None, title=None, rdf_class=SKOS.Collection):
        with open(file_name, 'r') as f:
            logging.debug("%s opened" % file_name)
            subgraph = Graph(store=self.store, identifier=url)
            collection = stix2.parse(f.read(), allow_custom=True)
            self.collections.append(
                {
                    'collection': collection, 
                    'url': url, 
                    'title': title, 
                    'class': rdf_class, 
                    'graph': subgraph 
                }
            )

    def convert(self, old_school_reification=True, subgraph_reification=False):
        # clear graph
        self.graph.remove( (None, None, None) )
        for collection in self.collections:
            logging.debug("type: %s, spec: %s, id: %s", 
                collection['collection']['type'],
                collection['collection'].get("spec_version", ""),
                collection['collection']['id'] )
            #if collection['collection']['type'] == "bundle" and collection['collection']["spec_version"] >= "2.0":
            if collection['collection']['type'] == "bundle":
                bundle_subject = self.ns[collection['collection']['id']]
                subgraph = collection['graph']
                subgraph.add( (bundle_subject, RDF.type, SKOS.Collection ) )
                subgraph.add( (bundle_subject, RDF.type, collection['class'] ) )
                if isin('title', collection):
                    subgraph.add( (bundle_subject, SKOS.prefLabel, Literal(collection['title']) ) )
                if isin('url', collection):
                    subgraph.add( (bundle_subject, DCTERMS.source, URIRef(collection['url']) ) )
                for stix_object in collection['collection']['objects']:
                    subject = self.ns[stix_object['id']]
                    self.processor(subgraph, subject, stix_object)
                    subgraph.add( (bundle_subject, SKOS.member, subject ) ) # https://www.dublincore.org/specifications/dublin-core/dcmi-terms/#http://purl.org/dc/terms/hasPart
                self.postprocess(subgraph, old_school_reification=old_school_reification, subgraph_reification=subgraph_reification)
        # logging.debug(self.graph.serialize(format='n3', encoding='utf-8').decode('utf-8'))

    def postprocess(self, subgraph, old_school_reification=True, subgraph_reification=True):
        #logging.debug(len(self.graph))
        self.postprocess_references(subgraph)
        self.postprocess_relationships(subgraph, old_school_reification=old_school_reification, subgraph_reification=subgraph_reification)
        #logging.debug(len(self.graph))

    def postprocess_references(self, subgraph):
        q = """
            PREFIX core: <http://ontologies.ti-semantics.com/core#>
            PREFIX cti: <http://ontologies.ti-semantics.com/cti#>
            PREFIX dcterms: <http://purl.org/dc/terms/>
            PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

            CONSTRUCT   {?reference dcterms:identifier ?new }
            WHERE {
                {
                    ?reference a dcterms:BibliographicResource ;
                        cti:referenceSource ?refsrc ;
                        core:externalID ?id .
                        
                    BIND( STRDT(CONCAT(CONCAT(REPLACE(LCASE(STR(?refsrc)), '[^a-z0-9]', '-'), '--'), LCASE(STR(?id))), xsd:NMTOKEN) AS ?new )
                }
                UNION
                {
                    ?reference a dcterms:BibliographicResource ;
                        cti:referenceSource ?refsrc .
                    FILTER NOT EXISTS { ?reference core:externalID ?id }
                    BIND( STRDT(REPLACE(LCASE(STR(?refsrc)), '[^a-z0-9]', '-'), xsd:NMTOKEN) AS ?new )
                }

            }
            """
        qres = self.graph.query(q)
        for row in qres:
            subgraph.add(row)

    def add_reification(self, subgraph, subsubgraph, subject, relationship_class, predicate, reification_node=None ):
        q2 = prepareQuery("""
            SELECT ?obj
            WHERE {
                ?subject a ?relationship ;
                    ?predicate ?obj .
            }
            """)
        for row in self.graph.query(q2, initBindings={
            'subject': subject, 
            'predicate': predicate, 
            'relationship': relationship_class}):
            if subgraph:
                #logging.debug(row)
                subgraph.add( (subsubgraph, predicate, row['obj']) )
            # if the reification_node is defined, then we also want to reify the old way
            if reification_node:
                logging.debug("Reifying the old way")
                self.graph.add( (reification_node, predicate, row['obj']) )
        if subgraph:
            subgraph.add( (subsubgraph, RDF.type, CTI.RelationshipGraph) )
            

    def postprocess_relationships(self, subgraph, subgraph_reification=False, old_school_reification=True):
        q1 = prepareQuery("""
            SELECT ?subject ?sourceLabel ?source ?target ?targetLabel
            WHERE {
                ?subject a ?relationship ;
                    cti:relationSource ?source ;
                    cti:relationTarget ?target .
                    OPTIONAL {
                       ?target skos:prefLabel ?targetLabel .
                    }
                    OPTIONAL {
                        ?source skos:prefLabel ?sourceLabel .
                    }
            }
            """, initNs = { "cti": CTI, "dcterms": DCTERMS, "skos": SKOS })

        for relationships in [
            {'class': CTI.UsesRelationship, 'pred': CTI.uses, 'desc': 'uses'}, 
            {'class': CTI.MitigatesRelationship, 'pred': CTI.mitigates, 'desc': 'mitigates'},
            {'class': CTI.RevokedByRelationship, 'pred': CTI.revokedBy},
            {'class': CTI.SubtechniqueOfRelationship, 'pred': SKOS.narrower}
            ]:
            logging.debug("Processing relationship %s", relationships['class'])
            # search for relationships of this class
            for row in self.graph.query(q1, initBindings={'relationship': relationships['class'] }):
                try:
                    label = row['sourceLabel'] + ' ' + relationships['desc'] + ' ' + row['targetLabel']
                    logging.debug("Generating new label %s", label)
                    self.graph.add( (row['subject'], SKOS.prefLabel, Literal(label)) )
                except Exception as e:
                    if 'sourceLabel' not in row:
                        logging.warning("Missing source label for %s", row['subject'])
                    if 'targetLabel' not in row:
                        logging.warning("Missing target label for %s", row['subject'])
                    logging.warning(row)
                    logging.warning(type(row['sourceLabel']))
                    logging.warning(type(row['targetLabel']))
                    logging.warning(e)
                #logging.debug(row)
                if subgraph_reification or old_school_reification:
                    if subgraph_reification:
                        subgraph.add( ( row['source'], relationships['pred'], row['target']))
                        # create a subgraph to contain the new semantic relationship
                        subsubgraph = Graph(store=self.store)
                        # create the triple that describes this relationship with a predicate and not with a resource
                        subsubgraph.add( ( row['source'], relationships['pred'], row['target']))
                    else:
                        subgraph = None
                        subsubgraph = None
                    if old_school_reification:
                        logging.debug("Reifying the old way")
                        reification_node = BNode()
                        self.graph.add( (reification_node, RDF.type, RDF.Statement) )
                        self.graph.add( (reification_node, RDF.subject, row['source']) )
                        self.graph.add( (reification_node, RDF.predicate, relationships['pred']) )
                        self.graph.add( (reification_node, RDF.object, row['target']) )
                    else:
                        reification_node = None
                    # reify the subgraph with all the relevant attributes we had in the resource form of the data
                    for reification_predicate in [
                        DCTERMS.references, 
                        DCTERMS.rights, 
                        DCTERMS.description, 
                        DCTERMS.creator, 
                        DCTERMS.modified, 
                        DCTERMS.created
                        ]:
                        logging.debug("Reifying predicate %s", reification_predicate)
                        self.add_reification(
                            subgraph=subgraph, 
                            subsubgraph=subsubgraph, 
                            subject=row['subject'], 
                            relationship_class=relationships['class'], 
                            predicate=reification_predicate,
                            reification_node=reification_node)

    """
        IMT: http://purl.org/dc/terms/IMT The set of media types specified by the Internet Assigned Numbers Authority.
        https://www.iana.org/assignments/media-types/application/stix+json stix+json (defined https://www.iana.org/assignments/media-types/media-types.xhtml)
    """

    def processor(self, subgraph, subject, item):
        dispatch = { 
            'aliases': {
                'proc': self.rdf_list_property,
                'pred': CTI.alias,
                'chain': lambda value: Literal(value)
            },
            'created': { 
                'proc': self.rdf_timestamp_property, 
                'pred': DCTERMS.created # https://www.dublincore.org/specifications/dublin-core/dcmi-terms/#http://purl.org/dc/terms/created
            },
            'created_by_ref': { 
                'proc': self.rdf_reference_property, 
                'pred': DCTERMS.creator, # https://www.dublincore.org/specifications/dublin-core/dcmi-terms/#http://purl.org/dc/terms/creator
                'type': DCTERMS.Agent # https://www.dublincore.org/specifications/dublin-core/dcmi-terms/#http://purl.org/dc/terms/Agent
            },
            'description': { 
                'proc': self.rdf_string_property, 
                #'pred': DCTERMS.description # https://www.dublincore.org/specifications/dublin-core/dcmi-terms/#http://purl.org/dc/terms/description
                'pred': SKOS.definition # https://www.w3.org/TR/skos-reference/#notes
            },
            'external_references': {
                'proc': self.rdf_list_property,
                'pred': DCTERMS.references,
                'chain': lambda value: self.rdf_external_reference(subgraph, value)
            },
            'id': {
                'proc': self.rdf_id_property,
                'pred': DCTERMS.identifier # https://www.dublincore.org/specifications/dublin-core/dcmi-terms/#http://purl.org/dc/terms/identifier
            },
            'identity_class': {
                'proc': self.rdf_definition_type_property, 
                'chain': lambda value: { 
                    'individual': FOAF.Person, # STIX: A single person. / http://xmlns.com/foaf/spec/#term_Person
                    'group': FOAF.Group, # STIX: An informal collection of people, without formal governance, such as a distributed hacker group./ http://xmlns.com/foaf/spec/#term_Group
                    # TODO This is unsatisfactory. There needs to be a way of separating class from group iiin FOAF.
                    'class': FOAF.Group, # STIX: A class of entities, such as all hospitals, all Europeans, or the Domain Administrators in a system./ http://xmlns.com/foaf/spec/#term_Group
                    'unknown': FOAF.Agent, # STIX: It is unknown whether the classification is individual, group, organization, or class./ http://xmlns.com/foaf/spec/#term_Agent
                    'organization': FOAF.Organization # STIX: A formal organization of people, with governance, such as a company or country./ http://xmlns.com/foaf/spec/#term_Organization
                }.get(value, FOAF.Agent)
            },
            'kill_chain_phases': {
                'proc': self.rdf_list_property,
                'pred': CTI.killChainPhase,
                'chain': lambda value: self.rdf_kill_chain_phase(subgraph, value)
            },
            'labels': { # This is redundant with the record type and is dropped
                #'proc': self.rdf_list_property,
                #'pred': CTI.label, 
                #'chain': lambda value: Literal(value)
            },
            'modified': {
                'proc': self.rdf_timestamp_property,
                'pred': DCTERMS.modified # https://www.dublincore.org/specifications/dublin-core/dcmi-terms/#http://purl.org/dc/terms/modified
            },
            'name': {
                'proc': self.rdf_string_property,
                #'pred': DCTERMS.title # https://www.dublincore.org/specifications/dublin-core/dcmi-terms/#http://purl.org/dc/terms/title
                'pred': SKOS.prefLabel # https://www.w3.org/TR/skos-reference/#labels
            },
            'object_marking_refs': {
                'proc': self.rdf_list_property,
                'pred': DCTERMS.rights, # https://www.dublincore.org/specifications/dublin-core/dcmi-terms/#http://purl.org/dc/terms/rights
                'chain': lambda value: self.rdf_object_marking_ref(subgraph, value)
            },
            'relationship_type': {
                'proc': self.rdf_relationship_property,
                'chain': lambda value: { 
                    'mitigates': CTI.MitigationRelationship,
                    'uses': CTI.UsesRelationship,
                    'subtechnique-of': CTI.SubtechniqueOfRelationship,
                    'revoked-by': CTI.RevokedByRelationship,
                    'related-to': CTI.RelatedToRelationship,
                    }.get(value, CTI.Relationship)
            },
            'definition': {
                'proc': self.rdf_definition_property
            },
            'definition_type': {
                'proc': self.rdf_definition_type_property,
                'chain': lambda value: {
                    'statement': DCTERMS.RightsStatement
                }.get(value, None)
            },
            'revoked': {
                'proc': self.rdf_boolean_property,
                'pred': CTI.revoked,
                'optional': True
            },
            'tactic_refs': {
                'proc': self.rdf_reference_property, 
                'pred': CTI.tactic,
                'type': CTI.Type
            },
            'type': {
                'proc': self.rdf_type_property,
                'chain': lambda value: { 
                    "attack-pattern": CTI.AttackPattern,
                    "course-of-action": CTI.CourseOfAction,
                    "intrusion-set": CTI.IntrusionSet,
                    "malware": CTI.Malware,
                    "report": CTI.Report,
                    "indicator": CTI.Indicator,
                    "marking-definition": CTI.MarkingDefinition,
                    "tool": CTI.Tool,        
                    "relationship": CTI.Relationship,
                    "x-mitre-matrix": XCTI.Matrix,
                    "identity": CTI.Identity, # TODO FOAF Agent might be enough
                    "x-mitre-tactic": CTI.Tactic # TODO: is this true?
                }.get(value, None)
            },
            'target_ref': {
                'proc': self.rdf_reference_property,
                'pred': CTI.relationTarget
            },
            'source_ref': {
                'proc': self.rdf_reference_property,
                'pred': CTI.relationSource
            },
            # MITRE extensions
            'x_mitre_aliases': {
                'proc': self.rdf_list_property,
                #'pred': XCTI.alias,
                'pred': SKOS.altLabel,
                'chain': lambda value: Literal(value)
            },
            'x_mitre_contributors': {
                'proc': self.rdf_list_property,
                'pred': XCTI.contributor,
                'chain': lambda value: Literal(value)
            },
            'x_mitre_data_sources': {
                'proc': self.rdf_list_property,
                'pred': XCTI.dataSource,
                'chain': lambda value: Literal(value)
            },
            'x_mitre_defense_bypassed': {
                'proc': self.rdf_list_property,
                'pred': XCTI.defenseBypassed,
                'chain': lambda value: Literal(value)
            },
            'x_mitre_deprecated': {
                'proc': self.rdf_boolean_property,
                'pred': CTI.deprecated
            },
            'x_mitre_detectable_by_common_defenses': {
                'proc': self.rdf_string_property,
                'pred': XCTI.detectableByCommonDefenses
            },
            'x_mitre_detectable_by_common_defenses_explanation': {
                'proc': self.rdf_string_property,
                'pred': XCTI.detectableByCommonDefensesExplanation
            },
            'x_mitre_detection': {
                'proc': self.rdf_string_property, 
                'pred': XCTI.detection
            },
            'x_mitre_difficulty_for_adversary': {
                'proc': self.rdf_string_property,
                'pred': XCTI.difficultyForAdversary
            },
            'x_mitre_difficulty_for_adversary_explanation': {
                'proc': self.rdf_string_property,
                'pred': XCTI.difficultyForAdversaryExplanation
            },
            'x_mitre_effective_permissions': {
                'proc': self.rdf_list_property,
                'pred': XCTI.effectivePermission,
                'chain': lambda value: Literal(value)
            },
            'x_mitre_impact_type': {
                'proc': self.rdf_list_property,
                'pred': XCTI.impactType,
                'chain': lambda value: Literal(value)
            },
            'x_mitre_is_subtechnique': {
                'proc': self.rdf_boolean_property,
                'pred': XCTI.isSubtechnique
            },
            'x_mitre_network_requirements': {
                'proc': self.rdf_boolean_property,
                'pred': XCTI.networkRequirement
            },
            'x_mitre_old_attack_id': {
                'proc': self.rdf_string_property, 
                'pred': XCTI.oldAttackID
            },
            'x_mitre_platforms': {
                'proc': self.rdf_list_property,
                'pred': XCTI.platform,
                'chain': lambda value: Literal(value)
            },
            'x_mitre_remote_support': {
                'proc': self.rdf_boolean_property,
                'pred': XCTI.remoteSupport
            },
            'x_mitre_shortname': {
                'proc': self.rdf_string_property,
                'pred': SKOS.hiddenLabel # https://www.w3.org/TR/skos-reference/#labels
            },
            'x_mitre_system_requirements': {
                'proc': self.rdf_list_property,
                'pred': XCTI.systemRequirement,
                'chain': lambda value: Literal(value)
            },
            'x_mitre_permissions_required': {
                'proc': self.rdf_list_property,
                'pred': XCTI.permissionsRequired,
                'chain': lambda value: Literal(value)
            },
            'x_mitre_tactic_type': {
                'proc': self.rdf_list_property,
                'pred': XCTI.tacticType,
                'chain': lambda value: Literal(value)
            },
            'x_mitre_version': {
                'proc': self.rdf_decimal_property, 
                'pred': XCTI.version
            },
        }
        for key in item.keys():
            if key in dispatch:
                if 'proc' in dispatch[key]:
                    dispatch[key]['proc'](subgraph, subject, key,
                        predicate=dispatch[key].get('pred', None),
                        value=item.get(key, None),
                        typ=dispatch[key].get('type', None), 
                        optional=dispatch[key].get('optional', None),
                        chain=dispatch[key].get('chain', None))
            else:
                logging.warn("Key %s unknown" % key)

    def rdf_attack_pattern(self, item):
        subject = self.ns[item['id']]
        self.processor(subject, item)

    def rdf_boolean_property(self, subgraph, subject, key, predicate=None, value=None, typ=None, optional=None, chain=None):
        if isinstance(value, str):
            if value.lower() == 'yes':
                obj = Literal(True, datatype=XSD.boolean)
            elif value.lower() == 'no':
                obj = Literal(False, datatype=XSD.boolean)
            else:
                logging.error("unknown boolean-like string %s" % value)
        else:
            if value:
                obj = Literal(True, datatype=XSD.boolean)
            elif optional:
                return
            elif not optional and value == False:
                obj = Literal(False, datatype=XSD.boolean)
            else:
                obj = Literal(False, datatype=XSD.boolean)
        subgraph.add( (subject, predicate, obj ) )

    def rdf_id_property(self, subgraph, subject, key, predicate=None, value=None, typ=None, optional=None, chain=None):
        subgraph.add( (subject, predicate, Literal(value) ) )

    def rdf_list_property(self, subgraph, subject, key, predicate=None, value=None, typ=None, optional=None, chain=None):
        for v in value:
            obj = chain(v)
            subgraph.add( (subject, predicate, obj ) )

    def rdf_reference_property(self, subgraph, subject, key, predicate=None, value=None, typ=None, optional=None, chain=None):
        obj = self.ns[value]
        if typ:
            self.graph.add( (obj, RDF.type, typ ) )
        subgraph.add( (subject, predicate, obj ) )
        # DCTERMS.bibliographicCitation

    def rdf_string_property(self, subgraph, subject, key, predicate=None, value=None, typ=None, optional=None, chain=None):
        subgraph.add( (subject, predicate, Literal(value) ) )

    def rdf_decimal_property(self, subgraph, subject, key, predicate=None, value=None, typ=None, optional=None, chain=None):
        subgraph.add( (subject, predicate, Literal(value, datatype=XSD.decimal) ) )

    def rdf_timestamp_property(self, subgraph, subject, key, predicate=None, value=None, typ=None, optional=None, chain=None):
        subgraph.add( (subject, predicate, Literal(value, datatype=XSD.dateTime) ) )

    def rdf_type_property(self, subgraph, subject, key, predicate=None, value=None, typ=None, optional=None, chain=None):
        t = chain(value)
        if not t:
            raise ValueError("Unknown type value {}".format(value))
        subgraph.add( (subject, RDF.type, t ) )
        
    def rdf_definition_property(self, subgraph, subject, key, predicate=None, value=None, typ=None, optional=None, chain=None):
        statement = Literal(value["statement"])
        # DC.rights is different from DCTERMS.rights This is what the defination says:
        # Information about rights held in and over the resource.
        # Typically, rights information includes a statement about various property rights associated with the resource, including intellectual property rights.
        # https://www.dublincore.org/specifications/dublin-core/dcmi-terms/#http://purl.org/dc/elements/1.1/rights
        subgraph.add( (subject, DC.rights, statement ) )

    def rdf_relationship_property(self, subgraph, subject, key, predicate=None, value=None, typ=None, optional=None, chain=None):
        typ = chain(value)
        subgraph.add( (subject, RDF.type, typ ) )

    # TODO this is more universal, so mis-named
    def rdf_definition_type_property(self, subgraph, subject, key, predicate=None, value=None, typ=None, optional=None, chain=None):
        typ = chain(value)
        subgraph.add( (subject, RDF.type, typ ) )

    def rdf_kill_chain_phase(self, subgraph, value):
        kill_chain_phase = self.ns['kill-chain-phase__' + value["kill_chain_name"] + '__' + value["phase_name"]]
        subgraph.add( (kill_chain_phase, RDF.type, CTI.KillChainPhase) )
        subgraph.add( (kill_chain_phase, SKOS.prefLabel, Literal(value["phase_name"])) )
        subgraph.add( (kill_chain_phase, CTI.killChainName, Literal(value["kill_chain_name"])) )
        return kill_chain_phase

    def rdf_external_reference(self, subgraph, value):
        # https://www.dublincore.org/specifications/dublin-core/dc-citation-guidelines/
        m = hashlib.sha256()
        for k in sorted(value.keys()):
            m.update((k + value[k]).encode('utf-8'))
        refnode = self.ns['ref_' + m.hexdigest()]
            # https://www.dublincore.org/specifications/dublin-core/dcmi-terms/#http://purl.org/dc/terms/BibliographicResource
        self.graph.add( (refnode, RDF.type, DCTERMS.BibliographicResource) )
        if "url" in value:
            # source is just a URI of some sort
            # https://www.dublincore.org/specifications/dublin-core/dcmi-terms/#http://purl.org/dc/terms/source
            subgraph.add( (refnode, DCTERMS.source, Literal(value['url'], datatype=XSD.anyURI)) )
        if "source_name" in value:
            # We'll use DC elements publisher because it is less type strict
            # https://www.dublincore.org/specifications/dublin-core/dcmi-terms/#http://purl.org/dc/elements/1.1/publisher
            #self.graph.add( (refnode, DC.publisher, Literal(value['source_name'], datatype=XSD.string)) )
            subgraph.add( (refnode, CTI.referenceSource, Literal(value['source_name'])) )
        if "external_id" in value:
            # https://www.dublincore.org/specifications/dublin-core/dcmi-terms/#http://purl.org/dc/terms/identifiers
            #self.graph.add( (refnode, DCTERMS.identifier, Literal(value['external_id'], datatype=XSD.token)) )
            subgraph.add( (refnode, CORE.externalID, Literal(value['external_id'])) )
        if "description" in value:
            subgraph.add( (refnode, DCTERMS.bibliographicCitation, Literal(value['description'])) )
        return refnode

    def rdf_object_marking_ref(self, subgraph, value):
        refnode = self.ns[value]
        subgraph.add( (refnode, RDF.type, DCTERMS.RightsStatement) )
        return refnode
