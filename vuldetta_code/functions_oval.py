from lxml import etree
import re

def get_processed_ubuntu_oval(xml_content):
    tests = dict()
    objects = dict()
    states = dict()
    variables = dict()
    p = etree.XMLParser(huge_tree=True, ns_clean=True, recover=True, encoding='utf-8')
    root = etree.fromstring(text=xml_content, parser=p)
    definitions = list()
    for block in root:
        if block.tag == "{http://oval.mitre.org/XMLSchema/oval-definitions-5}definitions":
            for definition in block:
                definition_dict = dict()
                definition_dict['id'] = definition.attrib['id']
                definition_dict['version'] = definition.attrib['version']
                definition_dict['class'] = definition.attrib['class']
                definition_dict['metadata'] = dict()
                definition_dict['metadata']['references'] = list()
                for definition_param in definition:
                    if definition_param.tag == "{http://oval.mitre.org/XMLSchema/oval-definitions-5}metadata":
                        for definition_metadata_param in definition_param:
                            if definition_metadata_param.tag == "{http://oval.mitre.org/XMLSchema/oval-definitions-5}reference":
                                ref_id = definition_metadata_param.attrib['ref_id']
                                ref_url = definition_metadata_param.attrib['ref_url']
                                source = definition_metadata_param.attrib['source']
                                definition_dict['metadata']['references'].append({
                                    "ref_id":ref_id,
                                    "ref_url":ref_url,
                                    "source":source
                                })
                            if definition_metadata_param.tag == "{http://oval.mitre.org/XMLSchema/oval-definitions-5}title":
                                definition_dict['metadata']['title'] = definition_metadata_param.text
                            if definition_metadata_param.tag == "{http://oval.mitre.org/XMLSchema/oval-definitions-5}description":
                                definition_dict['metadata']['description'] = definition_metadata_param.text
                    if definition_param.tag == "{http://oval.mitre.org/XMLSchema/oval-definitions-5}criteria":
                        definition_dict['criteria'] = dict()
                        definition_dict['criteria']['txt'] = str(etree.tostring(definition_param, encoding='utf8', method='xml'))
                        definition_dict['criteria']['tests'] = re.findall("test_ref=\"([^\"]*)\"", definition_dict['criteria']['txt'])
                        # if len(definition_dict['criteria']['tests']) != 2:
                        #     print("ERROR: wrong structure of tests!")
                        #     print(definition_dict['criteria']['tests'])
                        #     exit()
                    definitions.append(definition_dict)
        if block.tag == "{http://oval.mitre.org/XMLSchema/oval-definitions-5}tests":
            for test in block:
                test_description = {}
                for test_obj_state in test:
                    test_description["tag"] = test.tag
                    if "object_ref" in test_obj_state.attrib:
                        test_description["object_ref"] = test_obj_state.attrib["object_ref"]
                    if "state_ref" in test_obj_state.attrib:
                        test_description["state_ref"] = test_obj_state.attrib["state_ref"]
                tests[test.attrib['id']] = test_description
                # print(etree.tostring(test_obj_state, encoding='utf8', method='xml'))
        if block.tag == "{http://oval.mitre.org/XMLSchema/oval-definitions-5}objects":
            for object in block:
                object_description = {}
                for value in object:
                    if 'var_ref' in value.attrib:
                        object_description["var_ref"] = value.attrib["var_ref"]
                objects[object.attrib['id']] = object_description
            # print(etree.tostring(value, encoding='utf8', method='xml'))
        if block.tag == "{http://oval.mitre.org/XMLSchema/oval-definitions-5}variables":
            for variable in block:
                variable_description = {}
                values = []
                for value in variable:
                    # print(etree.tostring(value, encoding='utf8', method='xml'))
                    values.append(value.text)
                variable_description["values"] = values
                variables[variable.attrib['id']] = variable_description
            # print(etree.tostring(value, encoding='utf8', method='xml'))
        if block.tag == "{http://oval.mitre.org/XMLSchema/oval-definitions-5}states":
            for state in block:
                state_description = {}
                if state.tag == "{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}dpkginfo_state":
                    state_description["state_type"] = state.tag
                    for value in state:
                        state_description["state_action"] = value.tag
                        state_description["state_operation"] = value.attrib["operation"]
                        state_description["state_value"] = value.text
                    states[state.attrib['id']] = state_description
                    # print(etree.tostring(state, encoding='utf8', method='xml'))

    detection_rules = list()
    for definition in definitions:
        cves = list()
        usns = list()
        for reference in definition['metadata']['references']:
            if reference['source'] == 'CVE':
                cves.append(reference['ref_id'])
            if reference['source'] == 'USN':
                usns.append(reference['ref_id'])
        for usn in usns:
            for cve in cves:
                for test_id in definition['criteria']['tests']:
                    if tests[test_id]['tag'] == "{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}dpkginfo_test":
                        object_ref = tests[test_id]['object_ref']
                        var_ref = objects[object_ref]['var_ref']
                        packages = variables[var_ref]['values']
                        state_ref = tests[test_id]['state_ref']
                        for package in packages:
                            detection_rules.append(usn + ";" + cve + ";" + package + ";" + states[state_ref]['state_value'])


    return definitions, detection_rules


            
            
