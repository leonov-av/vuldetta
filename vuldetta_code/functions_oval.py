from lxml import etree
import re

def get_processed_ubuntu_oval(xml_content):
    tests = dict()

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
                    if "object_ref" in test_obj_state.attrib:
                        test_description["object_ref"] = test_obj_state.attrib["object_ref"]
                    if "state_ref" in test_obj_state.attrib:
                        test_description["state_ref"] = test_obj_state.attrib["state_ref"]
                tests[test.attrib['id']] = test_description
                # print(etree.tostring(test_obj_state, encoding='utf8', method='xml'))
    print(tests)
    return definitions


            
            
