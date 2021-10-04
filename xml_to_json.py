from pprint import pp, pprint
import requests
from lxml import etree
import json
import os


def get_criteria(element):
    operator_ = element.attrib.get('operator').lower()
    datas = {
        operator_: []
    }
    for elem in element:
        if elem.attrib.get('comment'):
            criterion = []
            comment = elem.attrib.get('comment').split(" ")[0]
            if comment.startswith("Red"):
                continue
            # cek id value
            ref_id = elem.attrib.get('test_ref')
            checker_elem = root.find(f'''.//*[@id='{ref_id}']''')
            if "#unix" in checker_elem.tag:
                state_elem = checker_elem.find(".//unix-def:state", namespaces=NSMAP)
            elif '#independent' in checker_elem.tag:
                state_elem = checker_elem.find(".//ind-def:state", namespaces=NSMAP)
            elif "#linux" in checker_elem.tag:
                state_elem = checker_elem.find(".//red-def:state", namespaces=NSMAP)
            try:
                state_ref = state_elem.attrib.get('state_ref')
            except Exception:
                import pdb; pdb.set_trace()
            uname = root.find(f'''.//*[@id='{state_ref}']''')
            elem_uname = uname.getchildren()[0].tag.split("}")[1]
            operation = uname.getchildren()[0].get('operation')
            regex_text = uname.getchildren()[0].text

            criterion.append(elem_uname)
            criterion.append(comment)
            criterion.append(operation)
            criterion.append(regex_text)

            datas[operator_].append(criterion)
        else:
            data = get_criteria(elem)
            datas[operator_].append(data)
    return datas


def manage_output():
    if not os.path.exists("output.json"):
        with open("output.json", "w") as out:
            json.dump([], out, indent=2)
    with open("output.json", 'r') as out:
        data = json.load(out)
    return data


if __name__ == "__main__":
    print('hi')
    # json_data = manage_output()
    url = "https://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml"
    response = requests.get(url, stream=True)
    output = {
        'advisory': []
    }
    root = etree.fromstring(response.content)
    NSMAP = {
        'xmlns': "http://oval.mitre.org/XMLSchema/oval-definitions-5",
        'red-def': "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
        'unix-def': "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix",
        'ind-def': "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
    }
    definition_list = root.findall('.//xmlns:definition', namespaces=NSMAP)
    tests = root.find('.//xmlns:tests', namespaces=NSMAP)
    states = root.find('.//xmlns:states', namespaces=NSMAP)

    for index, definition in enumerate(definition_list):
        print('index', index)
        title = definition.find(".//xmlns:title", namespaces=NSMAP)
        # if any(d['title'] == title.text for d in json_data):
        #     continue
        severity = definition.find(".//xmlns:severity", namespaces=NSMAP)
        definition_dict = {
            "title": title.text,
            "fixes_cve": [],
            "severity": severity.text,
            "affected_cpe": [],
            "criteria": []
        }
        for cve in definition.findall(".//xmlns:cve", namespaces=NSMAP):
            definition_dict['fixes_cve'].append(cve.text)
        cpe_set = set()
        for cpe in definition.findall(".//xmlns:cpe", namespaces=NSMAP):
            split_cpe = cpe.text.split("::")
            cpe_text = split_cpe[0]
            cpe_set.add(cpe_text)
        definition_dict['affected_cpe'] = list(cpe_set)

        first_criteria = definition.find(".//xmlns:criteria", namespaces=NSMAP)
        definition_dict['criteria'] = [get_criteria(first_criteria)]
        pprint(definition_dict)
        output['advisory'].append(definition_dict)
        if index % 10 == 0:
            with open("output.json", "w") as out:
                json.dump(output, out, indent=2)
