# Converting XML file from Red Hat to The Specified Format of JSON file

XML file is sometimes hard to read by human eyes. In this challenge I will try to convert XML file to JSON with Python script.

Steps:
1. Read XML file from Red Hat url:
    ```python
    url = "https://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml"
    response = requests.get(url, stream=True)
    ```
    I choose `requests`  library, because it is the easiest tool to read the data.
2. Choose python library to parse XML content.

    There are 3 libraries that I tried to finish this test.
    1. XML minidom
    2. ElementTree
    3. lxml

    I ended up using `lxml` because it has advance function like `getparent()` etc.

3. One obstacle that I found was the XML file is too big to read, so I was having trouble understanding the data structure. I truncate xml data to get one record to analyze, so I can understand the data structure and can get the necessary data.

4. It turns out that the data has a different namespaces so we need to create namespaces mapping:
    ```python
    NSMAP = {
        'xmlns': "http://oval.mitre.org/XMLSchema/oval-definitions-5",
        'red-def': "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
        'unix-def': "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix",
        'ind-def': "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
    }
    ```

5. Read XML content and find all `definition` tag:
    ```python
    root = etree.fromstring(response.content)
    definition_list = root.findall('.//xmlns:definition', namespaces=NSMAP)
    ```

6. Get `title, fixes_cve, severity, affected_cpe` it was relatively easy to get these data:
    ```python
    for index, definition in enumerate(definition_list):
        title = definition.find(".//xmlns:title", namespaces=NSMAP)
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
    ```

7. The next obstacle was when I try to find `criteria` data and match it with output JSON structure. So I create a recursive function to get all data.
The recursive function will the attributs of element tag. If the tag has attribute `operator` we will take the operator value and then go into recursive function again.
First we need to find the first `criteria` tag
    
```python
first_criteria = definition.find(".//xmlns:criteria", namespaces=NSMAP)
definition_dict['criteria'] = [get_criteria(first_criteria)]

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

            state_ref = state_elem.attrib.get('state_ref')
            
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
```

In recursive function we will find element with attribute `operator` and `comment`. If we find a `comment` attribute it will search for values with `id` from `test_ref` attribute.

9. After the recursive function is done. The script will save the output as a json file.
It will save to json file for every 10 record of advisory, because the source code is too big, so if something bad happen like a lost of internet connection we won't lose all data.

