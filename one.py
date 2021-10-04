import xml.etree.ElementTree as ET
from xml.dom.minidom import parse, Element, parseString
from pprint import pprint
import requests
import xmltodict, json
from lxml import etree

xmls = """
<criteria operator="OR">
    <criterion comment="Red Hat Enterprise Linux must be installed" test_ref="oval:com.redhat.rhba:tst:20070304026"/>
    <criteria operator="AND">
        <criterion comment="Red Hat Enterprise Linux 5 is installed" test_ref="oval:com.redhat.rhba:tst:20070331005"/>
        <criteria operator="OR">
            <criteria operator="AND">
                <criterion comment="xulrunner is earlier than 0:17.0.5-1.el5_9" test_ref="oval:com.redhat.rhsa:tst:20130696001"/>
                <criterion comment="xulrunner is signed with Red Hat redhatrelease key" test_ref="oval:com.redhat.rhsa:tst:20080569002"/>
            </criteria>
            <criteria operator="AND">
                <criterion comment="xulrunner-devel is earlier than 0:17.0.5-1.el5_9" test_ref="oval:com.redhat.rhsa:tst:20130696003"/>
                <criterion comment="xulrunner-devel is signed with Red Hat redhatrelease key" test_ref="oval:com.redhat.rhsa:tst:20080569004"/>
            </criteria>
            <criteria operator="AND">
                <criterion comment="firefox is earlier than 0:17.0.5-1.el5_9" test_ref="oval:com.redhat.rhsa:tst:20130696005"/>
                <criterion comment="firefox is signed with Red Hat redhatrelease key" test_ref="oval:com.redhat.rhsa:tst:20070097008"/>
            </criteria>
     </criteria>
    </criteria>
    <criteria operator="AND">
        <criterion comment="Red Hat Enterprise Linux 6 is installed" test_ref="oval:com.redhat.rhba:tst:20111656003"/>
        <criteria operator="OR">
            <criteria operator="AND">
                <criterion comment="xulrunner is earlier than 0:17.0.5-1.el6_4" test_ref="oval:com.redhat.rhsa:tst:20130696008"/>
                <criterion comment="xulrunner is signed with Red Hat redhatrelease2 key" test_ref="oval:com.redhat.rhsa:tst:20100861002"/>
            </criteria>
            <criteria operator="AND">
                <criterion comment="xulrunner-devel is earlier than 0:17.0.5-1.el6_4" test_ref="oval:com.redhat.rhsa:tst:20130696010"/>
                <criterion comment="xulrunner-devel is signed with Red Hat redhatrelease2 key" test_ref="oval:com.redhat.rhsa:tst:20100861004"/>
            </criteria>
            <criteria operator="AND">
                <criterion comment="firefox is earlier than 0:17.0.5-1.el6_4" test_ref="oval:com.redhat.rhsa:tst:20130696012"/>
                <criterion comment="firefox is signed with Red Hat redhatrelease2 key" test_ref="oval:com.redhat.rhsa:tst:20100861006"/>
            </criteria>
        </criteria>
    </criteria>
</criteria>
"""

xmls2 = """
<criteria operator="OR">
    <criterion comment="Red Hat Enterprise Linux must be installed" test_ref="oval:com.redhat.rhba:tst:20070304026"/>
    <criteria operator="AND">
        <criterion comment="Red Hat Enterprise Linux 4 is installed" test_ref="oval:com.redhat.rhba:tst:20070304025"/>
        <criteria operator="OR">
            <criterion comment="kernel earlier than 0:2.6.9-55.EL is currently running" test_ref="oval:com.redhat.rhba:tst:20070304023"/>
            <criterion comment="kernel earlier than 0:2.6.9-55.EL is set to boot up on next boot" test_ref="oval:com.redhat.rhba:tst:20070304024"/>
        </criteria>
        <criteria operator="OR">
            <criteria operator="AND">
                <criterion comment="kernel is earlier than 0:2.6.9-55.EL" test_ref="oval:com.redhat.rhba:tst:20070304001"/>
                <criterion comment="kernel is signed with Red Hat master key" test_ref="oval:com.redhat.rhba:tst:20070304002"/>
            </criteria>
            <criteria operator="AND">
                <criterion comment="kernel-devel is earlier than 0:2.6.9-55.EL" test_ref="oval:com.redhat.rhba:tst:20070304003"/>
                <criterion comment="kernel-devel is signed with Red Hat master key" test_ref="oval:com.redhat.rhba:tst:20070304004"/>
            </criteria>
            <criteria operator="AND">
                <criterion comment="kernel-doc is earlier than 0:2.6.9-55.EL" test_ref="oval:com.redhat.rhba:tst:20070304005"/>
                <criterion comment="kernel-doc is signed with Red Hat master key" test_ref="oval:com.redhat.rhba:tst:20070304006"/>
            </criteria>
            <criteria operator="AND">
                <criterion comment="kernel-hugemem is earlier than 0:2.6.9-55.EL" test_ref="oval:com.redhat.rhba:tst:20070304007"/>
                <criterion comment="kernel-hugemem is signed with Red Hat master key" test_ref="oval:com.redhat.rhba:tst:20070304008"/>
            </criteria>
            <criteria operator="AND">
                <criterion comment="kernel-hugemem-devel is earlier than 0:2.6.9-55.EL" test_ref="oval:com.redhat.rhba:tst:20070304009"/>
                <criterion comment="kernel-hugemem-devel is signed with Red Hat master key" test_ref="oval:com.redhat.rhba:tst:20070304010"/>
            </criteria>
            <criteria operator="AND">
                <criterion comment="kernel-largesmp is earlier than 0:2.6.9-55.EL" test_ref="oval:com.redhat.rhba:tst:20070304011"/>
                <criterion comment="kernel-largesmp is signed with Red Hat master key" test_ref="oval:com.redhat.rhba:tst:20070304012"/>
            </criteria>
            <criteria operator="AND">
                <criterion comment="kernel-largesmp-devel is earlier than 0:2.6.9-55.EL" test_ref="oval:com.redhat.rhba:tst:20070304013"/>
                <criterion comment="kernel-largesmp-devel is signed with Red Hat master key" test_ref="oval:com.redhat.rhba:tst:20070304014"/>
            </criteria>
            <criteria operator="AND">
                <criterion comment="kernel-smp is earlier than 0:2.6.9-55.EL" test_ref="oval:com.redhat.rhba:tst:20070304015"/>
                <criterion comment="kernel-smp is signed with Red Hat master key" test_ref="oval:com.redhat.rhba:tst:20070304016"/>
            </criteria>
            <criteria operator="AND">
                <criterion comment="kernel-smp-devel is earlier than 0:2.6.9-55.EL" test_ref="oval:com.redhat.rhba:tst:20070304017"/>
                <criterion comment="kernel-smp-devel is signed with Red Hat master key" test_ref="oval:com.redhat.rhba:tst:20070304018"/>
            </criteria>
            <criteria operator="AND">
                <criterion comment="kernel-xenU is earlier than 0:2.6.9-55.EL" test_ref="oval:com.redhat.rhba:tst:20070304019"/>
                <criterion comment="kernel-xenU is signed with Red Hat master key" test_ref="oval:com.redhat.rhba:tst:20070304020"/>
            </criteria>
            <criteria operator="AND">
                <criterion comment="kernel-xenU-devel is earlier than 0:2.6.9-55.EL" test_ref="oval:com.redhat.rhba:tst:20070304021"/>
                <criterion comment="kernel-xenU-devel is signed with Red Hat master key" test_ref="oval:com.redhat.rhba:tst:20070304022"/>
            </criteria>
        </criteria>
    </criteria>
</criteria>
"""

def parseXmlToJson(xml):
  response = {}

  for child in list(xml):
    if len(list(child)) > 0:
        response[child.attrib.get('operator')] = parseXmlToJson(child)
    else:
        if not child.attrib.get('operator'):
            continue
        response[child.attrib.get('operator')] = child.text or ''

  return response

def parse_element(element):
    dict_data = {}
    # if element.nodeType == element.TEXT_NODE:
    #     dict_data['data'] = element.data
    if element.nodeType not in [element.TEXT_NODE, element.DOCUMENT_NODE, 
                                element.DOCUMENT_TYPE_NODE]:
        for item in element.attributes.items():
            dict_data[item[0]] = item[1]
    if element.nodeType not in [element.TEXT_NODE, element.DOCUMENT_TYPE_NODE]:
        for child in element.childNodes:
            child_name, child_dict = parse_element(child)
            import pdb; pdb.set_trace()
            if child_name in dict_data:
                try:
                    dict_data[child_name].append(child_dict)
                except AttributeError:
                    dict_data[child_name] = [dict_data[child_name], child_dict]
            else:
                dict_data[child_name] = child_dict 
    return element.nodeName, dict_data

def recursive(element):
    opr = element.attrib.get('operator').lower()
    datas = {
        opr: []
    }
    for elem in element:
        if elem.attrib.get('comment'):
            datas[opr].append([elem.attrib.get('comment')])
        else:
            data = recursive(elem)
            datas[opr].append(data)
    return datas

if __name__ == "__main__":
    from xml.dom import minidom
    print('-----')
    root = etree.fromstring(xmls)
    first_opr = root.attrib.get('operator').lower()
    datas = {
        first_opr: []
    }
    tesss = recursive(root)
    import pdb; pdb.set_trace()
    for elem in root:
        if elem.attrib.get('comment'):
            datas[first_opr].append([elem.attrib.get('comment')])
        else:
            data = {elem.attrib.get('operator'): []}
            for el in elem:
                if el.attrib.get('comment'):
                    data[elem.attrib.get('operator')].append([el.attrib.get('comment')])
                else:
                    datael = {el.attrib.get('operator'): []}
                    for i in el:
                        if i.attrib.get('comment'):
                            datael[el.attrib.get('operator')].append([i.attrib.get('comment')])
                        else:
                            datai = {i.attrib.get('operator'): []}
                            datael[el.attrib.get('operator')].append(datai)
                    data[elem.attrib.get('operator')].append(datael)
            datas[first_opr].append(data)
    import pdb; pdb.set_trace()

    # root = minidom.parseString(xmls)
    # test = recursive(root)
    



    # obj = xmltodict.parse(xmls)
    # objdict = json.loads(json.dumps(obj))
    # for key, value in objdict.items():
    #     import pdb; pdb.set_trace()
    # # print(json.dumps(obj))
