import sys
import requests
import re
import logging
from io import BytesIO
from excelextractor import excelextractor
from reqdb import ReqDB, models
import json
from zipfile import ZipFile
import pypandoc
import xml.etree.ElementTree as ET
from reqdbcontentcreator.rollback import Rollback


def asvs(client: ReqDB):
    """Downloads and adds the OWASP ASVS to ReqDB

    :param client: ReqDB client
    :type client: ReqDB
    """

    logging.info("Start creating catalogues for 'OWASP ASVS'.")
    r = requests.get(
        "https://github.com/OWASP/ASVS/releases/download/v4.0.3_release/OWASP.Application.Security.Verification.Standard.4.0.3-en.json"
    )
    r.raise_for_status()
    asvsData = r.json()

    try:
        l1 = client.Tags.add(models.Tag(name="Level 1"))
        Rollback.tags.append(l1["id"])
        l2 = client.Tags.add(models.Tag(name="Level 2"))
        Rollback.tags.append(l2["id"])
        l3 = client.Tags.add(models.Tag(name="Level 3"))
        Rollback.tags.append(l3["id"])

        nist = client.ExtraTypes.add(
            models.ExtraType(title="NIST Ref", extraType=3, description="NIST Reference")
        )
        Rollback.extraTypes.append(nist["id"])
        cve = client.ExtraTypes.add(
            models.ExtraType(title="CVE Ref", extraType=3, description="CVE Reference")
        )
        Rollback.extraTypes.append(cve["id"])
    except Exception as e:
        panic(e, client)

    rootTopics = []
    try:
        for itemL1 in asvsData["Requirements"]:
            parentL1 = client.Topics.add(
                models.Topic(
                    key=f"V{itemL1['Shortcode'][1:].zfill(2)}",
                    title=itemL1["ShortName"],
                    description=itemL1["Name"],
                )
            )
            Rollback.topics.append(parentL1["id"])
            rootTopics.append(parentL1)
            for itemL2 in itemL1["Items"]:
                parentL2 = client.Topics.add(
                    models.Topic(
                        key=f"V{'.'.join([n.zfill(2) for n in itemL2['Shortcode'][1:].split('.')])}",
                        title=itemL2["Name"],
                        description=itemL2["Name"],
                        parent=parentL1,
                    )
                )
                Rollback.topics.append(parentL2["id"])
                for itemL3 in itemL2["Items"]:
                    t = []
                    if itemL3["L1"]["Required"] is True:
                        t.append(l1)
                    if itemL3["L2"]["Required"] is True:
                        t.append(l2)
                    if itemL3["L3"]["Required"] is True:
                        t.append(l3)
                    requirement = client.Requirements.add(
                        models.Requirement(
                            key=f"V{'.'.join([n.zfill(2) for n in itemL3['Shortcode'][1:].split('.')])}",
                            title=itemL2["Name"],
                            description=itemL3["Description"],
                            parent=parentL2,
                            visible="[DELETED," not in itemL3["Description"],
                            tags=t,
                        )
                    )
                    Rollback.requirements.append(requirement["id"])
                    if itemL3["CWE"] != []:
                        client.ExtraEntries.add(
                            models.ExtraEntry(
                                content=";".join(str(n) for n in itemL3["CWE"]),
                                extraTypeId=cve["id"],
                                requirementId=requirement["id"],
                            )
                        )
                    if itemL3["NIST"] != []:
                        client.ExtraEntries.add(
                            models.ExtraEntry(
                                content=";".join(str(n) for n in itemL3["NIST"]),
                                extraTypeId=nist["id"],
                                requirementId=requirement["id"],
                            )
                        )
        catalogue = client.Catalogues.add(
            models.Catalogue(
                title=f"{asvsData['Name']} ({asvsData['ShortName']})",
                description=asvsData["Description"],
                topics=rootTopics,
            )
        )
        logging.info(f"Catalogue with ID {catalogue['id']} created.")
    except Exception as e:
        panic(e, client)



def nistcsf(client: ReqDB):
    """Downloads and adds the NIST CSF to ReqDB

    :param client: ReqDB client
    :type client: ReqDB
    """

    logging.info("Start creating catalogues for 'NIST CSF'.")
    r = requests.get(
        "https://csrc.nist.gov/extensions/nudp/services/json/csf/download?olirids=all",
        stream=True,
    )
    r.raise_for_status()

    ee = excelextractor.ExcelExtractor(BytesIO(r.content))
    ee.setSheetFromId(1)

    ee.addHeader("Function")
    ee.addHeader("Category")
    ee.addHeader("Subcategory")
    ee.addHeader("Implementation Examples")

    ee.findHeaderColumns()

    data = ee.getData()

    o = {}

    for row in data:
        if row["Function"] != "":
            functionSplit = row["Function"].split(":", maxsplit=1)
            m = re.match(r"(.+) \((.+)\)", functionSplit[0])
            function = m.group(2)
            title = m.group(1)
            if function not in o:
                o[function] = {
                    "title": title,
                    "description": functionSplit[1].strip(),
                    "children": {},
                }
        if row["Category"] != "":
            categoryTitle, description = row["Category"].split(":", maxsplit=1)
            m = re.match(r"(.+) \((.+)\)", categoryTitle)
            category = m.group(2)
            title = m.group(1)
            if category not in o:
                o[function]["children"][category] = {
                    "title": title,
                    "description": description.strip(),
                    "requirements": {},
                }
        if (
            row["Subcategory"] != ""
            and row["Subcategory"].split(":", maxsplit=1)[0]
            not in o[function]["children"][category]["requirements"]
        ):
            requirement, title = row["Subcategory"].split(":", maxsplit=1)
            if title.startswith(" [Withdrawn"):
                title = row["Subcategory"]
            o[function]["children"][category]["requirements"][requirement] = {
                "title": title.strip(),
                "description": re.sub(r"Ex\d:", "*", row["Implementation Examples"]),
            }

    rootTopics = []

    try:
        for l1Key, itemL1 in o.items():
            parentL1 = client.Topics.add(
                models.Topic(
                    key=l1Key,
                    title=itemL1["title"],
                    description=itemL1["description"],
                )
            )
            Rollback.topics.append(parentL1["id"])
            rootTopics.append(parentL1)
            for l2Key, itemL2 in itemL1["children"].items():
                parentL2 = client.Topics.add(
                    models.Topic(
                        key=l2Key,
                        title=itemL2["title"],
                        description=itemL2["description"],
                        parent=parentL1,
                    )
                )
                Rollback.topics.append(parentL2["id"])
                for l3Key, itemL3 in itemL2["requirements"].items():
                    requirement = client.Requirements.add(
                        models.Requirement(
                            key=l3Key,
                            title=itemL3["title"],
                            description=itemL3["description"],
                            parent=parentL2,
                            tags=[],
                            visible="[Withdrawn" not in itemL3["title"],
                        )
                    )
                    Rollback.topics.append(requirement["id"])
        catalogue = client.Catalogues.add(
            models.Catalogue(
                title="NIST Cybersecurity Framework (CSF) 2.0",
                description="The NIST Cybersecurity Framework (CSF) 2.0 provides guidance to industry, government agencies, and other organizations to manage cybersecurity risks. It offers a taxonomy of high-level cybersecurity outcomes that can be used by any organization — regardless of its size, sector, or maturity — to better understand, assess, prioritize, and communicate its cybersecurity efforts. The CSF does not prescribe how outcomes should be achieved. Rather, it links to online resources that provide additional guidance on practices and controls that could be used to achieve those outcomes.",
                topics=rootTopics,
            )
        )
        logging.info(f"Catalogue with ID {catalogue['id']} created.")
    except Exception as e:
        panic(e, client)



def bsic5(client: ReqDB):
    """Downloads and adds the BSI C5 to ReqDB

    :param client: ReqDB client
    :type client: ReqDB
    """

    logging.info("Start creating catalogues for 'BSI C5'.")
    r = requests.get(
        "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/CloudComputing/ComplianceControlsCatalogue/2020/C5_2020_editable.xlsx?__blob=publicationFile&v=5",
        stream=True,
    )
    r.raise_for_status()

    ee = excelextractor.ExcelExtractor(BytesIO(r.content))
    ee.setSheetFromId(1)

    ee.addHeader("Area")
    ee.addHeader("ID")
    ee.addHeader("Title")
    ee.addHeader("Basic Criteria")
    ee.addHeader("Additional Criteria")
    ee.addHeader("Supplementary Information -\nAbout the Criteria")
    ee.addHeader("Supplementary Information -\nComplementary Customer Criteria")
    ee.addHeader(
        "Supplementary Information -\nNotes on Continuous Auditing - Feasibility"
    )
    ee.addHeader("Supplementary Information -\nNotes on Continuous Auditing")

    ee.findHeaderColumns()

    data = ee.getData()

    o = {}

    for row in data:
        if row["Area"] not in o.keys():
            o[row["Area"]] = {}

        o[row["Area"]][row["ID"]] = {
            "Title": row["Title"],
            "Basic Criteria": row["Basic Criteria"]
            .replace("\u2022", "*")
            .replace("\u201c", '"')
            .replace("\u201d", '"'),
            "Additional Criteria": row["Additional Criteria"]
            .replace("\u2022", "* ")
            .replace("\u201c", '"')
            .replace("\u201d", '"'),
            "Supplementary Information - About the Criteria": row[
                "Supplementary Information -\nAbout the Criteria"
            ]
            .replace("\u2022", "*")
            .replace("\u201c", '"')
            .replace("\u201d", '"'),
            "Supplementary Information - Complementary Customer Criteria": row[
                "Supplementary Information -\nComplementary Customer Criteria"
            ]
            .replace("\u2022", "*")
            .replace("\u201c", '"')
            .replace("\u201d", '"'),
            "Supplementary Information - Notes on Continuous Auditing - Feasibility": row[
                "Supplementary Information -\nNotes on Continuous Auditing - Feasibility"
            ]
            .replace("\u2022", "*")
            .replace("\u201c", '"')
            .replace("\u201d", '"'),
            "Supplementary Information - Notes on Continuous Auditing": row[
                "Supplementary Information -\nNotes on Continuous Auditing"
            ]
            .replace("\u2022", "*")
            .replace("\u201c", '"')
            .replace("\u201d", '"'),
        }

    try:
        ac = client.ExtraTypes.add(
            models.ExtraType(title="Additional Criteria", extraType=1, description="-")
        )
        Rollback.extraTypes.append(ac["id"])
        si1 = client.ExtraTypes.add(
            models.ExtraType(
                title="Supplementary Information - About the Criteria",
                extraType=1,
                description="-",
            )
        )
        Rollback.extraTypes.append(si1["id"])
        si2 = client.ExtraTypes.add(
            models.ExtraType(
                title="Supplementary Information - Complementary Customer Criteria",
                extraType=1,
                description="-",
            )
        )
        Rollback.extraTypes.append(si2["id"])
        si3 = client.ExtraTypes.add(
            models.ExtraType(
                title="Supplementary Information - Notes on Continuous Auditing - Feasibility",
                extraType=3,
                description="-",
            )
        )
        Rollback.extraTypes.append(si3["id"])
        si4 = client.ExtraTypes.add(
            models.ExtraType(
                title="Supplementary Information - Notes on Continuous Auditing",
                extraType=1,
                description="-",
            )
        )
        Rollback.extraTypes.append(si4["id"])

        rootTopics = []

        topicRe = re.compile(r"(.*?) \((.*?)\)")

        for k, v in o.items():

            kMatch = topicRe.match(k)
            parent = client.Topics.add(
                models.Topic(
                    key=f"C5-{kMatch.group(2)}",
                    title=kMatch.group(1),
                    description="-",
                )
            )
            Rollback.topics.append(parent["id"])

            rootTopics.append(parent)

            for ki, i in v.items():
                requirement = client.Requirements.add(
                    models.Requirement(
                        key=ki,
                        title=i["Title"],
                        description=i["Basic Criteria"],
                        parent=parent,
                        tags=[],
                    )
                )
                Rollback.topics.append(requirement["id"])
                client.ExtraEntries.add(
                    models.ExtraEntry(
                        content=i["Additional Criteria"],
                        extraTypeId=ac["id"],
                        requirementId=requirement["id"],
                    )
                )
                client.ExtraEntries.add(
                    models.ExtraEntry(
                        content=i["Supplementary Information - About the Criteria"],
                        extraTypeId=si1["id"],
                        requirementId=requirement["id"],
                    )
                )
                client.ExtraEntries.add(
                    models.ExtraEntry(
                        content=i[
                            "Supplementary Information - Complementary Customer Criteria"
                        ],
                        extraTypeId=si2["id"],
                        requirementId=requirement["id"],
                    )
                )
                client.ExtraEntries.add(
                    models.ExtraEntry(
                        content=i[
                            "Supplementary Information - Notes on Continuous Auditing - Feasibility"
                        ],
                        extraTypeId=si3["id"],
                        requirementId=requirement["id"],
                    )
                )
                client.ExtraEntries.add(
                    models.ExtraEntry(
                        content=i[
                            "Supplementary Information - Notes on Continuous Auditing"
                        ],
                        extraTypeId=si4["id"],
                        requirementId=requirement["id"],
                    )
                )

        catalogue = client.Catalogues.add(
            models.Catalogue(
                title="Cloud Computing Compliance Criteria Catalogue (C5:2020 Criteria)",
                description="The C5 (Cloud Computing Compliance Criteria Catalogue) criteria catalogue specifies minimum requirements for secure cloud computing and is primarily intended for professional cloud providers, their auditors and customers.",
                topics=rootTopics,
            )
        )
        logging.info(f"Catalogue with ID {catalogue['id']} created.")
    except Exception as e:
        panic(e, client)


def samm(client: ReqDB):
    """Downloads and adds the OWASP SAMM to ReqDB

    :param client: ReqDB client
    :type client: ReqDB
    """

    logging.info("Start creating catalogues for 'OWASP SAMM'.")
    r = requests.get(
        "https://github.com/owaspsamm/core/releases/download/v2.1.0/SAMM_spreadsheet.xlsx",
        stream=True,
    )
    r.raise_for_status()

    ee = excelextractor.ExcelExtractor(BytesIO(r.content))
    ee.setSheetFromName("imp-questions")

    ee.addHeader("ID")
    ee.addHeader("Business Function")
    ee.addHeader("Security Practice")
    ee.addHeader("Activity")
    ee.addHeader("Maturity")
    ee.addHeader("Question")
    ee.addHeader("Guidance")

    ee.findHeaderColumns()

    data = ee.getData()

    o = {}

    for row in data:
        ids = row["ID"].split("-")

        if ids[0] not in o.keys():
            o[ids[0]] = {"title": row["Business Function"], "topics": {}}
        if f"{ids[0]}-{ids[1]}" not in o[ids[0]]["topics"].keys():
            o[ids[0]]["topics"][f"{ids[0]}-{ids[1]}"] = {
                "title": row["Security Practice"],
                "topics": {},
            }
        if (
            f"{ids[0]}-{ids[1]}-{ids[2]}"
            not in o[ids[0]]["topics"][f"{ids[0]}-{ids[1]}"]["topics"].keys()
        ):
            o[ids[0]]["topics"][f"{ids[0]}-{ids[1]}"]["topics"][
                f"{ids[0]}-{ids[1]}-{ids[2]}"
            ] = {
                "title": row["Activity"],
                "requirements": {},
            }

        o[ids[0]]["topics"][f"{ids[0]}-{ids[1]}"]["topics"][
            f"{ids[0]}-{ids[1]}-{ids[2]}"
        ]["requirements"][row["ID"]] = {
            "title": row["Question"],
            "description": row["Guidance"],
            "tag": row["Maturity"],
        }

    try:
        maturity = {}
        maturity["1"] = client.Tags.add(models.Tag(name="Maturity 1"))
        Rollback.tags.append(maturity["1"]["id"])
        maturity["2"] = client.Tags.add(models.Tag(name="Maturity 2"))
        Rollback.tags.append(maturity["2"]["id"])
        maturity["3"] = client.Tags.add(models.Tag(name="Maturity 3"))
        Rollback.tags.append(maturity["3"]["id"])

        rootTopics = []

        for keyL1, itemL1 in o.items():
            parentL1 = client.Topics.add(
                models.Topic(key=keyL1, title=itemL1["title"], description="-")
            )
            Rollback.topics.append(parentL1["id"])
            rootTopics.append(parentL1)
            for keyL2, itemL2 in itemL1["topics"].items():
                parentL2 = client.Topics.add(
                    models.Topic(
                        key=keyL2, title=itemL2["title"], description="-", parent=parentL1
                    )
                )
                Rollback.topics.append(parentL2["id"])
                for keyL3, itemL3 in itemL2["topics"].items():
                    parentL3 = client.Topics.add(
                        models.Topic(
                            key=keyL3,
                            title=itemL3["title"],
                            description="-",
                            parent=parentL2,
                        )
                    )
                    Rollback.topics.append(parentL3["id"])
                    for keyL4, itemL4 in itemL3["requirements"].items():
                        requirement = client.Requirements.add(
                            models.Requirement(
                                key=keyL4,
                                title=itemL4["title"],
                                description=itemL4["description"],
                                parent=parentL3,
                                tags=[maturity[itemL4["tag"]]],
                            )
                        )
                        Rollback.requirements.append(requirement["id"])

        catalogue = client.Catalogues.add(
            models.Catalogue(
                title="Software Assurance Maturity Model (SAMM)",
                description="SAMM provides an effective and measurable way for all types of organizations to analyze and improve their software security posture.",
                topics=rootTopics,
            )
        )

        logging.info(f"Catalogue with ID {catalogue['id']} created.")
    except Exception as e:
        panic(e, client)


def csaccm(client: ReqDB):
    """Downloads and adds the CSA CCM to ReqDB

    :param client: ReqDB client
    :type client: ReqDB
    """

    logging.info("Start creating catalogues for 'CSA CCM'.")
    r = requests.get(
        "https://cloudsecurityalliance.org/download/artifacts/ccm-machine-readable-bundle-json-yaml-oscal",
        stream=True,
    )
    r.raise_for_status()

    with ZipFile(BytesIO(r.content)) as zip:
        path = None
        for name in zip.namelist():
            if name.endswith("/CCM/primary-dataset.json"):
                path = name
        if path is None:
            raise FileNotFoundError("Target source file not found in zip")
        with zip.open(path) as f:
            ccm = json.load(f)

    rootTopics = []

    try:
        for domain in ccm["domains"]:
            parentL1 = client.Topics.add(
                models.Topic(key=domain["id"], title=domain["title"], description="-")
            )
            Rollback.topics.append(parentL1["id"])
            rootTopics.append(parentL1)
            for control in domain["controls"]:
                requirement = client.Requirements.add(
                    models.Requirement(
                        key=control["id"],
                        title=control["title"],
                        description=control["specification"],
                        parent=parentL1,
                        tags=[],
                    )
                )
                Rollback.requirements.append(requirement["id"])

        catalogue = client.Catalogues.add(
            models.Catalogue(
                title=f"{ccm['name']} ({ccm['version']})",
                description=f"{ccm['name']}, Version {ccm['version']}. See {ccm['url']}",
                topics=rootTopics,
            )
        )

        logging.info(f"Catalogue with ID {catalogue['id']} created.")
    except Exception as e:
        logging.error(f"Error while inserting data: {e}")
        logging.info(f"Rolling back...")
        Rollback.rollbackAll(client)
        logging.debug(f"Rolling complete")
        logging.critical(f"Exiting due to critical error")
        sys.exit()


def ciscontrols(client: ReqDB, file: str):
    """Downloads and adds the CIS Controls to ReqDB

    :param client: ReqDB client
    :type client: ReqDB
    :param file: Path to the excel containing the CIS Controls from the CIS website
    :type file: string
    """
    
    logging.info("Start creating catalogues for 'CIS Controls'.")

    ee = excelextractor.ExcelExtractor(file)
    ee.setSheetFromName("Controls V8")

    ee.addHeader("CIS Control")
    ee.addHeader("CIS Safeguard")
    ee.addHeader("Asset Type")
    ee.addHeader("Security Function")
    ee.addHeader("Title")
    ee.addHeader("Description")
    ee.addHeader("IG1")
    ee.addHeader("IG2")
    ee.addHeader("IG3")

    ee.findHeaderColumns()

    data = ee.getData()

    o = {}
    assets = {}
    functions = {}

    for row in data:
        if row["CIS Safeguard"] == "":
            o[f"CIS-{row['CIS Control']}"] = {
                "title": row["Title"],
                "description": row["Description"],
                "requirements": {},
            }
        else:
            if row["Asset Type"] != "" and row["Asset Type"] not in assets:
                assets[row["Asset Type"]] = None
            if (
                row["Security Function"] != ""
                and row["Security Function"] not in assets
            ):
                functions[row["Security Function"]] = None

            level = []
            if row["IG1"] == "x":
                level.append("IG1")
            if row["IG2"] == "x":
                level.append("IG2")
            if row["IG3"] == "x":
                level.append("IG3")

            o[f"CIS-{row['CIS Control']}"]["requirements"][
                f"CIS-{row['CIS Safeguard'].replace(',', '.')}"
            ] = {
                "title": row["Title"],
                "description": row["Description"],
                "asset": row["Asset Type"],
                "function": row["Security Function"],
                "level": level,
            }

    rootTopics = []

    try:
        igs = {}
        igs["IG1"] = client.Tags.add(models.Tag(name="IG1"))
        Rollback.tags.append(igs["IG1"]["id"])
        igs["IG2"] = client.Tags.add(models.Tag(name="IG2"))
        Rollback.tags.append(igs["IG2"]["id"])
        igs["IG3"] = client.Tags.add(models.Tag(name="IG3"))
        Rollback.tags.append(igs["IG2"]["id"])
        
        for k in assets:
            assets[k] = client.Tags.add(models.Tag(name=k))
            Rollback.tags.append(assets[k]["id"])
        for k in functions:
            functions[k] = client.Tags.add(models.Tag(name=k))
            Rollback.tags.append(functions[k]["id"])

        for domainKey, domain in o.items():
            parentL1 = client.Topics.add(
                models.Topic(
                    key=domainKey, title=domain["title"], description=domain["description"]
                )
            )
            Rollback.topics.append(parentL1["id"])
            rootTopics.append(parentL1)
            for requirementKey, requirement in domain["requirements"].items():
                tags = []
                tags.append(functions[requirement["function"]])
                tags.append(assets[requirement["asset"]])
                for i in requirement["level"]:
                    tags.append(igs[i])
                requirement = client.Requirements.add(
                    models.Requirement(
                        key=requirementKey,
                        title=requirement["title"],
                        description=requirement["description"],
                        parent=parentL1,
                        tags=tags,
                    )
                )
                Rollback.requirements.append(requirement["id"])

        catalogue = client.Catalogues.add(
            models.Catalogue(
                title="CIS Controls Version 8",
                description="The CIS Critical Security Controls (CIS Controls) are a prioritized set of Safeguards to mitigate the most prevalent cyber-attacks against systems and networks. They are mapped to and referenced by multiple legal, regulatory, and policy frameworks.",
                topics=rootTopics,
            )
        )

        logging.info(f"Catalogue with ID {catalogue['id']} created.")
    except Exception as e:
        panic(e, client)


def bsigrundschutz(client: ReqDB):
    """Downloads and adds the BSI Grundschutz to ReqDB

    :param client: ReqDB client
    :type client: ReqDB
    """

    logging.info("Start creating catalogues for 'BSI Grundschutz'.")
    logging.debug("Downloading source file (XML_Kompendium_2023.xml).")

    r = requests.get(
        "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-GS-Kompendium/XML_Kompendium_2023.xml?__blob=publicationFile&v=4",
    )
    r.raise_for_status()

    logging.debug("Start parsing XML... ")
    logging.debug(
        "This might take a while as the BSI is incompetent and unwilling to provide a proper machine readable file to get the building blocks and threats."
    )

    root = ET.fromstring(r.text)

    namespaces = {"ns": "http://docbook.org/ns/docbook"}

    requirementChapters = root.findall(
        "./ns:chapter/ns:section/ns:section[ns:title='Anforderungen']/....", namespaces
    )
    elementalThreats = root.findall(
        "./ns:chapter[ns:title='Elementare Gefährdungen']/ns:section", namespaces
    )
    buildingBlocks = readBSIBuildingBlocks(requirementChapters, namespaces)
    try:
        logging.debug("Start writing requirements to ReqDB.")
        writeBSIRequirements(client, buildingBlocks)
        logging.debug("Writing requirements done.")
        logging.debug("Start writing threats to ReqDB.")
        writeBSIGrundschutzThreats(client, elementalThreats, buildingBlocks, namespaces)
        logging.debug("Writing threats done.")
    except Exception as e:
        panic(e, client)


def convertXMLDescriptionToMD(XMLDescription: ET.Element) -> str:
    """Converts an XML Path to a markdown string and removes the first line (title line)

    :param xml.etree.Element XMLDescription: The XML path element for conversion
    :return string: A markdown formatted string from the XML path without first line
    """
    return (
        pypandoc.convert_text(
            ET.tostring(XMLDescription, encoding="utf8"), "md", format="docbook", extra_args=["--wrap=none", "--markdown-headings=atx"]
        )
        .split("\n\n", 1)[1]
        .strip()
    )


def writeBSIGrundschutzThreats(client: ReqDB, elementalThreatsET: list[: ET.Element], buildingBlocks: dict, namespaces: dict):
    """Writes the BSI Grundschutz threats from the XML tree into ReqDB

    :param client client: ReqDB client
    :param xml.etree.Element elementalThreatsET: "section" element containing the elemental threats
    :param dict buildingBlocks: Dictionary containing the BSI building blocks
    :param dict namespaces: namespace for docbook XML schema
    """
    elementalThreats = {}

    elementalTag = client.Tags.add(models.Tag(name="Elementar"))
    Rollback.tags.append(elementalTag["id"])
    topicTag = client.Tags.add(models.Tag(name="Themenspezifisch"))
    Rollback.tags.append(topicTag["id"])

    elementalRoot = client.Topics.add(
        models.Topic(
            key=f"EG",
            title="Elementare Gefährdungen",
            description="",
            parent=None,
        )
    )
    Rollback.topics.append(elementalRoot["id"])

    for e in elementalThreatsET:
        titleLine = (
            e.find("./ns:title", namespaces).text.replace("G ", "G", 1).split(" ", 1)
        )
        requirement = client.Requirements.add(
            models.Requirement(
                key=titleLine[0],
                title=titleLine[1],
                description=convertXMLDescriptionToMD(e),
                parent=elementalRoot,
                tags=[elementalTag],
            )
        )
        Rollback.requirements.append(requirement["id"])
        elementalThreats[titleLine[0]] = {
            "title": titleLine[1],
            "description": convertXMLDescriptionToMD(e),
        }

    buildingBlockRoots = []
    for buildingBlockKey, buildingBlock in buildingBlocks.items():
        buildingBlockRoot = client.Topics.add(
            models.Topic(
                key=f"{buildingBlockKey} (G)",
                title=f"{buildingBlock['title']} Gefährdungen",
                description="",
                parent=None,
            )
        )
        Rollback.topics.append(buildingBlockRoot["id"])
        buildingBlockRoots.append(buildingBlockRoot)
        for topicKey, topic in buildingBlock["children"].items():
            parentTopic = client.Topics.add(
                models.Topic(
                    key=f"{topicKey}.G",
                    title=f"{topic['title']} Gefährdungen",
                    description="",
                    parent=buildingBlockRoot,
                )
            )
            Rollback.topics.append(parentTopic["id"])
            for threatKey, threat in topic["threats"].items():
                requirement = client.Requirements.add(
                    models.Requirement(
                        key=threatKey,
                        title=threat["title"],
                        description=threat["description"],
                        parent=parentTopic,
                        tags=[topicTag],
                    )
                )
                Rollback.requirements.append(requirement["id"])

    catalogue = client.Catalogues.add(
        models.Catalogue(
            title="BSI Grundschutz Gefährdungen (2023)",
            description="Elementare und themenspezifische Gefährdungen aus dem BSI Grundschutz (2023)",
            topics=buildingBlockRoots + [elementalRoot],
        )
    )
    Rollback.catalogues.append(catalogue["id"])
    logging.info(f"Catalogue '{catalogue['title']}' with ID {catalogue['id']} created.")


def writeBSIRequirements(client: ReqDB, buildingBlocks: dict):
    """Writes requirements from the building blocks into ReqDB

    :param client client: The ReqDB client
    :param dict buildingBlocks: BSI building blocks
    """

    tags = {}
    tags["B"] = client.Tags.add(models.Tag(name="Basis"))
    Rollback.tags.append(tags["B"]["id"])
    tags["S"] = client.Tags.add(models.Tag(name="Standard"))
    Rollback.tags.append(tags["S"]["id"])
    tags["H"] = client.Tags.add(models.Tag(name="Erhöht"))
    Rollback.tags.append(tags["H"]["id"])

    buildingBlockRoots = []
    for buildingBlockKey, buildingBlock in buildingBlocks.items():
        buildingBlockRoot = client.Topics.add(
            models.Topic(
                key=buildingBlockKey,
                title=buildingBlock["title"],
                description="",
                parent=None,
            )
        )
        Rollback.topics.append(buildingBlockRoot["id"])
        buildingBlockRoots.append(buildingBlockRoot)
        for topicKey, topic in buildingBlock["children"].items():
            parentTopic = client.Topics.add(
                models.Topic(
                    key=topicKey,
                    title=topic["title"],
                    description="",
                    parent=buildingBlockRoot,
                )
            )
            Rollback.topics.append(parentTopic["id"])
            for requirementKey, requirement in topic["requirements"].items():
                requirementReturn = client.Requirements.add(
                    models.Requirement(
                        key=requirementKey,
                        title=requirement["title"],
                        description=requirement["description"],
                        parent=parentTopic,
                        tags=[
                            (
                                tags[requirement["tag"]]
                                if requirement["tag"] is not None
                                else None
                            )
                        ],
                        visible=(
                            False
                            if requirement["title"].startswith("ENTFALLEN (")
                            else True
                        ),
                    )
                )
                Rollback.requirements.append(requirementReturn["id"])

    catalogue = client.Catalogues.add(
        models.Catalogue(
            title="BSI Grundschutz Bausteine (2023)",
            description="Anforderungsbausteine des BSI Grundschutzes (2023)",
            topics=buildingBlockRoots,
        )
    )
    Rollback.catalogues.append(catalogue["id"])
    logging.info(f"Catalogue '{catalogue['title']}' with ID {catalogue['id']} created.")


def readBSIBuildingBlocks(topicsET: ET.Element, namespaces: dict) -> dict:
    """Reads the BSI Grundschutz building blocks from the XML tree

    :param xml.etree.Element topicsET: "chapter" elements containing the building blocks
    :param dict namespaces: namespace for docbook XML schema
    :return dict: Dictionary containing the building blocks with requirements and threats
    """
    buildingBlocks = {}
    tagRe = re.compile(r".*\((B|S|H)\).*")

    for e in topicsET:
        chapterTitle = e.find("./ns:title", namespaces).text.split(" ", 1)
        buildingBlocks[chapterTitle[0]] = {"title": chapterTitle[1], "children": {}}

        topics = e.findall("./ns:section", namespaces)

        for t in topics:
            topicTitleLine = t.find("./ns:title", namespaces).text.split(" ", 1)
            topicKey = '.'.join([n.zfill(2) for n in topicTitleLine[0].split('.')])
            buildingBlocks[chapterTitle[0]]["children"][topicKey] = {
                "title": topicTitleLine[1],
                "threats": {},
                "requirements": {},
            }
            threatSections = t.findall(
                "./ns:section[ns:title='Gefährdungslage']/ns:section", namespaces
            )
            threatIndex = 1
            for th in threatSections:
                titleLine = th.find("./ns:title", namespaces).text
                buildingBlocks[chapterTitle[0]]["children"][topicKey][
                    "threats"
                ][f"{topicKey}.G{threatIndex:02}"] = {
                    "title": titleLine,
                    "description": convertXMLDescriptionToMD(th),
                }
                threatIndex += 1
            requirementSections = t.findall(
                "./ns:section[ns:title='Anforderungen']/ns:section/ns:section",
                namespaces,
            )
            for r in requirementSections:
                titleLine = r.find("./ns:title", namespaces).text.split(" ", 1)
                if titleLine[0] == "OPS.2.3A22": # Fix for BSI incompetence
                    titleLine[0] = "OPS.2.3.A22"
                titleKeySplit = titleLine[0].split(".A", 1)
                titleLine[0] = ".A".join([titleKeySplit[0], titleKeySplit[1].zfill(2)])
                requirement = '.'.join([n.zfill(2) for n in titleLine[0].split('.')])
                tagMatch = tagRe.match(titleLine[1])
                tag = tagMatch.group(1) if tagMatch is not None else None
                buildingBlocks[chapterTitle[0]]["children"][topicKey][
                    "requirements"
                ][requirement] = {
                    "title": titleLine[1],
                    "tag": tag,
                    "description": convertXMLDescriptionToMD(r),
                }
    return buildingBlocks

def panic(e: Exception, client: ReqDB):
    """Handles upload errors with rollback

    :param e: The thrown exception
    :type e: Exception
    :param client: the ReqDB client connection
    :type client: ReqDB
    """
    logging.error(f"Error while inserting data: {e}")
    logging.info(f"Rolling back...")
    Rollback.rollbackAll(client)
    logging.debug(f"Rolling complete")
    logging.critical(f"Exiting due to critical error")
    sys.exit()
