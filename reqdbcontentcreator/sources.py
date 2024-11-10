import requests
import re
from io import BytesIO
from excelextractor import excelextractor
from reqdb import models
import json
from zipfile import ZipFile


def asvs(client):
    """Downloads and adds the OWASP ASVS to ReqDB

    :param client: ReqDB client
    :type client: ReqDB
    """

    r = requests.get(
        "https://github.com/OWASP/ASVS/releases/download/v4.0.3_release/OWASP.Application.Security.Verification.Standard.4.0.3-en.json"
    )
    r.raise_for_status()
    asvsData = r.json()

    l1 = client.Tags.add(models.Tag(name="Level 1"))
    l2 = client.Tags.add(models.Tag(name="Level 2"))
    l3 = client.Tags.add(models.Tag(name="Level 3"))

    nist = client.ExtraTypes.add(
        models.ExtraType(title="NIST Ref", extraType=3, description="NIST Reference")
    )
    cve = client.ExtraTypes.add(
        models.ExtraType(title="CVE Ref", extraType=3, description="CVE Reference")
    )

    rootTopics = []

    for itemL1 in asvsData["Requirements"]:
        parentL1 = client.Topics.add(
            models.Topic(
                key=itemL1["Shortcode"],
                title=itemL1["ShortName"],
                description=itemL1["Name"],
            )
        )
        rootTopics.append(parentL1)
        for itemL2 in itemL1["Items"]:
            parentL2 = client.Topics.add(
                models.Topic(
                    key=itemL2["Shortcode"],
                    title=itemL2["Name"],
                    description=itemL2["Name"],
                    parent=parentL1,
                )
            )
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
                        key=itemL3["Shortcode"],
                        title=itemL2["Name"],
                        description=itemL3["Description"],
                        parent=parentL2,
                        visible="[DELETED," not in itemL3["Description"],
                        tags=t,
                    )
                )
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

    print(f"Catalogue with ID {catalogue['id']} created.")


def nistcsf(client):
    """Downloads and adds the NIST CSF to ReqDB

    :param client: ReqDB client
    :type client: ReqDB
    """

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
                "description": re.sub("Ex\d:", "*", row["Implementation Examples"]),
            }

    rootTopics = []

    for l1Key, itemL1 in o.items():
        parentL1 = client.Topics.add(
            models.Topic(
                key=l1Key,
                title=itemL1["title"],
                description=itemL1["description"],
            )
        )
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

    catalogue = client.Catalogues.add(
        models.Catalogue(
            title="NIST Cybersecurity Framework (CSF) 2.0",
            description="The NIST Cybersecurity Framework (CSF) 2.0 provides guidance to industry, government agencies, and other organizations to manage cybersecurity risks. It offers a taxonomy of high-level cybersecurity outcomes that can be used by any organization — regardless of its size, sector, or maturity — to better understand, assess, prioritize, and communicate its cybersecurity efforts. The CSF does not prescribe how outcomes should be achieved. Rather, it links to online resources that provide additional guidance on practices and controls that could be used to achieve those outcomes.",
            topics=rootTopics,
        )
    )

    print(f"Catalogue with ID {catalogue['id']} created.")


def bsic5(client):
    """Downloads and adds the BSI C5 to ReqDB

    :param client: ReqDB client
    :type client: ReqDB
    """

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

    ac = client.ExtraTypes.add(
        models.ExtraType(title="Additional Criteria", extraType=1, description="-")
    )
    si1 = client.ExtraTypes.add(
        models.ExtraType(
            title="Supplementary Information - About the Criteria",
            extraType=1,
            description="-",
        )
    )
    si2 = client.ExtraTypes.add(
        models.ExtraType(
            title="Supplementary Information - Complementary Customer Criteria",
            extraType=1,
            description="-",
        )
    )
    si3 = client.ExtraTypes.add(
        models.ExtraType(
            title="Supplementary Information - Notes on Continuous Auditing - Feasibility",
            extraType=3,
            description="-",
        )
    )
    si4 = client.ExtraTypes.add(
        models.ExtraType(
            title="Supplementary Information - Notes on Continuous Auditing",
            extraType=1,
            description="-",
        )
    )

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

    print(f"Catalogue with ID {catalogue['id']} created.")


def samm(client):
    """Downloads and adds the OWASP SAMM to ReqDB

    :param client: ReqDB client
    :type client: ReqDB
    """

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

    maturity = {
        "1": client.Tags.add(models.Tag(name="Maturity 1")),
        "2": client.Tags.add(models.Tag(name="Maturity 2")),
        "3": client.Tags.add(models.Tag(name="Maturity 3")),
    }

    rootTopics = []

    for keyL1, itemL1 in o.items():
        parentL1 = client.Topics.add(
            models.Topic(key=keyL1, title=itemL1["title"], description="-")
        )
        rootTopics.append(parentL1)
        for keyL2, itemL2 in itemL1["topics"].items():
            parentL2 = client.Topics.add(
                models.Topic(
                    key=keyL2, title=itemL2["title"], description="-", parent=parentL1
                )
            )
            for keyL3, itemL3 in itemL2["topics"].items():
                parentL3 = client.Topics.add(
                    models.Topic(
                        key=keyL3,
                        title=itemL3["title"],
                        description="-",
                        parent=parentL2,
                    )
                )
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

    catalogue = client.Catalogues.add(
        models.Catalogue(
            title="Software Assurance Maturity Model (SAMM)",
            description="SAMM provides an effective and measurable way for all types of organizations to analyze and improve their software security posture.",
            topics=rootTopics,
        )
    )

    print(f"Catalogue with ID {catalogue['id']} created.")


def csaccm(client):
    """Downloads and adds the CSA CCM to ReqDB

    :param client: ReqDB client
    :type client: ReqDB
    """

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

    for domain in ccm["domains"]:
        parentL1 = client.Topics.add(
            models.Topic(key=domain["id"], title=domain["title"], description="-")
        )
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

    catalogue = client.Catalogues.add(
        models.Catalogue(
            title=f"{ccm['name']} ({ccm['version']})",
            description=f"{ccm['name']}, Version {ccm['version']}. See {ccm['url']}",
            topics=rootTopics,
        )
    )

    print(f"Catalogue with ID {catalogue['id']} created.")


def ciscontrols(client, file):
    """Downloads and adds the CIS Controls to ReqDB

    :param client: ReqDB client
    :type client: ReqDB
    :param file: Path to the excel containing the CIS Controls from the CIS website
    :type file: string
    """
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

    igs = {
        "IG1": client.Tags.add(models.Tag(name="IG1")),
        "IG2": client.Tags.add(models.Tag(name="IG2")),
        "IG3": client.Tags.add(models.Tag(name="IG3")),
    }

    for k in assets:
        assets[k] = client.Tags.add(models.Tag(name=k))
    for k in functions:
        functions[k] = client.Tags.add(models.Tag(name=k))

    for domainKey, domain in o.items():
        parentL1 = client.Topics.add(
            models.Topic(
                key=domainKey, title=domain["title"], description=domain["description"]
            )
        )
        rootTopics.append(parentL1)
        for requirementKey, requirement in domain["requirements"].items():
            tags = []
            tags.append(functions[requirement["function"]])
            tags.append(assets[requirement["asset"]])
            for i in requirement["level"]:
                tags.append(igs[i])
            client.Requirements.add(
                models.Requirement(
                    key=requirementKey,
                    title=requirement["title"],
                    description=requirement["description"],
                    parent=parentL1,
                    tags=tags,
                )
            )

    catalogue = client.Catalogues.add(
        models.Catalogue(
            title="CIS Controls Version 8",
            description="The CIS Critical Security Controls (CIS Controls) are a prioritized set of Safeguards to mitigate the most prevalent cyber-attacks against systems and networks. They are mapped to and referenced by multiple legal, regulatory, and policy frameworks.",
            topics=rootTopics,
        )
    )

    print(f"Catalogue with ID {catalogue['id']} created.")
