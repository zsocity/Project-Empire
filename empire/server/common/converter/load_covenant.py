import yaml


def _convert_covenant_to_empire(covenant_dict: dict, file_path: str):
    empire_yaml = {
        "name": covenant_dict["Name"],
        "authors": _convert_convenant_authors_to_empire([covenant_dict["Author"]]),
        "description": covenant_dict["Description"],
        "language": covenant_dict["Language"].lower(),
        "compatible_dot_net_versions": covenant_dict["CompatibleDotNetVersions"],
        "script": covenant_dict["Code"],
        "options": _convert_covenant_options_to_empire(
            covenant_dict["Options"],
            covenant_dict.get("Empire", {}).get("options", []),
            covenant_dict["CompatibleDotNetVersions"],
        ),
        "compiler_yaml": yaml.dump([covenant_dict], sort_keys=False),
    }

    if "advanced" in covenant_dict.get("Empire", {}):
        empire_yaml["advanced"] = covenant_dict["Empire"]["advanced"]

    return empire_yaml


def _convert_convenant_authors_to_empire(covenant_authors: list[dict]):
    empire_authors = []
    for author in covenant_authors:
        empire_authors.append(
            {
                "handle": author["Handle"],
                "name": author["Name"],
                "link": author["Link"],
            }
        )
    return empire_authors


def _convert_covenant_options_to_empire(
    covenant_options: list[dict],
    empire_options: list[dict],
    compatible_versions: list[str],
):
    empire_options.append(
        {
            "name": "Agent",
            "value": "",
            "description": "Agent to run module on.",
            "required": True,
            "suggested_values": [],
        }
    )
    empire_options.append(
        {
            "name": "DotNetVersion",
            "value": compatible_versions[0],
            "description": ".NET version to compile against",
            "required": True,
            "suggested_values": compatible_versions,
            "strict": True,
        }
    )

    for option in covenant_options:
        empire_options.append(
            {
                "name": option["Name"],
                "value": option["Value"],
                "description": option["Description"],
                "required": not option["Optional"],
                "suggested_values": option["SuggestedValues"],
            }
        )

    return empire_options
