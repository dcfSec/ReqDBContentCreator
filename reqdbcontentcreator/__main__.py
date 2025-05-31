import argparse
import logging
from os import getenv
from msal import PublicClientApplication
from reqdb import ReqDB
import yaml
from reqdbcontentcreator import sources


def getArgs():
    """Reads the command line arguments and stores them.

    positional arguments:
    {asvs4,asvs5,samm,bsic5,nistcsf,csaccm,ciscontrols,bsigrundschutz}
                            Source standard to upload to ReqDB

    options:
    -h, --help            show this help message and exit
    -c CONFIG, --config CONFIG
                            Path to the config file
    --create-config       Creates a config file with the given config parameters and exits. Saves the config into the given config file
    -t TARGET, --target TARGET
                            The target ReqDB server
    --tenant-id TENANT_ID
                            The tenant ID for the Entra ID oauth provider. Defaults to the env var 'REQDB_CLIENT_TENANT_ID'
    --client-id CLIENT_ID
                            The client ID for the Entra ID oauth provider. Defaults to the env var 'REQDB_CLIENT_CLIENT_ID'
    --insecure            Allows the connection to ReqDB over TLS. Use this only in local test environments. This will leak your access token
    -f FILE, --file FILE  Input file used as a source for the standard. This is only needed for the CIS Controls as they are behind a login wall. Will be ignored by the other sources
    """
    parser = argparse.ArgumentParser(
        prog="reqdbcontentcreator",
        description="Creates requirements in ReqDB from public standards",
    )
    parser.add_argument(
        "source",
        help="Source standard to upload to ReqDB",
        choices=[
            "asvs4",
            "asvs5",
            "samm",
            "bsic5",
            "nistcsf",
            "csaccm",
            "ciscontrols",
            "bsigrundschutz",
        ],
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Path to the config file",
    )
    parser.add_argument(
        "--create-config",
        help="Creates a config file with the given config parameters and exits. Saves the config into the given config file",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-t",
        "--target",
        help="The target ReqDB server",
    )
    parser.add_argument(
        "--tenant-id",
        help="The tenant ID for the Entra ID oauth provider. Defaults to the env var 'REQDB_CLIENT_TENANT_ID'",
        default=getenv("REQDB_CLIENT_TENANT_ID", None),
    )
    parser.add_argument(
        "--client-id",
        help="The client ID for the Entra ID oauth provider. Defaults to the env var 'REQDB_CLIENT_CLIENT_ID'",
        default=getenv("REQDB_CLIENT_CLIENT_ID", None),
    )
    parser.add_argument(
        "--insecure",
        help="Allows the connection to ReqDB over TLS. Use this only in local test environments. This will leak your access token",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-f",
        "--file",
        help="Input file used as a source for the standard. This is only needed for the CIS Controls as they are behind a login wall. Will be ignored by the other sources",
    )
    parser.add_argument(
        "-d",
        "--debug",
        help="Turns on debug log output",
        action="store_true",
        default=False,
    )

    args = parser.parse_args()

    if args.create_config is True and not args.config:
        raise SyntaxError(
            "A config file (-c, --config) must be given to write a config"
        )
    return args


def getAccessToken(tenantID, clientID):
    """
    Returns an access token for the given client in the given tenant

    :param string tenantID: Tenant ID from the used Entra ID tenant
    :param string clientID: oAuth client ID for the ReqDB application
    :raises PermissionError: Raises if an access token could not be fetched
    :raises RuntimeError: Raises if an unknown error occurred
    :return string: oAuth access token
    """
    scopes = [
        f"api://{clientID}/ReqDB.Requirements.Reader",
        f"api://{clientID}/ReqDB.Requirements.Writer",
    ]
    app = PublicClientApplication(
        clientID, authority=f"https://login.microsoftonline.com/{tenantID}"
    )

    result = app.acquire_token_interactive(scopes=scopes)

    if result:
        if "access_token" in result:
            return result["access_token"]
        else:
            raise PermissionError(
                f"{result.get('error')}: {result.get('error_description')} [{result.get('correlation_id')}]"
            )
    else:
        raise RuntimeError("Unknown error")


def createConfig(target, tenantID, clientID, config):
    """Creates the config file

    :param target: Target ReqDB server
    :type target: string
    :param tenantID: Tenant ID for the Entra ID config
    :type tenantID: string
    :param clientID: Client ID from the Entra ID app
    :type clientID: string
    :param config: Config file name
    :type config: string
    """
    c = {"target": target, "auth": {"tenant": tenantID, "client": clientID}}
    with open(config, "w") as f:
        yaml.dump(c, f)


def loadConfig(config):
    """Loads the config from the given file

    :param config: Config file name
    :type config: string
    :return: Tuple with the needed config variables
    :rtype: Tuple(string,string,string)
    """
    with open(config, "r") as f:
        c = yaml.safe_load(f)
    return c["target"], c["auth"]["tenant"], c["auth"]["client"]


def main():
    args = getArgs()

    logging.basicConfig(
        format="[%(asctime)s][%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.INFO,
    )

    logging.getLogger().setLevel(logging.INFO if not args.debug else logging.DEBUG)

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("msal").setLevel(logging.WARNING)
    logging.getLogger("pypandoc").setLevel(logging.WARNING)

    if args.create_config:
        createConfig(args.target, args.tenant_id, args.client_id, args.config)
        exit(0)
    if args.config:
        target, tenantID, clientID = loadConfig(args.config)
    else:
        target, tenantID, clientID = args.target, args.tenant_id, args.client_id

    token = getAccessToken(tenantID, clientID)

    client = ReqDB(f"{target}", token, args.insecure)

    sourceFn = {
        "asvs4": sources.asvs4,
        "asvs5": sources.asvs5,
        "samm": sources.samm,
        "bsic5": sources.bsic5,
        "nistcsf": sources.nistcsf,
        "csaccm": sources.csaccm,
        "bsigrundschutz": sources.bsigrundschutz,
    }
    if args.source in sourceFn.keys():
        sourceFn[args.source](client)
    elif args.source == "ciscontrols":
        if not args.file:
            raise FileNotFoundError(
                "A xlsx file containing the CIS Controls must be provided with --file. Download at https://learn.cisecurity.org/cis-controls-download-v8"
            )
        sources.ciscontrols(client, args.file)


if __name__ == "__main__":
    main()
