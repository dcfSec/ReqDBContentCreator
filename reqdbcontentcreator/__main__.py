import argparse
from collections.abc import Callable
import logging
from os import getenv

import yaml
from reqdb import ReqDB
from reqdb.api import OAuthClientAuth, AccessTokenAuth

from reqdbcontentcreator import sources


def getArgs() -> argparse.Namespace:
    """Reads the command line arguments and stores them.

    positional arguments:
    {asvs4,asvs5,samm,bsic5,nistcsf,csaccm,ciscontrols,bsigrundschutz}
                            Source standard to upload to ReqDB

    options:
        -h, --help            show this help message and exit
        -c, --config CONFIG   Path to the config file
        --create-config       Creates a config file with the given config parameters and exits. Saves the config into the given config file
        -t, --target TARGET   The target ReqDB server
        --token-endpoint TOKEN_ENDPOINT
                                The URL for the OAuth token endpoint. Defaults to the env var 'REQDB_CLIENT_TOKEN_ENDPOINT'
        --scope SCOPE         The scope for the OAuth app (ReqDB API). Defaults to the env var 'REQDB_API_SCOPE'
        --client-id CLIENT_ID
                                The client Id for the oauth client. Defaults to the env var 'REQDB_CLIENT_CLIENT_ID'
        --client-secret CLIENT_SECRET
                                The client secret for the oauth client. The env var should be used for this. Defaults to the env var 'REQDB_CLIENT_CLIENT_SECRET'
        --insecure            Allows the connection to ReqDB over TLS. Use this only in local test environments. This will leak your access token
        -f, --file FILE       Input file used as a source for the standard. This is only needed for the CIS Controls as they are behind a login wall. Will be ignored by the
                                other sources
        -d, --debug           Turns on debug log output
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
        "--token-endpoint",
        help="The URL for the OAuth token endpoint. Defaults to the env var 'REQDB_CLIENT_TOKEN_ENDPOINT'",
        default=getenv("REQDB_CLIENT_TOKEN_ENDPOINT", None),
    )
    parser.add_argument(
        "--scope",
        help="The scope for the OAuth app (ReqDB API). Defaults to the env var 'REQDB_API_SCOPE'",
        default=getenv("REQDB_API_SCOPE", None),
    )
    parser.add_argument(
        "--client-id",
        help="The client Id for the oauth client. Defaults to the env var 'REQDB_CLIENT_CLIENT_ID'",
        default=getenv("REQDB_CLIENT_CLIENT_ID", None),
    )
    parser.add_argument(
        "--client-secret",
        help="The client secret for the oauth client. The env var should be used for this. Defaults to the env var 'REQDB_CLIENT_CLIENT_SECRET'",
        default=getenv("REQDB_CLIENT_CLIENT_SECRET", None),
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
        "--token",
        help="Use an access token for authentication. This will overwrite client-secret authentication",
        default=getenv("REQDB_ACCESS_TOKEN", None),
    )
    parser.add_argument(
        "-d",
        "--debug",
        help="Turns on debug log output",
        action="store_true",
        default=False,
    )

    args: argparse.Namespace = parser.parse_args()

    if args.create_config is True and not args.config:
        raise SyntaxError(
            "A config file (-c, --config) must be given to write a config"
        )
    return args


def createConfig(
    target: str, clientId: str, tokenEndpoint: str, scope: str, config: str
) -> None:
    """Creates the config file

    :param target: Target ReqDB server
    :type target: string
    :param tenantId: Tenant Id for the Entra Id config
    :type tenantId: string
    :param clientId: Client Id from the Entra Id app
    :type clientId: string
    :param config: Config file name
    :type config: string
    """
    c = {
        "target": target,
        "auth": {"clientId": clientId, "tokenEndpoint": tokenEndpoint, "scope": scope},
    }
    with open(config, "w") as f:
        yaml.dump(c, f)


def loadConfig(config: str) -> tuple[str, str, str, str]:
    """Loads the config from the given file

    :param config: Config file name
    :type config: string
    :return: Tuple with the needed config variables
    :rtype: Tuple(string,string,string)
    """
    with open(config, "r") as f:
        c = yaml.safe_load(f)
    return (
        c["target"],
        c["auth"]["clientId"],
        c["auth"]["tokenEndpoint"],
        c["auth"]["scope"],
    )


def main() -> None:
    args: argparse.Namespace = getArgs()

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
        createConfig(
            args.target, args.client_id, args.token_endpoint, args.scope, args.config
        )
        exit(0)
    if args.config:
        target, clientId, tokenEndpoint, scope = loadConfig(args.config)
    else:
        target, clientId, tokenEndpoint, scope = (
            args.target,
            args.tenant_id,
            args.client_id,
            args.scope,
        )

    if args.token:
        client = ReqDB(
            target,
            AccessTokenAuth(args.token),
            args.insecure,
        )
    else:
        client = ReqDB(
            target,
            OAuthClientAuth(scope, clientId, args.client_secret, tokenEndpoint),
            args.insecure,
        )

    sourceFn: dict[str, Callable[..., None]] = {
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
