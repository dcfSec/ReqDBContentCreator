# ReqDBContentCreator

A tool to add different requirement catalogues to ReqDB. The content creator supports following catalogues:
* [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
* [OWASP SAMM](https://owasp.org/www-project-samm/)
* [BSI C5](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Informationen-und-Empfehlungen/Empfehlungen-nach-Angriffszielen/Cloud-Computing/Kriterienkatalog-C5/kriterienkatalog-c5_node.html)
* [NIST CSF](https://www.nist.gov/cyberframework)
* [CSA CCM](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
* [CIS Controls](https://www.cisecurity.org/controls) (You need to manually download the Excel at [the official website](https://learn.cisecurity.org/cis-controls-download))

## Installation

### With PIP

Use pip to install the client:

```bash
pip install reqdbcontentcreator
```

### Manually

1. Clone the repository: `git clone https://github.com/dcfSec/ReqDBContentCreator.git`
2. Go to the repository: `cd ReqDBContentCreator`
3. Run the ReqDBContentCreator: `python -m reqdbcontentcreator`

## Usage

```
usage: reqdbcontentcreator [-h] [-c CONFIG] [--create-config] [-t TARGET] [--tenant-id TENANT_ID] [--client-id CLIENT_ID] [--insecure] [-f FILE] [-d] {asvs,samm,bsic5,nistcsf,csaccm,ciscontrols,bsigrundschutz}

Creates requirements in ReqDB from public standards

positional arguments:
  {asvs,samm,bsic5,nistcsf,csaccm,ciscontrols,bsigrundschutz}
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
  -d, --debug           Turns on debug log output
```

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/dcfSec/ReqDB/tags). 

## Authors

 * [dcfSec](https://github.com/dcfSec) - *Initial work*

See also the list of [contributors](https://github.com/dcfSec/ReqDB-PyClient/contributors) who participated in this project.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details