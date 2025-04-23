import argparse
import base64
import requests
import json

CENTREON_STATUSES = ["OK", "WARNING", "CRITICAL", "UNKNOWN"]
INCIDENT_STATUSES = ["new"]
INCIDENT_SEVERITIES = ["info", "low", "medium", "high", "severe"]
PRODUCT_VARIANTS = ["mobileprotection", "mobileprotection_vpn", "computerprotection", "computerprotection_premium", "computerprotection_edr", "computerprotection_premium_edr", "edr", "radar", "serversecurity", "serverprotection_premium", "serverprotection_premium_rdr", "rdr_server", "elements_connector"]

WITHSECURE_DEVICE_API = "https://api.connect.withsecure.com/devices/v1/devices"
WITHSECURE_INCIDENT_API = "https://api.connect.withsecure.com/incidents/v1/incidents"

def parserSetup():
    parser = argparse.ArgumentParser(description='Withsecure centreon plugin, returns a status number (0: OK, 1: WARNING, 2: CRITICAL, 3: UNKNOWN)')
    subparsers = parser.add_subparsers(dest="command", required=True)

    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("-i", "--id", help="The api user id", type=str, required=True)
    common_parser.add_argument("-s", "--secret", help="The api user secret", type=str, required=True)
    common_parser.add_argument("-w", "--warning", help="The warning threshold", type=int, required=True)
    common_parser.add_argument("-c", "--critical", help="The critical threshold", type=int, required=True)


    parser_incidents = subparsers.add_parser("incidents", parents=[common_parser], help="Returns the number of incidents")
    parser_incidents.add_argument("-st", "--status", help="The status filter for incidents", choices=INCIDENT_STATUSES, required=True)
    parser_incidents.add_argument("-msv", "--minimum-severity", help="The minimum severity filter for incidents", choices=INCIDENT_SEVERITIES, required=True)
    parser_incidents.add_argument("--exclude-info", action="store_true", help="Exclude info severity events from the graph")

    parser_patches = subparsers.add_parser("patches", parents=[common_parser], help="Returns the number of missing patch updates")

    parser_licenses = subparsers.add_parser("licenses", parents=[common_parser], help="Returns the number of used licenses")
    parser_licenses.add_argument("-v", "--variant", help="The product variant filter for licenses", choices=PRODUCT_VARIANTS, required=True)
    
    args = parser.parse_args()

    return args

def authenticate(id, secret):
    url = "https://api.connect.withsecure.com/as/token.oauth2"
    encodedAuth = base64.b64encode(f"{id}:{secret}".encode('utf-8')).decode('utf-8')
    headers = {
        "Content-Type" : "application/x-www-form-urlencoded",
        "Authorization" : f"Basic {encodedAuth}"
    }
    form_data = {
        "grant_type": "client_credentials",
        "scope": "connect.api.read"
    }
    response = requests.post(url, form_data, headers=headers)

    if response.status_code == 401:
        print("Error: The provided api user id / api user secret is invalid or the user doesn't have the read permissions on Withsecure.")
        exit(3)

    json_response = json.loads(response.text)
    return json_response["access_token"]

class CentreonWithsecurePlugin:
    def __init__(self):
        self.args = parserSetup()
        self.token = authenticate(self.args.id, self.args.secret)

    def getCommandResult(self):
        if self.args.command == "incidents":
            self.getIncidentsCentreonStatus()
        
        elif self.args.command == "patches":
            self.getPatchesCentreonStatus()

        elif self.args.command == "licenses":
            self.getLicensesCentreonStatus()

    def getUrl(self, url:str, params:dict):
        url += "?"
        for param in params.keys():
            url += f"{param}={params[param]}&"
        return url[:-1]

    def getHeaders(self):
        return {
            "Authorization" : f"Bearer {self.token}"
        }

    def getIncidentsByStatus(self):
        incidents = []
        nextAnchor = ""

        while nextAnchor is not None:
            url = self.getUrl(WITHSECURE_INCIDENT_API, {"archived":"false", "status":self.args.status, "anchor":nextAnchor})
            try:
                response = requests.get(url, headers=self.getHeaders())
                json_response = response.json()
                incidents.extend(json_response.get("items", []))
                if "nextAnchor" in json_response:
                    nextAnchor = json_response["nextAnchor"] 
                else:
                    nextAnchor = None
            except requests.exceptions.JSONDecodeError:
                break
        return incidents
    
    def getDevices(self):
        devices = []
        nextAnchor = ""

        while nextAnchor is not None:
            url = self.getUrl(url=WITHSECURE_DEVICE_API, params={"anchor":nextAnchor})
            try:
                response = requests.get(url, headers=self.getHeaders())
                json_response = response.json()
                devices.extend(json_response.get("items", []))
                if "nextAnchor" in json_response:
                    nextAnchor = json_response["nextAnchor"] 
                else:
                    nextAnchor = None
            except requests.exceptions.JSONDecodeError:
                break
        return devices
    
    def getIncidentsCentreonStatus(self):
        incidents = self.getIncidentsByStatus()
        incidentNbBySeverity = {severity : 0 for severity in INCIDENT_SEVERITIES}
        for incident in incidents:
            incidentNbBySeverity[incident["riskLevel"]] += 1

        nbIncidents = 0
        
        for severity in INCIDENT_SEVERITIES[INCIDENT_SEVERITIES.index(self.args.minimum_severity):]:
            nbIncidents += incidentNbBySeverity[severity]

        exitCode = 0

        if nbIncidents < self.args.warning:
            exitCode = 0
        elif nbIncidents < self.args.critical:
            exitCode = 1
        else:
            exitCode = 2

        message = f"{CENTREON_STATUSES[exitCode]}: Number of {self.args.status} {self.args.minimum_severity}+ incidents is {nbIncidents}.|"
        if not self.args.exclude_info:
            message += f"info_events={incidentNbBySeverity['info']} "
        for severity in INCIDENT_SEVERITIES[1:]:
            message += f"{severity}_events={incidentNbBySeverity[severity]} "
        print(message[:-1])
        exit(exitCode)

    def getPatchesCentreonStatus(self):
        devices = self.getDevices()
        patchesNbs = {"notScannedYet" : 0, "outdatedScanResults" : 0, "disabled" : 0, "importantUpdatesInstalled" : 0, "missingImportantUpdates" : 0, "missingCriticalUpdates" : 0}

        for device in devices:
            if "patchOverallState" in device:
                patchesNbs[device["patchOverallState"]] += 1

        nbMissingPatchesImportantPlus = patchesNbs["missingImportantUpdates"] + patchesNbs["missingCriticalUpdates"]
        if nbMissingPatchesImportantPlus < self.args.warning:
            print(f"OK: Number of important+ missing patches is {nbMissingPatchesImportantPlus}.|missing_important_patches={patchesNbs['missingImportantUpdates']} missing_critical_patches={patchesNbs['missingCriticalUpdates']}")
            exit(0)
        elif nbMissingPatchesImportantPlus < self.args.critical:
            print(f"WARNING: Number of important+ missing patches is {nbMissingPatchesImportantPlus}.|missing_important_patches={patchesNbs['missingImportantUpdates']} missing_critical_patches={patchesNbs['missingCriticalUpdates']}")
            exit(1)
        else:
            print(f"CRITICAL: Number of important+ missing patches is {nbMissingPatchesImportantPlus}.|missing_important_patches={patchesNbs['missingImportantUpdates']} missing_critical_patches={patchesNbs['missingCriticalUpdates']}")
            exit(2)

    def getLicensesCentreonStatus(self):
        devices = self.getDevices()
        licenseNbByVariant = {variant : 0 for variant in PRODUCT_VARIANTS}
        for device in devices:
            if "subscription" in device:
                licenseNbByVariant[device["subscription"]["productVariant"]] += 1
        
        exitCode = 0
        nbLicenses = licenseNbByVariant[self.args.variant]
        if nbLicenses < self.args.warning:
            exitCode = 0
        elif nbLicenses < self.args.critical:
            exitCode = 1
        else:
            exitCode = 2
        
        message = f"{CENTREON_STATUSES[exitCode]}: Number of {self.args.variant} licenses is {nbLicenses}.|"
        for variant in PRODUCT_VARIANTS[1:]:
            if licenseNbByVariant[variant] > 0:
                message += f"{variant}_licenses={licenseNbByVariant[variant]} "
        print(message[:-1])
        exit(exitCode)

def main():
    plugin = CentreonWithsecurePlugin()
    plugin.getCommandResult()

if __name__ == "__main__":
    main()