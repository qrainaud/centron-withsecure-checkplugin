import argparse
import base64
import requests
import json

def parse_args():
    parser = argparse.ArgumentParser(description='Returns the status of incidents (0: OK, 1: WARNING, 2: CRITICAL, 3: UNKNOWN)')
    parser.add_argument("-M", help="The mode used", choices=["incidents", "patches"], required=True)
    parser.add_argument("-W", help="The warning thresold", type=int)
    parser.add_argument("-C", help="The critical thresold", type=int)
    parser.add_argument("-F", help="The incident status filter", choices=["new"])
    parser.add_argument("-I", help="The api user id", required=True, type=str)
    parser.add_argument("-S", help="The api user secret", required=True, type=str)

    args = parser.parse_args()

    if args.M == "incidents" and (args.W is None or args.C is None or args.F is None or args.W == 0 or args.C == 0 or args.F == ""):
        parser.error("-W, -C and -F parameters are required in 'incidents' mode.")
    elif args.M == "patches" and (args.W is None or args.C is None or args.W == 0 or args.C == 0):
        parser.error("-W and -C parameters are required in 'patches' mode.")

    return args

def authenticate(id:str, secret:str):
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
    response = requests.post(url, data=form_data, headers=headers)

    if response.status_code == 401:
        print("Error: The provided api user id / api user secret is invalid or the user doesn't have the read permissions on Withsecure.")
        exit(-1)

    json_response = json.loads(response.text)
    return json_response["access_token"]

def getIncidents(accessToken:str, filter:str):
    headers = {
        "Authorization" : f"Bearer {accessToken}"
    }
    incidents = []
    nextAnchor = ""

    while nextAnchor is not None:
        url = f"https://api.connect.withsecure.com/incidents/v1/incidents?archived=false&status={filter}&anchor={nextAnchor}"
        try:
            response = requests.get(url, headers=headers)
            json_response = response.json()
            incidents.extend(json_response.get("items", []))
            if "nextAnchor" in json_response:
                nextAnchor = json_response["nextAnchor"] 
            else:
                nextAnchor = None
        except requests.exceptions.JSONDecodeError:
            break
    return incidents

def getDevices(accessToken:str):
    headers = {
        "Authorization" : f"Bearer {accessToken}"
    }
    devices = []
    nextAnchor = ""

    while nextAnchor is not None:
        url=f"https://api.connect.withsecure.com/devices/v1/devices?anchor={nextAnchor}"
        try:
            response = requests.get(url, headers=headers)
            json_response = response.json()
            devices.extend(json_response.get("items", []))
            if "nextAnchor" in json_response:
                nextAnchor = json_response["nextAnchor"] 
            else:
                nextAnchor = None
        except requests.exceptions.JSONDecodeError:
            break
    return devices

def getIncidentsStatus(incidents:list, warningThresold:int, criticalThresold:int, filter:str):
    nbIncidents = len(incidents)
    incidentNbs = {"info" : 0,"low" : 0, "medium" : 0, "high" : 0, "severe" : 0}
    for incident in incidents:
        incidentNbs[incident["riskLevel"]] += 1
    
    nbIncidentsMediumPlus = incidentNbs["medium"] + incidentNbs["high"] + incidentNbs["severe"]
    if nbIncidentsMediumPlus < warningThresold:
        print(f"OK: Number of {filter} medium+ incidents is {nbIncidentsMediumPlus}.|low_events={incidentNbs["low"]} medium_events={incidentNbs["medium"]} high_events={incidentNbs["high"]} severe_events={incidentNbs["severe"]}")
        exit(0)
    elif nbIncidentsMediumPlus < criticalThresold:
        print(f"WARNING: Number of {filter} medium+ incidents is {nbIncidentsMediumPlus}.|low_events={incidentNbs["low"]} medium_events={incidentNbs["medium"]} high_events={incidentNbs["high"]} severe_events={incidentNbs["severe"]}")
        exit(1)
    else:
        print(f"CRITICAL: Number of {filter} medium+ incidents is {nbIncidentsMediumPlus}.|low_events={incidentNbs["low"]} medium_events={incidentNbs["medium"]} high_events={incidentNbs["high"]} severe_events={incidentNbs["severe"]}")
        exit(2)

def getPatchesStatus(devices:list, warningThresold:int, criticalThresold:int):
    patchesNbs = {"notScannedYet" : 0, "outdatedScanResults" : 0, "disabled" : 0, "importantUpdatesInstalled" : 0, "missingImportantUpdates" : 0, "missingCriticalUpdates" : 0}

    for device in devices:
        if "patchOverallState" in device:
            patchesNbs[device["patchOverallState"]] += 1

    nbMissingPatchesImportantPlus = patchesNbs["missingImportantUpdates"] + patchesNbs["missingCriticalUpdates"]
    if nbMissingPatchesImportantPlus < warningThresold:
        print(f"OK: Number of important+ missing patches is {nbMissingPatchesImportantPlus}.|missing_important_patches={patchesNbs["missingImportantUpdates"]} missing_critical_patches={patchesNbs["missingCriticalUpdates"]}")
        exit(0)
    elif nbMissingPatchesImportantPlus < criticalThresold:
        print(f"WARNING: Number of important+ missing patches is {nbMissingPatchesImportantPlus}.|missing_important_patches={patchesNbs["missingImportantUpdates"]} missing_critical_patches={patchesNbs["missingCriticalUpdates"]}")
        exit(1)
    else:
        print(f"CRITICAL: Number of important+ missing patches is {nbMissingPatchesImportantPlus}.|missing_important_patches={patchesNbs["missingImportantUpdates"]} missing_critical_patches={patchesNbs["missingCriticalUpdates"]}")
        exit(2)

def main():
    args = parse_args()

    apiUserId = args.I
    apiUserSecret = args.S
    mode = args.M

    apiAccessToken = authenticate(id=apiUserId, secret=apiUserSecret)

    if mode == "incidents":
        warningThresold = args.W
        criticalThresold = args.C
        filter = args.F
        incidents = getIncidents(accessToken=apiAccessToken, filter=filter)
        getOverallStatus(incidents=incidents, warningThresold=warningThresold, criticalThresold=criticalThresold, filter=filter)
        
    elif mode == "patches":
        warningThresold = args.W
        criticalThresold = args.C
        filter = args.F
        devices = getDevices(accessToken=apiAccessToken)
        getPatchesStatus(devices=devices, warningThresold=warningThresold, criticalThresold=criticalThresold)


main()