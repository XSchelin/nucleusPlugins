#!/usr/bin/python3.7
"""
Converts an exported CrowdStrike CSV file of vulnerabilities to a Nucleus-approved format.
Optionally uploads that file directly to Nucleus after conversion.
"""
__author__ = "Nucleus Security"
__license__ = "MIT License"
__version__ = "0.1"

# Used for writing to csv
import csv
# Used for arguments
import argparse
# Used to post the file to Nucleus
import requests
import json
import sys

global args

try:
    settings = json.load(open("cs_settings.json", "r"))
except FileNotFoundError:
    sys.exit("Error: No file named `cs_settings.json` found")

NUCLEUS_ROOT_URL = settings["root_url"]
API_KEY = settings["api_key"]
EXPORT_FIELDS = settings["fields"]


def customParser(inpath, outpath):
    """
    Convert the CrowdStrike CSV file to a Nucleus-appropriate one.
    :param inpath: string, the inbound file or path
    :param outpath string, the file or path to be created
    """
    with open(inpath, 'r', newline='', encoding="utf-8") as input_file:
        # Create the csv file for writing
        with open(outpath, 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',')
            csvwriter.writerow(EXPORT_FIELDS)

            # Try to parse the data.
            try:
                findings = csv.reader(input_file, delimiter=',')
                next(findings)

                # Going to be used to check for duplicates in the input file
                csv_dupe_array = []

                for finding in findings:
                    csv_line = []
                    # Grab the values we need
                    try:
                        asset_name = finding[0].strip()
                        asset_ip = finding[1]
                        os = finding[3]
                        asset_domain = finding[6]
                        finding_output = finding[7]
                        finding_cve = finding[8]
                        finding_name = finding[8]
                        finding_number = finding[8]
                        description = finding[9]
                        severity = finding[11]
                        scan_date = finding[12]

                        # If there's an evidence, append it to the description
                        if finding[29] != "":
                            description += "\n\nVulnerable product version(s): " + finding[29]

                        solution = finding[20] + ": " + finding[21]
                        if finding[22] != "":
                            solution += "\n\n" + finding[22]
                        finding_exploitable = 'false' if finding[26] == "0" else 'true'

                        references = "Exploit Status:" + finding[27] + "," + "Exploit Status Value:" + finding[26]

                        # Append links to the references area
                        ref_links = []
                        if finding[18] != "":
                            new_link = "<a href='" + finding[18] + "' target='_blank'>" + finding[18] + "</a>"
                            ref_links.append(new_link)
                        if finding[19] != "":
                            links = finding[19].split(", ")
                            for link in links:
                                new_link = "<a href='" + link + "' target='_blank'>" + link + "</a>"
                                ref_links.append(new_link)
                        references += "\n\n" + "\n".join(ref_links)

                        # Used to check for duplicates.
                        # Alter this if you want to change how Nucleus tracks instances of vulns
                        fjk = asset_name + finding_number

                    except Exception as e:
                        print("Error getting finding: ", e)

                    csv_line.extend(['1', asset_name, asset_ip, 'Host', 'CrowdStrike', 'Vuln', finding_cve, 
					                finding_number, finding_output, finding_name, severity, description, solution, 
									scan_date, 'Failed', references, finding_exploitable, os, asset_domain, 0])

                    # Use this to deduplicate the findings from CrowdStrike
                    if fjk in csv_dupe_array:
                        print("whoop")
                        pass

                    else:
                        csvwriter.writerow(csv_line)
                        csv_dupe_array.append(fjk)

            except Exception as e:
                print("Error parsing the file:", e)


def get_args():
    """
    Retrieve command-line arguments.
    """
    global args
    parser = argparse.ArgumentParser(description="For parsing whitesource files to be uploaded into Nucleus. If "
                                     "project ID is specified, will post the Nucleus supported file to "
                                     "Nucleus project.")

    # List arguments. Should only include input file and output file
    parser.add_argument('-i', '--inputfile', dest='input_file',
                        help="Path to CrowdStrike CSV file", required=True)
    parser.add_argument('-o', '--outputfile', dest='output_file',
                        help="Path to CSV file output", required=True)
    parser.add_argument('-p', '--project_id', dest="project_id",
                        help="The project ID of the Nucleus project to which you want to post. If not "
                        "specified, this script will only convert the exported file for manual upload.")

    args = parser.parse_args()


def post_to_nucleus(outputfile):
    """
    Send the converted file to Nucleus.
    :param outfile: string, the converted CSV file
    """
    with open(outputfile.name, 'rb') as f:
        # Get the final Nucleus URL to post to
        nucleus_url = NUCLEUS_ROOT_URL + '/nucleus/api/projects/' + args.project_id + '/scans'

        # Send file with proper header. Keep note of the project ID you need to send
        file_upload = requests.post(
            nucleus_url,
            files={outputfile.name: f},
            headers={'x-apikey': API_KEY}
        )

        # Print the response from the server
        # TODO: Change this to just print the status code, iff (sic) it didn't succeed
        print(file_upload.content)


if __name__ == "__main__":
    get_args()
    # Get the input file to parse
    input_path = args.input_file
    # Get the output file to save to
    output_path = args.output_file
    # Start the parsing and csv writing
    outfile = customParser(input_path, output_path)

    # If a project ID was specified, send the file to Nucleus
    if args.project_id:
        post_to_nucleus(outfile)

    # If no project ID was specified, just export file to Nucleus format for manual file upload
    else:
        pass
