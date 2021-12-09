import hashlib
import json

from dojo.models import Finding


class GitleaksParser(object):
    """
    A class that can be used to parse the Gitleaks JSON report files
    """

    def get_scan_types(self):
        return ["Gitleaks Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Gitleaks Scan findings in JSON format."

    def get_findings(self, filename, test):
        """
        Converts a Gitleaks report to DefectDojo findings
        """
        issues = json.load(filename)
        # empty report are just null object
        if issues is None:
            return list()

        dupes = dict()
        for issue in issues:
            line = None
            file_path = issue["File"]
            reason = issue["RuleID"]
            titleText = "Hard Coded " + reason
            description = "**Commit:** " + issue["Message"].rstrip("\n") + "\n"
            description += "**Commit Hash:** " + issue["Commit"] + "\n"
            description += "**Commit Date:** " + issue["Date"] + "\n"
            description += "**Author:** " + issue["Author"] + " <" + issue["Email"] + ">" + "\n"
            description += "**Reason:** " + reason + "\n"
            description += "**Path:** " + file_path + "\n"
            if "StartLine" in issue:
                description += "**StartLine:** %i\n" % issue["StartLine"]
                line = issue["StartLine"]
            if "EndLine" in issue:
                description += "**EndLine:** %i\n" % issue["EndLine"]
            if "File" in issue:
                description += "**File:** " + issue["File"] + "\n"

            description += "\n**String Found:**\n\n```\n" + issue["StartLine"].replace(issue["Secret"], "REDACTED") + "\n```"

            severity = "High"
            if "Github" in reason or "AWS" in reason or "Heroku" in reason:
                severity = "Critical"

            finding = Finding(
                title=titleText,
                test=test,
                cwe=798,
                description=description,
                severity=severity,
                file_path=file_path,
                line=line,
                dynamic_finding=False,
                static_finding=True,
            )
            # manage tags
            finding.unsaved_tags = issue.get("Tags", [])#.split(', ')

            dupe_key = hashlib.sha256((issue["Secret"] + file_path + str(line)).encode("utf-8")).hexdigest()

            if dupe_key not in dupes:
                dupes[dupe_key] = finding

        return list(dupes.values())
