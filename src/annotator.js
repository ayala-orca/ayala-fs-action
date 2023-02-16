const core = require("@actions/core");

function getSecretDetails(controlResults, file) {
    let title = controlResults.catalog_control["title"];
    let details = `${title} secret was found`
    return details
}

function getVulnDetails(controlResults, vulnerability) {
    let scoreMessage = '';
    if (vulnerability.cvss_v2_score) {
        scoreMessage += `CVSS2 Score: ${vulnerability.cvss_v2_score}\n`;
    }
    if (vulnerability.cvss_v3_score) {
        scoreMessage += `CVSS3 Score: ${vulnerability.cvss_v3_score}\n`;
    }
    let fixed = vulnerability["fixed_version"]
    let installed = vulnerability["installed_version"]
    return `Severity: ${vulnerability.severity}\n${scoreMessage}Installed version: ${installed}\nFixed version:${fixed}`
}

function extractSecretFinding(controlResults, annotations) {
    for (const finding of controlResults.findings) {
        annotations.push({
            file: finding["file_name"],
            startLine: finding.position["start_line"],
            endLine: finding.position["end_line"],
            priority: controlResults["priority"],
            status: controlResults["status"],
            title: `[${controlResults["priority"]}] controlResults.catalog_control["title"]`,
            details: getSecretDetails(controlResults, finding),
        });
    }
}

function extractVulnerability(controlResults, annotations) {
    for (const vulnerability of controlResults.vulnerabilities) {
        annotations.push({
            // vulnerability does not return real path on github, so we need to concatenate path given by github
            file: `${process.env.INPUT_PATH}/${controlResults["target"]}`,
            // currently no start line and end line for vulnerabilities available
            startLine: 1,
            endLine: 1,
            priority: vulnerability["severity"],
            status: vulnerability.status_summary["status"],
            title: `${vulnerability["pkg_name"]} (${vulnerability["vulnerability_id"]})`,
            details: getVulnDetails(controlResults, vulnerability),
        });
    }
}

function extractAnnotations(results) {
    let annotations = [];
    for (const controlResults of results.results.secret_detection.results) {
        extractSecretFinding(controlResults, annotations);
    }
    for (const controlResults of results.vulnerabilities) {
        extractVulnerability(controlResults, annotations);
    }
    return annotations;
}

function annotateChangesWithResults(results) {
    const annotations = extractAnnotations(results);
    annotations.forEach((annotation) => {
        let annotationProperties = {
            title: annotation.title,
            startLine: annotation.startLine,
            endLine: annotation.endLine,
            file: annotation.file,
        };
        if (annotation.status === "FAILED") {
            core.error(annotation.details, annotationProperties);
        } else {
            core.warning(annotation.details, annotationProperties);
        }
    });
}

module.exports = {
    annotateChangesWithResults,
};
