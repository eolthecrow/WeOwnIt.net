# WeOwnIT Firewall Review 1.0

Original browser implementation. No external analyzer/library, backend, configuration upload, analytics call or configuration persistence in the Firewall Review code. This component shares the existing Tools page with the other website tools.

## Accepted snapshots

- Fortinet: balanced FortiOS `config firewall policy` CLI, address/service objects and groups, VDOMs. FortiManager CLI `adom`/`pkg` scopes are kept separate. FortiManager JSON, binary/encrypted backups and installed-policy reconstruction are unsupported.
- Palo Alto Networks: PAN-OS `<config>` XML, optionally inside an XML API response. Local VSYS and Panorama/shared pre/post rulebases are parsed separately. Panorama inheritance/overrides, dynamic groups and application-default port expansion are unsupported.
- Check Point: Management API access-rulebase JSON with embedded objects-dictionary, or related extracted rule/object JSON files selected together. Access sections are flattened within their layer; UIDs are resolved and pages deduplicated. No `.tar.gz`, ZIP, Gaia CLI, NAT or Threat Prevention analysis.

Each snapshot is limited to 5 MiB / 5,000 policies. Pairwise literal-selector checks run only within scopes with at most 350 active policies. HTML/JSON exports include the applicable scope warnings; the page previews 200 findings and 100 policies.

## Checks

Broad allow policies; explicitly disabled allow-policy logging; disabled/absent inspection profiles where represented by the vendor; selected administrative-service names from any source; missing descriptions; possible redundancy/action conflicts based on earlier literal-selector coverage. Disabled rules are excluded. Negated, incomplete and complex rules are excluded from broad/overlap inference. An Any source is not proof of Internet exposure.

Fortinet omitted logging/UTM and PAN-OS omitted logging remain unknown. No rule-usage verdict is inferred without hit counts. Potential overlap findings are review candidates, not proof of ineffective/unused policies. There is no security/compliance score, reachability proof, firmware scan or certified compliance verdict.

Before/after comparison uses policy context plus ID (or name if no UUID exists) and reports changed fields/order, additions and removals. It does not validate business application availability. Object definitions, topology and effective inherited policy are not diffed.

## Developer verification

`node --test tests/firewall-review.test.cjs` from the repository root. Python 3 is needed by the test XML DOM adapter only; production uses the browser's native DOMParser. Browser smoke tests check native XML processing, demos, language changes, exports and error handling separately.

## Format references

- [Fortinet CLI policy reference](https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/333889629/config-firewall-policy)
- [PAN-OS configuration XML API](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/configuration-api)
- [PAN-OS security rule configuration](https://docs.paloaltonetworks.com/network-security/security-policy/administration/security-rules/create-a-security-policy-rule)
- [Check Point Management API](https://sc1.checkpoint.com/documents/latest/api_reference/index.html)
- [Check Point policy-package export structure](https://github.com/CheckPointSW/ShowPolicyPackage)
