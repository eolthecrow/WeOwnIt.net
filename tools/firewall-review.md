# weownit Firewall Review 1.1

Original browser implementation. No external analyzer/library, backend, configuration upload, analytics call or configuration persistence in the Firewall Review code. This component shares the existing Tools page with the other website tools.

## Accepted snapshots

- Fortinet CLI: balanced FortiOS `config firewall policy` CLI, address/service objects and groups, VDOMs. FortiManager CLI `adom`/`pkg` scopes are kept separate. FortiManager JSON, binary/encrypted backups and installed-policy reconstruction are unsupported.
- Palo Alto Networks XML: PAN-OS `<config>` XML, optionally inside an XML API response. Local VSYS and Panorama/shared pre/post rulebases are parsed separately. Panorama inheritance/overrides, dynamic groups and application-default port expansion are unsupported.
- Check Point: Management API access-rulebase JSON with embedded objects-dictionary, or related extracted rule/object JSON files selected together. Access sections are flattened within their layer; UIDs are resolved and pages deduplicated. No `.tar.gz`, ZIP, Gaia CLI, NAT or Threat Prevention analysis.

- Fortinet JSON: FortiOS REST response wrappers with `path`, `name`, `vdom`, and array `results`. Supported endpoints: `firewall/policy`, `firewall/address`, `firewall/addrgrp`, `firewall.service/custom`, `firewall.service/group`. Select related files together, or use an array of response wrappers / `{ "responses": [...] }`. Raw policy arrays and FortiManager JSON are not supported. Duplicate identical entries are removed; conflicting duplicate entries are rejected. API array order is not treated as proof of effective rule order.
- Palo Alto Networks CLI: complete `set ... rulebase security rules` listings, including local VSYS, explicit `vsys` prefixes, Panorama `device-group` and `shared` pre/post rulebases. Relative local listings assume `vsys1`, with an explicit warning. Repeated selectors and bracket lists are merged. Change scripts (`delete`, `move`, etc.) are not accepted.
- Palo Alto Networks JSON: configuration hierarchy under `config` (including XML API JSON wrappers), direct hierarchy, and named-key CLI JSON containers. REST `result.entry` security rules need `@location` and `@vsys` / `@device-group`. Panorama REST exports additionally need a top-level `resource` such as `Policies/SecurityPreRules` or `Policies/SecurityPostRules` to identify their rulebase. REST order is unknown; absent REST profiles remain unknown. Multiple PAN-OS JSON files are not merged.
- Common review standard: JSON with `schema: "weownit.firewall-review.snapshot"`, `schemaVersion: 1`, vendor, sourceFormat, objects, warnings, and normalized policies; XML has root `firewall-review-snapshot` with schema/schema-version/vendor attributes. Both export formats can be reloaded. The JSON report includes this schema plus findings and comparison; findings are recomputed on reload. A snapshot preserves policy identifiers, contexts, normalized selectors, unknown/incomplete flags and coverage warnings. It excludes original admin secrets and unrelated configuration. It is **not** a vendor backup, restore file, cross-vendor migration configuration, or full network model. Check Point Gaia `show configuration` remains unsupported for access-policy review; use Management API / `mgmt_cli --format json` policy data.

Each snapshot is limited to 5 MiB / 5,000 policies. Pairwise literal-selector checks run only within scopes with at most 350 active policies. HTML/JSON exports include the applicable scope warnings; the page previews 200 findings and 100 policies.

## Checks

Broad allow policies; explicitly disabled allow-policy logging; disabled/absent inspection profiles where represented by the vendor; selected administrative-service names from any source; missing descriptions; possible redundancy/action conflicts based on earlier literal-selector coverage. Disabled rules are excluded. Negated, incomplete and complex rules are excluded from broad/overlap inference. An Any source is not proof of Internet exposure.

Fortinet omitted logging/UTM and PAN-OS omitted logging remain unknown. No rule-usage verdict is inferred without hit counts. Potential overlap findings are review candidates, not proof of ineffective/unused policies. There is no security/compliance score, reachability proof, firmware scan or certified compliance verdict.

Before/after comparison uses policy context plus ID (or name if no UUID exists) and reports changed fields/order, additions and removals. PAN-OS names provide a fallback when a format lacks UUIDs; ambiguous duplicate names are not matched by name. Order comparisons and overlap findings are skipped when order is unknown. Cross-format comparison requires the same policy context. It does not validate business application availability. Object definitions, topology and effective inherited policy are not diffed.

## Developer verification

`node --test tests/firewall-review.test.cjs` from the repository root. Python 3 is needed by the test XML DOM adapter only; production uses the browser's native DOMParser. Browser smoke tests check native XML processing, demos, language changes, exports and error handling separately.

## Format references

- [Fortinet CLI policy reference](https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/333889629/config-firewall-policy)
- [PAN-OS configuration XML API](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/configuration-api)
- [PAN-OS security rule configuration](https://docs.paloaltonetworks.com/network-security/security-policy/administration/security-rules/create-a-security-policy-rule)
- [Check Point Management API](https://sc1.checkpoint.com/documents/latest/api_reference/index.html)
- [Check Point policy-package export structure](https://github.com/CheckPointSW/ShowPolicyPackage)

- [FortiOS REST JSON response structure](https://docs.fortinet.com/document/fortigate/7.4.7/administration-guide/940602/using-apis)
- [PAN-OS CLI set/XML output](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClHoCAK)
- [PAN-OS CLI JSON output](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClUHCA0)
- [PAN-OS REST security rule JSON](https://docs.paloaltonetworks.com/ngfw/api/pan-os-rest-api-use-cases/create-security-policy-rule-rest-api)
- [Panorama REST rulebase context](https://docs.paloaltonetworks.com/ngfw/api/pan-os-rest-api-use-cases/work-with-policy-rules-on-panorama-rest-api)
- [Check Point management CLI JSON exports](https://sc1.checkpoint.com/documents/latest/APIs/data/v1.5/introduction.html)
