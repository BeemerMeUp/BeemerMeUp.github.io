# Detecting Email Forwarding Rules in Microsoft Sentinel

## Handling Microsoft’s Logging Changes for Reliable Threat Detection

Email forwarding rules remain one of the most abused mechanisms in account-takeover scenarios. Whether attackers are quietly exfiltrating sensitive data or maintaining persistence after stealing credentials, unauthorized mailbox forwarding can quickly become a major security incident.

But in the last year, Microsoft made changes to how various forwarding-related actions are logged in **OfficeActivity** table. These changes introduced inconsistencies in the events generated for forwarding, redirecting, and mailbox-level forwarding configurations. As a result, security teams relying on older detection logic may now miss critical events or receive incomplete data.

This blog breaks down what changed, why it matters, and presents an advanced Microsoft Sentinel KQL detection that normalizes all forwarding-related logs into a single, uniform output—regardless of the operation type or the logging source.
________________________________________

### Why Forwarding-Rule Detection Became More Complicated

Forwarding rules can be created or modified in several places:

* **Inbox rules** (Outlook / OWA)
* **Transport rules** (Exchange admin center / PowerShell)
* **Mailbox settings** (forwarding address, forwarding SMTP address)
* **Modern clients that trigger UpdateInboxRules operations**

Historically, Microsoft logged many of these actions under predictable Operation values such as:

* New-InboxRule
* Set-InboxRule
* New-TransportRule
* Set-TransportRule
* Set-Mailbox

However, Microsoft has:

#### 1. Introduced new operation names

For example, UpdateInboxRules now appears for various modern Outlook actions and bundles multiple rule changes into a single event.

#### 2. Changed how forwarding actions appear in the audit log

Certain forwarding configurations no longer surface under Parameters but instead under OperationProperties.

#### 3. Modified how destinations and rule definition objects are serialized

Some events now return:

* Arrays or nested JSON objects
* Complex structures like RuleActions
* Forwarding addresses prefixed with smtp:
* Multiple recipients combined into one string

#### 4. Created inconsistencies across legacy vs. modern clients

Outlook desktop vs. Outlook on the web vs. PowerShell can produce significantly different schema structures for functionally identical actions.

These inconsistencies make detection difficult—unless all cases are accounted for and normalized.
________________________________________

### A Sentinel Detection That Normalizes All Forwarding Logs

The following KQL analytic rule solves this challenge with a unified approach:

* Normalizes different logging structures
* Extracts forwarding destinations regardless of their source format
* Handles legacy and modern rule-update formats
* Expands and cleans email lists (removing smtp: prefixes)
* Extracts rule names and rule types when available
* Parses and normalizes IP address fields
* Filters out organization-owned/verified domains

The full Detection can be found on my [Github Page](https://github.com/BeemerMeUp/BeemerMeUp.github.io/blob/main/Forward-or-Redirect-Created-or-Updated.kql).

________________________________________

### How the Detection Works

#### 1. Collect all forwarding-related audit operations

The rule begins by defining:

* A one-hour lookback window
* A list of all relevant forwarding-related Operation names
* A list of forwarding-related property names
* Your verified internal domains (using a watchlist)

Then it collects all Exchange-related OfficeActivity logs matching those operations and extracts their parameter structures, regardless of whether they appear under Parameters or OperationProperties.

#### 2. Normalize inbox rule and transport rule logs

The detection separates:

* Traditional New-InboxRule / Set-InboxRule
* Transport rule modifications
* Events using the modern UpdateInboxRules

Each gets its own parsing path because Microsoft logs them differently.

#### 3. Extract forwarding destinations from all possible schema layouts

Depending on the operation type, forwarding info may be buried inside:

* ForwardTo
* RedirectTo
* ForwardingSmtpAddress
* RuleActions → nested recipients array
* Combined multiple recipients (semicolon or comma separators)

This query handles all of them.

#### 4. Normalize output into a single unified dataset

After each operation type is parsed in its respective block, all results are unioned and cleaned.

The final output contains:

| Field | Meaning |
| ----- | -----  |
| TimeGenerated | When the rule was created/modified |
| Operation | The specific log type triggered |
| IPAddress / Port | Client network info |
| InitiatedBy | UPN of the user who created/changed the rule |
| ForwardDestination | Cleaned forwarding target |
| ForwardDomain | Domain extracted from destination |
| RuleName | The rule’s name (if available) |
| RuleType | Type of forwarding action |
| Name / UPNSuffix | Parsed username + domain |

Finally, it filters out any forwarding rules targeting your own domains, leaving only external or untrusted forwarding destinations.
________________________________________

### Why This Matters for Threat Detection

Attackers rely on forwarding rules because they provide:

* Persistence – email copies keep flowing out even if MFA is enabled
* Stealth – users often don’t notice forward rules
* Data exfiltration – sensitive email sent outside the environment

Given Microsoft’s logging changes, organizations using outdated Sentinel queries may:

* Miss modern Outlook rule updates
* Fail to parse forwarding SMTP addresses
* Misinterpret nested RuleActions
* Miss multi-recipient forwarding
* Lose visibility into external data flows

This detection restores that visibility.
________________________________________

### Conclusion

Microsoft’s shifting log schemas for forwarding rules have made detection more complex—but not impossible. By accounting for all known variations and normalizing them into a single output table, this Sentinel detection provides reliable visibility into potentially dangerous email forwarding activity across the entire tenant.

If you rely on forwarding-rule monitoring for security (and you should), updating your detection logic is essential.
