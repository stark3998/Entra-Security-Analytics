"""Built-in (''system'') correlation rules seeded on first run.

Each dict is a ``CorrelationRule`` row with ``is_system = True``.
The ``rule_definition`` values conform to ``RuleDefinition`` from
``app.analyzers.rule_schema``.

Numbering follows the rule catalog:
  1.x  Identity / Authentication Changes
  2.x  Privilege Escalation
  3.x  Data Exfiltration / DLP
  4.x  Consent & Application Abuse
  5.x  Shadow IT / Power Platform
  M.x  Meta-rules (multi-signal correlation)
"""

from __future__ import annotations

from app.models.database import CorrelationRule, Severity

# ── Helpers ───────────────────────────────────────────────────────────────

def _m(field: str, op: str, value=None, **kw):
    """Shorthand for a FieldMatcher dict."""
    d = {"field": field, "operator": op}
    if value is not None:
        d["value"] = value
    d.update(kw)
    return d


def _trigger(source: str, *matchers):
    return {"source": source, "matchers": list(matchers)}


def _ww(days: int = 14, pts: int = 15, enabled: bool = True):
    return {"enabled": enabled, "duration_days": days, "risk_points": pts}


# ── Category 1: Identity / Authentication Changes ────────────────────────

RULE_1_1 = {
    "name": "1.1 MFA Method Changed",
    "severity": Severity.MEDIUM,
    "risk_points": 15,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "in", [
                    "User registered security info",
                    "User changed default security info",
                    "User deleted security info",
                ]),
            ),
        ],
        "watch_window": _ww(14, 15),
        "description": "User changed, added, or removed an MFA method.",
        "mitre_tactics": ["Persistence", "Defense Evasion"],
        "mitre_techniques": ["T1556.006"],
    },
}

RULE_1_2 = {
    "name": "1.2 MFA Disabled",
    "severity": Severity.HIGH,
    "risk_points": 25,
    "watch_window_days": 30,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "in", [
                    "Disable Strong Authentication",
                    "Admin disabled per-user MFA",
                ]),
            ),
        ],
        "watch_window": _ww(30, 25),
        "description": "MFA was disabled for a user account.",
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1556.006"],
    },
}

RULE_1_3 = {
    "name": "1.3 MFA Fraud Reported",
    "severity": Severity.CRITICAL,
    "risk_points": 30,
    "watch_window_days": 7,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "contains", "Fraud reported"),
            ),
        ],
        "watch_window": _ww(7, 30),
        "description": "User reported MFA prompt they did not initiate.",
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1078"],
    },
}

RULE_1_4 = {
    "name": "1.4 Password Reset by Admin",
    "severity": Severity.MEDIUM,
    "risk_points": 15,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "eq", "Reset password (by admin)"),
            ),
        ],
        "watch_window": _ww(14, 15),
        "description": "An admin reset a user's password.",
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1098"],
    },
}

RULE_1_5 = {
    "name": "1.5 Password Changed After Risky Sign-In",
    "severity": Severity.HIGH,
    "risk_points": 20,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "in", [
                    "Change user password",
                    "Reset user password",
                    "Change password (self-service)",
                ]),
            ),
        ],
        "correlations": [
            {
                "secondary_source": "entra_signin",
                "secondary_matchers": [
                    _m("raw_json.riskLevelDuringSignIn", "in", ["medium", "high"]),
                ],
                "window_minutes": 1440,
                "direction": "before",
            },
        ],
        "watch_window": _ww(14, 20),
        "description": "Password change occurred within 24h of a risky sign-in.",
        "mitre_tactics": ["Persistence", "Defense Evasion"],
        "mitre_techniques": ["T1098"],
    },
}

RULE_1_6 = {
    "name": "1.6 Legacy Auth Protocol Used",
    "severity": Severity.LOW,
    "risk_points": 10,
    "watch_window_days": 7,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_signin",
                _m("raw_json.clientAppUsed", "in", [
                    "Exchange ActiveSync",
                    "IMAP4",
                    "POP3",
                    "SMTP",
                    "Authenticated SMTP",
                    "Other clients",
                ]),
            ),
        ],
        "watch_window": _ww(7, 10),
        "description": "Sign-in used a legacy authentication protocol.",
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1078"],
    },
}

RULE_1_7 = {
    "name": "1.7 Brute Force / Password Spray Detected",
    "severity": Severity.HIGH,
    "risk_points": 20,
    "watch_window_days": 7,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_signin",
                _m("raw_json.status.errorCode", "in", [50126, 50053, 50055]),
            ),
        ],
        "threshold": {
            "aggregation": "count",
            "operator": "gt",
            "value": 10,
            "window_minutes": 60,
            "group_by": "user_principal_name",
        },
        "watch_window": _ww(7, 20),
        "description": "10+ failed sign-ins within 1 hour (brute force / spray).",
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110"],
    },
}

RULE_1_8 = {
    "name": "1.8 Impossible Travel",
    "severity": Severity.HIGH,
    "risk_points": 25,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_signin",
                _m("raw_json.riskEventTypes_v2", "contains", "impossibleTravel"),
            ),
        ],
        "watch_window": _ww(14, 25),
        "description": "Azure AD Identity Protection flagged an impossible-travel sign-in.",
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1078"],
    },
}

RULE_1_9 = {
    "name": "1.9 Leaked Credentials",
    "severity": Severity.CRITICAL,
    "risk_points": 30,
    "watch_window_days": 30,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_signin",
                _m("risk_level_during_sign_in", "in", ["high"]),
                _m("raw_json.riskEventTypes_v2", "contains", "leakedCredentials"),
            ),
        ],
        "watch_window": _ww(30, 30),
        "description": "Sign-in flagged with leaked-credentials risk detection.",
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1078.004"],
    },
}

RULE_1_10 = {
    "name": "1.10 Conditional Access Policy Deleted",
    "severity": Severity.HIGH,
    "risk_points": 25,
    "watch_window_days": 30,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "eq", "Delete conditional access policy"),
            ),
        ],
        "watch_window": _ww(30, 25),
        "description": "A Conditional Access policy was deleted.",
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.001"],
    },
}

# ── Category 2: Privilege Escalation ─────────────────────────────────────

RULE_2_1 = {
    "name": "2.1 Global Admin Role Assigned",
    "severity": Severity.CRITICAL,
    "risk_points": 30,
    "watch_window_days": 30,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "eq", "Add member to role"),
                _m("raw_json.targetResources", "contains", "Global Administrator"),
            ),
        ],
        "watch_window": _ww(30, 30),
        "description": "User was assigned the Global Administrator role.",
        "mitre_tactics": ["Privilege Escalation"],
        "mitre_techniques": ["T1078.004"],
    },
}

RULE_2_2 = {
    "name": "2.2 Privileged Role Assigned",
    "severity": Severity.HIGH,
    "risk_points": 20,
    "watch_window_days": 21,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "in", [
                    "Add member to role",
                    "Add eligible member to role",
                ]),
                _m("category", "eq", "RoleManagement"),
            ),
        ],
        "watch_window": _ww(21, 20),
        "description": "A privileged directory role was assigned to a user.",
        "mitre_tactics": ["Privilege Escalation"],
        "mitre_techniques": ["T1078.004"],
    },
}

RULE_2_3 = {
    "name": "2.3 Role Assignment Outside PIM",
    "severity": Severity.HIGH,
    "risk_points": 25,
    "watch_window_days": 30,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "eq", "Add member to role"),
                _m("raw_json.initiatedBy.app", "not_exists"),
            ),
        ],
        "watch_window": _ww(30, 25),
        "description": "Role assignment performed outside Privileged Identity Management.",
        "mitre_tactics": ["Privilege Escalation", "Defense Evasion"],
        "mitre_techniques": ["T1078.004"],
    },
}

RULE_2_4 = {
    "name": "2.4 PIM Settings Modified",
    "severity": Severity.HIGH,
    "risk_points": 20,
    "watch_window_days": 30,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "contains", "role setting"),
                _m("category", "eq", "RoleManagement"),
            ),
        ],
        "watch_window": _ww(30, 20),
        "description": "PIM role settings were modified.",
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1078"],
    },
}

RULE_2_5 = {
    "name": "2.5 SharePoint Site Admin Added",
    "severity": Severity.MEDIUM,
    "risk_points": 15,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "sharepoint",
                _m("operation", "in", [
                    "SiteCollectionAdminAdded",
                    "SiteAdminChangeRequest",
                ]),
            ),
        ],
        "watch_window": _ww(14, 15),
        "description": "A site collection administrator was added.",
        "mitre_tactics": ["Privilege Escalation"],
        "mitre_techniques": ["T1098"],
    },
}

RULE_2_6 = {
    "name": "2.6 Privilege Escalation Chain",
    "severity": Severity.CRITICAL,
    "risk_points": 30,
    "watch_window_days": 30,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "in", [
                    "Add member to role",
                    "Add eligible member to role",
                ]),
            ),
        ],
        "correlations": [
            {
                "secondary_source": "entra_audit",
                "secondary_matchers": [
                    _m("activity_display_name", "in", [
                        "Add member to role",
                        "Add eligible member to role",
                    ]),
                    _m("initiated_by_user", "neq", ""),
                ],
                "window_minutes": 60,
                "direction": "both",
            },
        ],
        "watch_window": _ww(30, 30),
        "description": "Multiple role assignments within 1 hour – possible escalation chain.",
        "mitre_tactics": ["Privilege Escalation"],
        "mitre_techniques": ["T1078.004"],
    },
}

# ── Category 3: Data Exfiltration / DLP ──────────────────────────────────

RULE_3_1 = {
    "name": "3.1 Mass File Download",
    "severity": Severity.HIGH,
    "risk_points": 20,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "sharepoint",
                _m("operation", "in", ["FileDownloaded", "FileSyncDownloadedFull"]),
            ),
        ],
        "threshold": {
            "aggregation": "count",
            "operator": "gt",
            "value": 50,
            "window_minutes": 60,
            "group_by": "user_id",
        },
        "watch_window": _ww(14, 20),
        "description": "50+ file downloads within 1 hour.",
        "mitre_tactics": ["Collection", "Exfiltration"],
        "mitre_techniques": ["T1530"],
    },
}

RULE_3_2 = {
    "name": "3.2 Bulk File Delete",
    "severity": Severity.HIGH,
    "risk_points": 20,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "sharepoint",
                _m("operation", "in", ["FileDeleted", "FileDeletedFirstStageRecycleBin"]),
            ),
        ],
        "threshold": {
            "aggregation": "count",
            "operator": "gt",
            "value": 30,
            "window_minutes": 60,
            "group_by": "user_id",
        },
        "watch_window": _ww(14, 20),
        "description": "30+ files deleted within 1 hour.",
        "mitre_tactics": ["Impact"],
        "mitre_techniques": ["T1485"],
    },
}

RULE_3_3 = {
    "name": "3.3 Recycle Bin Purge",
    "severity": Severity.HIGH,
    "risk_points": 25,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "sharepoint",
                _m("operation", "in", [
                    "FileDeletedSecondStageRecycleBin",
                    "FolderDeletedSecondStageRecycleBin",
                ]),
            ),
        ],
        "watch_window": _ww(14, 25),
        "description": "Items were permanently deleted from the second-stage recycle bin.",
        "mitre_tactics": ["Impact", "Defense Evasion"],
        "mitre_techniques": ["T1485"],
    },
}

RULE_3_4 = {
    "name": "3.4 Anonymous Sharing Link Created",
    "severity": Severity.MEDIUM,
    "risk_points": 15,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "sharepoint",
                _m("operation", "eq", "AnonymousLinkCreated"),
            ),
        ],
        "watch_window": _ww(14, 15),
        "description": "An anonymous (anyone) sharing link was created for a document.",
        "mitre_tactics": ["Exfiltration"],
        "mitre_techniques": ["T1567"],
    },
}

RULE_3_5 = {
    "name": "3.5 External User Sharing",
    "severity": Severity.MEDIUM,
    "risk_points": 15,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "sharepoint",
                _m("operation", "in", [
                    "SharingInvitationCreated",
                    "AddedToSecureLink",
                ]),
                _m("raw_json.TargetUserOrGroupType", "eq", "Guest"),
            ),
        ],
        "watch_window": _ww(14, 15),
        "description": "Content was shared with an external / guest user.",
        "mitre_tactics": ["Exfiltration"],
        "mitre_techniques": ["T1567"],
    },
}

RULE_3_6 = {
    "name": "3.6 Mass Sharing Burst",
    "severity": Severity.HIGH,
    "risk_points": 20,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "sharepoint",
                _m("operation", "in", [
                    "AnonymousLinkCreated",
                    "SharingInvitationCreated",
                    "CompanyLinkCreated",
                ]),
            ),
        ],
        "threshold": {
            "aggregation": "count",
            "operator": "gt",
            "value": 20,
            "window_minutes": 60,
            "group_by": "user_id",
        },
        "watch_window": _ww(14, 20),
        "description": "20+ sharing events within 1 hour.",
        "mitre_tactics": ["Exfiltration"],
        "mitre_techniques": ["T1567"],
    },
}

RULE_3_7 = {
    "name": "3.7 Sensitive File Type Downloaded",
    "severity": Severity.MEDIUM,
    "risk_points": 15,
    "watch_window_days": 7,
    "rule_definition": {
        "triggers": [
            _trigger(
                "sharepoint",
                _m("operation", "eq", "FileDownloaded"),
                _m("source_file_extension", "in", [
                    "pst", "ost", "bak", "sql", "mdb", "accdb",
                    "pfx", "key", "pem", "kdbx", "ovpn",
                ]),
            ),
        ],
        "watch_window": _ww(7, 15),
        "description": "Download of a sensitive file type (backup, database, certificate, password vault).",
        "mitre_tactics": ["Collection"],
        "mitre_techniques": ["T1530"],
    },
}

RULE_3_8 = {
    "name": "3.8 Data Access After Risky Sign-In",
    "severity": Severity.HIGH,
    "risk_points": 25,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "sharepoint",
                _m("operation", "in", ["FileDownloaded", "FileAccessed"]),
            ),
        ],
        "correlations": [
            {
                "secondary_source": "entra_signin",
                "secondary_matchers": [
                    _m("raw_json.riskLevelDuringSignIn", "in", ["medium", "high"]),
                ],
                "window_minutes": 120,
                "direction": "before",
            },
        ],
        "watch_window": _ww(14, 25),
        "description": "File download/access within 2 hours of a risky sign-in.",
        "mitre_tactics": ["Collection", "Exfiltration"],
        "mitre_techniques": ["T1530"],
    },
}

# ── Category 4: Consent & Application Abuse ──────────────────────────────

RULE_4_1 = {
    "name": "4.1 Illicit Consent Grant",
    "severity": Severity.CRITICAL,
    "risk_points": 30,
    "watch_window_days": 30,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "eq", "Consent to application"),
                _m("raw_json.targetResources", "contains", "AllPrincipals"),
            ),
        ],
        "watch_window": _ww(30, 30),
        "description": "Admin consent was granted to an application for all users.",
        "mitre_tactics": ["Persistence", "Defense Evasion"],
        "mitre_techniques": ["T1550.001"],
    },
}

RULE_4_2 = {
    "name": "4.2 New Service Principal with Credentials",
    "severity": Severity.HIGH,
    "risk_points": 20,
    "watch_window_days": 30,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "in", [
                    "Add service principal credentials",
                    "Add service principal",
                ]),
            ),
        ],
        "watch_window": _ww(30, 20),
        "description": "A service principal was created or had credentials added.",
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1098.001"],
    },
}

RULE_4_3 = {
    "name": "4.3 App Registration Modified",
    "severity": Severity.MEDIUM,
    "risk_points": 15,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "in", [
                    "Update application",
                    "Update application – Certificates and secrets management",
                    "Add owner to application",
                ]),
                _m("category", "eq", "ApplicationManagement"),
            ),
        ],
        "watch_window": _ww(14, 15),
        "description": "An application registration was modified.",
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1098.001"],
    },
}

RULE_4_4 = {
    "name": "4.4 Consent After Risky Sign-In",
    "severity": Severity.CRITICAL,
    "risk_points": 30,
    "watch_window_days": 30,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "eq", "Consent to application"),
            ),
        ],
        "correlations": [
            {
                "secondary_source": "entra_signin",
                "secondary_matchers": [
                    _m("raw_json.riskLevelDuringSignIn", "in", ["medium", "high"]),
                ],
                "window_minutes": 120,
                "direction": "before",
            },
        ],
        "watch_window": _ww(30, 30),
        "description": "Application consent within 2 hours of a risky sign-in.",
        "mitre_tactics": ["Persistence", "Initial Access"],
        "mitre_techniques": ["T1550.001"],
    },
}

RULE_4_5 = {
    "name": "4.5 Bulk Permission Grants",
    "severity": Severity.HIGH,
    "risk_points": 25,
    "watch_window_days": 30,
    "rule_definition": {
        "triggers": [
            _trigger(
                "entra_audit",
                _m("activity_display_name", "in", [
                    "Add app role assignment to service principal",
                    "Add delegated permission grant",
                    "Add app role assignment grant to user",
                ]),
            ),
        ],
        "threshold": {
            "aggregation": "count",
            "operator": "gt",
            "value": 5,
            "window_minutes": 60,
            "group_by": "initiated_by_user",
        },
        "watch_window": _ww(30, 25),
        "description": "5+ permission grants within 1 hour.",
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1098.001"],
    },
}

# ── Category 5: Shadow IT / Power Platform ───────────────────────────────

RULE_5_1 = {
    "name": "5.1 Power App Created by Watched User",
    "severity": Severity.HIGH,
    "risk_points": 20,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "powerapps",
                _m("operation", "in", ["CreatePowerApp", "PublishPowerApp"]),
            ),
        ],
        "watch_window": _ww(14, 20),
        "description": "A user created or published a Power App.",
        "mitre_tactics": ["Persistence", "Execution"],
        "mitre_techniques": ["T1059"],
    },
}

RULE_5_2 = {
    "name": "5.2 Connector Consent Granted",
    "severity": Severity.MEDIUM,
    "risk_points": 15,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "powerapps",
                _m("operation", "in", [
                    "ConsentToConnector",
                    "CreateConnection",
                ]),
            ),
        ],
        "watch_window": _ww(14, 15),
        "description": "A user consented to a Power Platform connector.",
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1098"],
    },
}

RULE_5_3 = {
    "name": "5.3 Power App Published to Org",
    "severity": Severity.MEDIUM,
    "risk_points": 15,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "powerapps",
                _m("operation", "eq", "PublishPowerApp"),
            ),
        ],
        "watch_window": _ww(14, 15),
        "description": "A Power App was published to the organization.",
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1195"],
    },
}

RULE_5_4 = {
    "name": "5.4 Power Automate Flow Created",
    "severity": Severity.MEDIUM,
    "risk_points": 15,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "powerapps",
                _m("operation", "in", ["CreateFlow", "EditFlow"]),
            ),
        ],
        "watch_window": _ww(14, 15),
        "description": "A Power Automate flow was created or edited.",
        "mitre_tactics": ["Execution"],
        "mitre_techniques": ["T1059"],
    },
}

RULE_5_5 = {
    "name": "5.5 DLP Policy Violation",
    "severity": Severity.HIGH,
    "risk_points": 20,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "powerapps",
                _m("operation", "in", [
                    "CreateDlpPolicy",
                    "UpdateDlpPolicy",
                    "DeleteDlpPolicy",
                ]),
            ),
        ],
        "watch_window": _ww(14, 20),
        "description": "A DLP policy was created, updated, or deleted in Power Platform.",
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562"],
    },
}

RULE_5_6 = {
    "name": "5.6 Third-Party App Installed",
    "severity": Severity.MEDIUM,
    "risk_points": 15,
    "watch_window_days": 7,
    "rule_definition": {
        "triggers": [
            _trigger(
                "office365",
                _m("operation", "in", [
                    "AppInstalled",
                    "AppUpgraded",
                ]),
            ),
        ],
        "watch_window": _ww(7, 15),
        "description": "A third-party application was installed (Teams / O365 add-in).",
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1195.002"],
    },
}

RULE_5_7 = {
    "name": "5.7 Power Platform Environment Created",
    "severity": Severity.MEDIUM,
    "risk_points": 15,
    "watch_window_days": 14,
    "rule_definition": {
        "triggers": [
            _trigger(
                "powerapps",
                _m("operation", "in", [
                    "CreateEnvironment",
                    "AdminCreateEnvironment",
                ]),
            ),
        ],
        "watch_window": _ww(14, 15),
        "description": "A new Power Platform environment was created.",
        "mitre_tactics": ["Resource Development"],
        "mitre_techniques": ["T1583"],
    },
}

# ── Meta-rules ────────────────────────────────────────────────────────────

META_RULE_M1 = {
    "name": "M.1 Account Takeover Chain",
    "severity": Severity.CRITICAL,
    "risk_points": 40,
    "watch_window_days": 30,
    "rule_definition": {
        "meta_rule": {
            "required_rule_slugs": [
                "1.1 MFA Method Changed",
                "1.5 Password Changed After Risky Sign-In",
            ],
            "min_active_windows": 2,
        },
        "watch_window": _ww(30, 40),
        "description": "MFA change + password change after risky sign-in for the same user.",
        "mitre_tactics": ["Initial Access", "Persistence"],
        "mitre_techniques": ["T1078"],
    },
}

META_RULE_M2 = {
    "name": "M.2 Persistence + Exfiltration",
    "severity": Severity.CRITICAL,
    "risk_points": 40,
    "watch_window_days": 30,
    "rule_definition": {
        "meta_rule": {
            "required_rule_slugs": [
                "4.2 New Service Principal with Credentials",
                "3.1 Mass File Download",
            ],
            "min_active_windows": 2,
        },
        "watch_window": _ww(30, 40),
        "description": "Service principal created + mass download for the same user.",
        "mitre_tactics": ["Persistence", "Exfiltration"],
        "mitre_techniques": ["T1098", "T1530"],
    },
}

META_RULE_M3 = {
    "name": "M.3 Privilege Escalation + Data Theft",
    "severity": Severity.CRITICAL,
    "risk_points": 40,
    "watch_window_days": 30,
    "rule_definition": {
        "meta_rule": {
            "required_rule_slugs": [
                "2.1 Global Admin Role Assigned",
                "3.1 Mass File Download",
            ],
            "min_active_windows": 2,
        },
        "watch_window": _ww(30, 40),
        "description": "Global Admin assignment + mass download for the same user.",
        "mitre_tactics": ["Privilege Escalation", "Exfiltration"],
        "mitre_techniques": ["T1078.004", "T1530"],
    },
}

META_RULE_M4 = {
    "name": "M.4 Shadow IT Data Pipeline",
    "severity": Severity.HIGH,
    "risk_points": 30,
    "watch_window_days": 21,
    "rule_definition": {
        "meta_rule": {
            "required_rule_slugs": [
                "5.4 Power Automate Flow Created",
                "5.2 Connector Consent Granted",
            ],
            "min_active_windows": 2,
        },
        "watch_window": _ww(21, 30),
        "description": "Power Automate flow + connector consent — potential shadow data pipeline.",
        "mitre_tactics": ["Collection", "Exfiltration"],
        "mitre_techniques": ["T1059", "T1567"],
    },
}

META_RULE_M5 = {
    "name": "M.5 Multi-Signal Compromise",
    "severity": Severity.CRITICAL,
    "risk_points": 50,
    "watch_window_days": 30,
    "rule_definition": {
        "meta_rule": {
            "required_rule_slugs": [],
            "min_active_windows": 3,
        },
        "watch_window": _ww(30, 50),
        "description": "3+ active watch windows for the same user — multi-signal compromise indicator.",
        "mitre_tactics": ["Multiple"],
        "mitre_techniques": ["T1078"],
    },
}

# ── Aggregate list ────────────────────────────────────────────────────────

ALL_SEED_RULES: list[dict] = [
    # Category 1
    RULE_1_1, RULE_1_2, RULE_1_3, RULE_1_4, RULE_1_5,
    RULE_1_6, RULE_1_7, RULE_1_8, RULE_1_9, RULE_1_10,
    # Category 2
    RULE_2_1, RULE_2_2, RULE_2_3, RULE_2_4, RULE_2_5, RULE_2_6,
    # Category 3
    RULE_3_1, RULE_3_2, RULE_3_3, RULE_3_4, RULE_3_5,
    RULE_3_6, RULE_3_7, RULE_3_8,
    # Category 4
    RULE_4_1, RULE_4_2, RULE_4_3, RULE_4_4, RULE_4_5,
    # Category 5
    RULE_5_1, RULE_5_2, RULE_5_3, RULE_5_4, RULE_5_5, RULE_5_6, RULE_5_7,
    # Meta
    META_RULE_M1, META_RULE_M2, META_RULE_M3, META_RULE_M4, META_RULE_M5,
]


def _make_slug(name: str) -> str:
    """Generate a URL-safe slug from a rule name like '1.1 MFA Method Changed'."""
    import re
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def seed_rules(db) -> int:
    """Insert all seed rules that do not already exist.

    Returns the number of newly inserted rules.
    """
    from sqlalchemy import select as sa_select
    existing_names: set[str] = set(
        db.execute(sa_select(CorrelationRule.name)).scalars().all()
    )
    inserted = 0
    for rule_data in ALL_SEED_RULES:
        if rule_data["name"] in existing_names:
            continue
        row = CorrelationRule(
            slug=_make_slug(rule_data["name"]),
            name=rule_data["name"],
            severity=rule_data["severity"],
            risk_points=rule_data["risk_points"],
            watch_window_days=rule_data["watch_window_days"],
            rule_definition=rule_data["rule_definition"],
            is_system=True,
            enabled=True,
        )
        db.add(row)
        inserted += 1
    db.flush()
    return inserted
