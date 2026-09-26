"""Curated Tier-1 SOC knowledge base.

Four document kinds feed the retriever:
  technique  â€” ATT&CK technique with triage steps, detection queries, remediation
  playbook   â€” scenario runbook keyed to an alert category
  policy     â€” escalation / SLA / containment authorisation matrix
  query      â€” reusable detection logic (Sigma-flavoured, tool-agnostic)

Kept as plain dicts so it is greppable and diffable, and cheap to extend.
"""

TECHNIQUES: list[dict] = [
    {
        "id": "T1059.001",
        "kind": "technique",
        "title": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "keywords": "powershell encoded command pwsh scriptblock downloadstring invoke-expression",
        "body": (
            "Adversaries abuse PowerShell via -EncodedCommand, -w hidden, Invoke-Expression, "
            "FromBase64String, and in-memory download cradles (DownloadString, Net.WebClient, "
            "IEX) to execute payloads without writing executables to disk. EncodedCommand is the "
            "highest-fidelity signal. Check for AMSI bypass attempts, disabled logging, and "
            "remote runspace creation (New-PSSession, Invoke-Command to remote hosts)."
        ),
        "triage": [
            "Decode the -EncodedCommand payload (base64 + UTF-16LE) and inspect the plaintext.",
            "Check parent process: explorer.exe or w3wp.exe parent indicates execution, not a script.",
            "Check script block logging (Event ID 4104) for dynamic invocation.",
            "Look for .NET reflection: Assembly.Load, InvokeMember, [System.Reflection].",
        ],
        "queries": [
            "EventID=4104 | where ScriptBlockText has_any('FromBase64String','DownloadString','IEX','Invoke-Expression','-enc','amsi','Reflections')",
            "process_name=powershell.exe | where cmdline matches '(?i)-e(nc|ncodedcommand)\\s+[A-Za-z0-9+/=]{40,}'",
            "process_name=powershell.exe,pwsh.exe | where parent_image != 'explorer.exe' and parent_image != 'powershell.exe'",
        ],
        "remediation": [
            "Isolate the host if the decoded payload is malicious or touches credential stores.",
            "Force password reset for the executing account and revoke active sessions.",
            "Constrain PowerShell to ConstrainedLanguage Mode via WDAC/AppLocker.",
            "Enable Script Block Logging and AMSI integration enterprise-wide.",
        ],
    },
    {
        "id": "T1059.003",
        "kind": "technique",
        "title": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "keywords": "cmd.exe batch script rundll32 regsvr32 mshta wmic certutil bitsadmin",
        "body": (
            "cmd.exe chains living-off-the-land binaries to download or execute payloads. "
            "High-fidelity abuse patterns: certutil -urlcache -split -decode, bitsadmin /transfer, "
            "mshta http://, regsvr32 /i:http:// scrobj.dll, wmic process call create, "
            "rundll32 with export names like .jscript or JavaScript_*."
        ),
        "triage": [
            "Reconstruct the full command chain including parent cmd.exe invocations.",
            "Identify the network destination the LOLB tried to reach.",
            "Check for /c, /k, /r flags and any obfuscation (^, %, !var!, string concatenation).",
        ],
        "queries": [
            "process_name=certutil.exe,bitsadmin.exe | where cmdline matches '(?i)(-urlcache|-split|-decode|/transfer)'",
            "process_name=mshta.exe,rundll32.exe,regsvr32.exe | where cmdline matches '(?i)(https?://|javascript:)'",
            "process_name=wmic.exe | where cmdline matches '(?i)process call create'",
        ],
        "remediation": [
            "Block LOLB execution of remote content via application control policy.",
            "Alert on outbound connections from rundll32/regsvr32/mshta â€” they are near-always malicious.",
            "Verify the downloaded payload hash against known-good baselines.",
        ],
    },
    {
        "id": "T1003",
        "kind": "technique",
        "title": "OS Credential Dumping",
        "tactic": "Credential Access",
        "keywords": "lsass mimikatz sekurlsa procdump comsvcs minidump ntdsutil sam hive",
        "body": (
            "Credential dumping targets LSASS memory (procdump comsvcs.dll MiniDump, taskmgr, "
            "Mimikatz sekurlsa::logonpasswords), the SAM hive (reg save HKLM\\SAM), NTDS.dit "
            "(ntdsutil /ifm or vssadmin), and DPAPI master keys. Any handle opened to lsass.exe "
            "with VM_READ from a non-system process is a strong compromise indicator."
        ),
        "triage": [
            "Enumerate processes that opened handles to lsass.exe and their command lines.",
            "Check for comsvcs.dll MiniDump invocation â€” near-certain credential theft.",
            "Check whether a shadow copy was created or deleted immediately prior (vssadmin).",
            "Treat every account that was logged on the host during the dump window as exposed.",
        ],
        "queries": [
            "process_name=procdump.exe | where cmdline matches '(?i)lsass'",
            "cmdline matches '(?i)comsvcs\\.dll.*MiniDump'",
            "cmdline matches '(?i)(reg save .*\\\\SAM|reg save .*\\\\SYSTEM|vssadmin.*create shadow)'",
        ],
        "remediation": [
            "P1 â€” isolate host immediately and declare all local credentials compromised.",
            "Force reset of every local, domain and cached credential used on the host.",
            "Rotate krbtgt twice (reset 1 -> reset 2) to invalidate Kerberos tickets.",
            "Enable Credential Guard / LSA protection to block lsass memory reads.",
        ],
    },
    {
        "id": "T1021",
        "kind": "technique",
        "title": "Remote Services",
        "tactic": "Lateral Movement",
        "keywords": "smb wmi psexec rdp winrm dcom remote desktop lateral movement admin share",
        "body": (
            "Lateral movement via SMB (PsExec, admin$, c$), WMI (wmic /node process call create), "
            "WinRM/PowerShell Remoting, RDP, DCOM, and SSH. Establish whether the source host is "
            "authorised to reach the target. A workstation initiating outbound SMB to many peers is "
            "a higher-severity signal than a server reaching one admin share."
        ),
        "triage": [
            "Build the source -> destination pair list for the last 24h.",
            "Check if the source account is an admin/service account and whether it is expected.",
            "Look for service creation (T1543) on the destination shortly after the remote logon.",
        ],
        "queries": [
            "event_id=4624 logon_type=3 | where source_host not in server_list and target_host in critical_asset_list",
            "event_id=5140 | where share_name matches '(?i)(ADMIN\\$|IPC\\$|C\\$)' and subject not in admin_list",
            "cmdline matches '(?i)wmic /node:.*process call create'",
        ],
        "remediation": [
            "Restrict SMB/RDP/WinRM between endpoint subnets at the firewall.",
            "Enforce jump-host-only administration; disable direct RDP to workstations.",
            "Review local administrator group membership on every destination touched.",
        ],
    },
    {
        "id": "T1078",
        "kind": "technique",
        "title": "Valid Accounts",
        "tactic": "Persistence",
        "keywords": "valid accounts stolen credentials legitimate logon impossible travel service account",
        "body": (
            "Adversaries authenticate with legitimate credentials to avoid detection. Distinguish "
            "compromise from misuse by baseline deviation: impossible travel, new ASN/geo, new user "
            "agent, unusual hours, first-time host for the account, and logon type mismatch "
            "(interactive logon from a server is anomalous)."
        ),
        "triage": [
            "Compare the source IP reputation and ASN against the account's 30-day baseline.",
            "Check for concurrent sessions in two geographies (impossible travel).",
            "Verify the logon type: 3 (network) or 10 (RDP) from a known admin workstation is suspicious.",
            "Check whether MFA was satisfied, and by which factor type.",
        ],
        "queries": [
            "event_id=4624 | where account not in service_accounts and source_ip_country != user_home_country",
            "event_id=4624 logon_type=10 | where target_host not in server_list",
            "event_id=4768 | where preauth_type=0 and account not in legacy_app_list",
        ],
        "remediation": [
            "Reset the password and revoke all active sessions/tokens for the account.",
            "Force re-registration of MFA and review the factor history.",
            "Escalate to Identity team if privileged account or the account touches many hosts.",
        ],
    },
    {
        "id": "T1021.001",
        "kind": "technique",
        "title": "Remote Services: RDP",
        "tactic": "Lateral Movement",
        "keywords": "rdp 3389 terminal services mstsc remote desktop interactive logon",
        "body": (
            "RDP lateral movement. High-risk pattern: a non-admin workstation establishing RDP "
            "outbound to peers, or RDP logon followed within minutes by PowerShell execution. "
            "Also check for clipboard/drive redirection, which is a common data-theft channel."
        ),
        "triage": [
            "Identify the source and destination of each RDP session.",
            "Check Event ID 1149 (Network Profile Detection) for the source address.",
            "Correlate the session with subsequent process creation on the target.",
        ],
        "queries": [
            "event_id=1149 | where source_address not in vpn_range and profile != domain_authenticated",
            "event_id=21 (RDP) | where destination not in server_list",
        ],
        "remediation": [
            "Block RDP (3389) between workstations; require VPN + MFA for all RDP access.",
            "Enable Network Level Authentication and disable drive/clipboard redirection for non-admins.",
        ],
    },
    {
        "id": "T1486",
        "kind": "technique",
        "title": "Data Encrypted for Impact",
        "tactic": "Impact",
        "keywords": "ransomware encryption wiper shadow copy deletion bcdedit vssadmin",
        "body": (
            "Ransomware behaviour: rapid mass file rename/extension change, shadow copy deletion "
            "(vssadmin delete shadows, wbadmin delete catalog), recovery disablement "
            "(bcdedit /set {default} recoveryenabled No), and service stops (backup, SQL, VSS). "
            "ANY shadow-copy deletion combined with a mass file-change burst is a P1 with no triage."
        ),
        "triage": [
            "Confirm mass file modification volume against the host's 30-day baseline.",
            "Verify shadow copies and backup catalogue state on the affected hosts.",
            "Determine patient zero by comparing first-observed timestamps across hosts.",
            "Do not reboot affected hosts if memory forensics is required.",
        ],
        "queries": [
            "cmdline matches '(?i)(vssadmin.*delete shadows|wbadmin.*delete catalog|bcdedit.*recoveryenabled no)'",
            "file_operation=rename | where new_extension not in allowed_extensions and volume_change_ratio > 0.05",
            "process_name=* | where cmdline matches '(?i)net stop.*(vss|sql|backup)'",
        ],
        "remediation": [
            "P1 â€” immediate isolation of affected hosts; do not delay for confirmation.",
            "Verify offline or immutable backups are intact and tested before advertising recovery time.",
            "Disable the compromised accounts across the estate.",
            "Hunt for persistence and exfiltration from the same hosts in parallel.",
        ],
    },
    {
        "id": "T1567",
        "kind": "technique",
        "title": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "keywords": "exfiltration cloud storage dropbox onedrive mega pastebin upload dns tunnel",
        "body": (
            "Exfiltration via legitimate web services (cloud storage, paste sites, dead-drop "
            "resolvers) blends with normal egress. Signals: large uploads to a newly-registered or "
            "rare domain, uploads to personal cloud storage from a server, high entropy in DNS "
            "labels, and uploads immediately following archive/password-protected file creation."
        ),
        "triage": [
            "Quantify bytes sent to each external destination over the last 7 days.",
            "Check domain age and registration for newly observed external hosts.",
            "Look for staged archives (7z, rar with -p) created before the upload.",
        ],
        "queries": [
            "network_direction=outbound | where bytes_out > 100MB and destination_category != sanctioned_cdn",
            "process_name=rclone,winSCP,browser | where connection to personal_cloud_storage",
            "dns_query | where subdomain_entropy > 3.8 and query_count_per_hour > 500",
        ],
        "remediation": [
            "Apply proxy/egress allow-list; block unsanctioned cloud-storage domains at the proxy.",
            "Enable data-loss prevention on archive creation and outbound upload.",
            "Preserve proxy logs for the full exfiltration window before rotation.",
        ],
    },
    {
        "id": "T1190",
        "kind": "technique",
        "title": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "keywords": "exploit vulnerability cve internet facing web application unpatched log4shell",
        "body": (
            "Exploitation of an internet-exposed application. Correlate the CVE in the payload with "
            "actual patch state â€” many detections are exploitation attempts against already-patched "
            "systems, which downgrades to Medium. Distinguish attempt (400/404/500 without side "
            "effects) from success (child process, new file, or outbound callback)."
        ),
        "triage": [
            "Confirm the target's patch level against the CVE.",
            "Check for post-exploitation side effects: child process, new web shell, outbound beacon.",
            "Check WAF/IDS logs for repeated attempts indicating scanning vs a targeted campaign.",
        ],
        "queries": [
            "url_path contains '/${jndi:' or 'union+select' or '..%2f'",
            "web_server_access | where status in (200,500) and request_body matches '(?i)(\\$\\{jndi:|cmd=|/bin/sh)'",
        ],
        "remediation": [
            "Patch the vulnerable component immediately, or apply a virtual patch/WAF rule.",
            "Isolate the host if exploitation succeeded; review web root for web shells.",
            "Rotate any secrets or credentials exposed in the request path or config.",
        ],
    },
    {
        "id": "T1566",
        "kind": "technique",
        "title": "Phishing",
        "tactic": "Initial Access",
        "keywords": "phishing email attachment macro spearphishing credential harvest",
        "body": (
            "Email-borne initial access. Triage the sender domain (lookalike, reply-to mismatch, "
            "free-mail from a corporate persona), attachment type and hash, and whether the mail "
            "gateway detonated it. Successful phishing shows a sandbox submission from the "
            "recipient's host after delivery."
        ),
        "triage": [
            "Defang and expand all URLs; check against mail-gateway verdict and urlscan history.",
            "Enrich the attachment hash across all available sources.",
            "Check whether any other recipients received the same campaign and whether any clicked.",
            "Search the mail gateway for the sender infrastructure to size the campaign.",
        ],
        "queries": [
            "email_attachment | where extension in (iso,img,lnk,one) or has_macro",
            "email | where from_domain_age < 30_days and reply_to_domain != from_domain",
        ],
        "remediation": [
            "Purge the message from all mailboxes and block the sender infrastructure.",
            "If the attachment executed, isolate the recipient host and run the malware triage playbook.",
            "Reset credentials for anyone who interacted with the message.",
        ],
    },
    {
        "id": "T1055",
        "kind": "technique",
        "title": "Process Injection",
        "tactic": "Defense Evasion",
        "keywords": "process injection dll injection hollowing reflective load svchost explorer tamper",
        "body": (
            "Injection lets code run under a trusted process to evade detection. Signatures: "
            "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread on a remote PID, hollowing "
            "(NtUnmapViewOfSection on a legitimate image), and tampering with lsass/rundll32 "
            "tokens. Also check for signed-binary proxy execution (T1218)."
        ),
        "triage": [
            "Identify the source process and the injection target; a mismatch is a red flag.",
            "Check the target process's loaded modules for unsigned or temp-path DLLs.",
            "Correlate with the source process's own ancestry for the initial delivery vector.",
        ],
        "queries": [
            "api_call=VirtualAllocEx+WriteProcessMemory+CreateRemoteThread",
            "process_name=svchost.exe,rundll32.exe | where loaded_module_path matches '(?i)(temp|programdata|appdata)'",
        ],
        "remediation": [
            "Isolate the host; capture memory before reboot if feasible.",
            "Review the injecting binary's origin and persistence mechanism.",
            "Enforce signed-binary-only execution (WDAC allow-list).",
        ],
    },
    {
        "id": "T1110",
        "kind": "technique",
        "title": "Brute Force",
        "tactic": "Credential Access",
        "keywords": "brute force password spray failed logon account lockout many accounts one password",
        "body": (
            "Distinguish password spraying (one password against many accounts, low per-account "
            "count, avoids lockout) from brute force (many passwords against few accounts). "
            "Spraying is stealthier and is the pattern to hunt for. Success = a 4625 storm followed "
            "by a 4624 for one of the targeted accounts."
        ),
        "triage": [
            "Count distinct accounts per source IP; spraying is high-accounts/low-counts.",
            "Check whether any 4625 cluster is followed by a 4624 success.",
            "Check for MFA fatigue (repeated MFA prompts with denied logons).",
        ],
        "queries": [
            "event_id=4625 | group by source_ip | where distinct_accounts > 20 and attempts_per_account < 5",
            "event_id=4624 | where preceded_within_10m by (event_id=4625 group by source_ip)",
        ],
        "remediation": [
            "Block the source at the perimeter; enable lockout or progressive delay for sprayed accounts.",
            "Enforce MFA to make spraying ineffective.",
            "Review and reset any account that authenticated successfully after the spray.",
        ],
    },
    {
        "id": "T1071",
        "kind": "technique",
        "title": "Application Layer Protocol",
        "tactic": "Command and Control",
        "keywords": "c2 beacon http https dns callback command and control periodic jitter",
        "body": (
            "C2 over HTTP(S), DNS or other legitimate protocols. Key analytic is periodicity: beacon "
            "intervals cluster tightly around a mean with low jitter. Also look for a small "
            "request/response size ratio profile typical of tasking, and certificate anomalies "
            "(self-signed, default issuer, mismatched SAN)."
        ),
        "triage": [
            "Plot connection timestamps and compute the inter-arrival mean and standard deviation.",
            "Inspect TLS certificate issuer, SAN and validity for the destination.",
            "Check the destination's first-seen date and passive-DNS history.",
        ],
        "queries": [
            "network_connection | group by destination | where connection_count > 50 and stddev_interval_minutes < 0.5",
            "tls_certificate | where issuer matches '(?i)self.signed|default' and not in known_good",
        ],
        "remediation": [
            "Block the C2 destination at proxy, DNS and firewall; sinkhole the domain.",
            "Isolate the host and hunt for persistence and neighbouring beacons on the same subnet.",
        ],
    },
    {
        "id": "T1547",
        "kind": "technique",
        "title": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "keywords": "persistence run key startup folder scheduled task service registry autorun",
        "body": (
            "Persistence via Run/RunOnce keys, Startup folder, scheduled tasks, or services. "
            "Triage by asking whether the entry is software-expected: check signer, install path, "
            "and whether the binary hash matches a known-good package. Persistence in a temp or "
            "user-writable path is a high-confidence malicious verdict."
        ),
        "triage": [
            "List all new autostart entries in the last 14 days.",
            "Enrich each referenced binary hash and inspect the file's signature.",
            "Check the creating process in the log for the same event window.",
        ],
        "queries": [
            "registry_key in ('HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run','HKCU\\\\...\\\\Run') | where last_write > 14d",
            "scheduled_task | where action_path matches '(?i)(temp|appdata|programdata|public)'",
            "service_created | where image_path matches '(?i)(appdata|programdata|\\\\\\\\users\\\\\\\\)'",
        ],
        "remediation": [
            "Remove the unauthorised autostart entry and quarantine the referenced binary.",
            "Sweep the estate for the same persistence artefact (same binary hash or task name).",
            "Identify the initial access vector that created it.",
        ],
    },
    {
        "id": "T1053",
        "kind": "technique",
        "title": "Scheduled Task/Job",
        "tactic": "Execution",
        "keywords": "schtasks at.exe scheduled task cron persistence encoded arguments",
        "body": (
            "Abuse of schtasks, at.exe, or the Task Scheduler COM API. Watch for tasks created with "
            "SYSTEM or highest privileges that run a script from a user-writable location, and for "
            "tasks registered with a random or event-triggered schedule."
        ),
        "triage": [
            "Export the task XML and review Principal (RunLevel), Trigger and Action ExecStart.",
            "Check the action binary's path, hash and signature.",
        ],
        "queries": [
            "cmdline matches '(?i)schtasks /create' and cmdline matches '(?i)(ru system|/rl highest)'",
            "scheduled_task | where run_level in ('highest','system') and action_path matches '(?i)(temp|appdata|users)'",
        ],
        "remediation": [
            "Delete the task and quarantine the payload.",
            "Restrict task creation to administrators via GPO; alert on non-admin task creation.",
        ],
    },
    {
        "id": "T1218",
        "kind": "technique",
        "title": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "keywords": "rundll32 regsvr32 mshta certutil bitsadmin signed binary proxy execution",
        "body": (
            "Legitimate Windows binaries abused to proxy malicious payloads. The key tell is a "
            "signed Microsoft binary with an unusual parent, an unusual export/URL argument, or "
            "network access it has no business performing."
        ),
        "triage": [
            "Confirm the parent process and the user context.",
            "Extract the inline argument and treat it as a nested payload â€” enrich and decode it.",
        ],
        "queries": [
            "process_name in (rundll32.exe,regsvr32.exe,mshta.exe) | where cmdline matches '(?i)(https?://|javascript:|scrobj)'",
            "process_name=certutil.exe | where cmdline matches '(?i)-urlcache'",
        ],
        "remediation": [
            "Block the inline argument's network destination.",
            "Apply AppLocker/WDAC rules denying remote-URL arguments to these binaries.",
        ],
    },
    {
        "id": "T1499",
        "kind": "technique",
        "title": "Endpoint Denial of Service",
        "tactic": "Impact",
        "keywords": "dos denial of service resource exhaustion fork bomb huge file malware",
        "body": (
            "Availability impact. Distinguish an attack from a legitimate resource incident: "
            "check the process ancestry for a dropper, and whether the resource type is unusual "
            "for the host role (a print server spawning 4,000 browsers is not normal)."
        ),
        "triage": [
            "Identify the spawning process and its ancestry.",
            "Determine whether the volume exceeds the host's normal operating envelope.",
        ],
        "queries": [
            "process_name=* | where process_count_per_host > baseline * 5",
            "cmdline matches '(?i):\\(\\)' and process_name=cmd.exe",
        ],
        "remediation": [
            "Kill the offending process tree and isolate the host if self-propagating.",
            "Apply per-host process and memory quotas to blunt the impact.",
        ],
    },
    {
        "id": "T1498",
        "kind": "technique",
        "title": "Network Denial of Service",
        "tactic": "Impact",
        "keywords": "ddos volumetric amplification syn flood dns amplification reflection attack",
        "body": (
            "Volumetric or protocol-level DoS. Identify whether the estate is the target or an "
            "accom unwitting participant (reflection/amplification). Check for spoofed-source "
            "traffic (no TCP handshake, high SYN rate per source)."
        ),
        "triage": [
            "Compare traffic volume against the 30-day baseline per link.",
            "Determine role: target or reflector/amplifier.",
        ],
        "queries": [
            "flow | group by dst | where pps > baseline_pps * 3",
            "flow | where protocol='dns' and response_bytes > query_bytes * 20",
        ],
        "remediation": [
            "Engage upstream provider scrubbing; enable source-IP validation (BCP 38).",
            "Rate-limit and disable open resolvers/reflectors under your control.",
        ],
    },
    {
        "id": "T1620",
        "kind": "technique",
        "title": "Reflective Code Loading",
        "tactic": "Defense Evasion",
        "keywords": "reflective dll loading fileless in memory assembly load unmanaged payload",
        "body": (
            "Fileless execution: the payload never touches disk, defeating file-based AV. Detect "
            "via memory content, unbacked executable regions, and the .NET loader stack."
        ),
        "triage": [
            "Flag processes with no image on disk but with executable memory regions.",
            "Capture a memory image for offline analysis; do not reboot.",
        ],
        "queries": [
            "process | where image_path == null and has_executable_regions",
            "api_call=Assembly.Load+InvokeMember with originating process not dotnet.exe",
        ],
        "remediation": [
            "Isolate and memory-capture the host.",
            "Move to allow-list application control; file-based AV is not sufficient here.",
        ],
    },
    {
        "id": "T1552",
        "kind": "technique",
        "title": "Unsecured Credentials",
        "tactic": "Credential Access",
        "keywords": "credentials in files registry keys password manager plaintext secrets config",
        "body": (
            "Discovery of credentials in files, environment variables, registry keys, or password "
            "managers. Common in developer workstations: .env, .aws/credentials, config files "
            "with embedded keys, and cloud instance metadata access from unexpected processes."
        ),
        "triage": [
            "Identify the credential type and owner.",
            "Determine whether the accessing process is expected (the app that owns the secret).",
        ],
        "queries": [
            "process_name=curl,wget | where cmdline matches '(?i)169\\.254\\.169\\.254'",
            "file_access | where filename matches '(?i)(\\.env$|\\.aws\\\\credentials|id_rsa|\\.npmrc)$'",
        ],
        "remediation": [
            "Rotate any exposed secret â€” treat it as compromised regardless of how it was found.",
            "Move secrets to a managed vault and inject at runtime.",
        ],
    },
    {
        "id": "T1027",
        "kind": "technique",
        "title": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "keywords": "obfuscation base64 encoded packer cryptpter malformed unicode evasion",
        "body": (
            "Payloads are disguised via encoding, packing, or malformed Unicode to defeat static "
            "signatures. Indicators: high-entropy files, known packer stubs, unusual file "
            "extensions for the content type (a .docx that is actually an ELF binary)."
        ),
        "triage": [
            "Check the file's magic bytes against its extension â€” mismatch is a strong signal.",
            "Compute entropy and check for known packer signatures.",
        ],
        "queries": [
            "file_created | where extension != magic_type and magic_type in ('elf','pe','mz')",
            "file_created | where entropy > 7.2 and size < 5MB",
        ],
        "remediation": [
            "Quarantine the file and submit to a sandbox; block the hash enterprise-wide.",
        ],
    },
    {
        "id": "T1105",
        "kind": "technique",
        "title": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "keywords": "ingress tool transfer wget curl download payload second stage dropper",
        "body": (
            "Adversaries transfer tools or second-stage payloads onto a compromised host. "
            "This is frequently the first clear evidence of active attacker tooling rather "
            "than exploitation. Triage the destination URL, the saved file path, and whether "
            "the file was then executed."
        ),
        "triage": [
            "Identify the transfer tool and the remote URL.",
            "Check the saved file's path, hash and whether it executed immediately after.",
            "Determine whether the URL resolves to attacker-controlled infrastructure.",
        ],
        "queries": [
            "process_name=wget.exe,curl.exe,certutil.exe | where cmdline matches '(?i)https?://'",
            "process_name=powershell.exe | where cmdline matches '(?i)(Invoke-WebRequest|Start-BitsTransfer|Net\\.WebClient)'",
        ],
        "remediation": [
            "Quarantine the transferred file and block the source URL at the proxy.",
            "Hunt estate-wide for the same file hash and source domain.",
            "Review what allowed the transfer â€” proxy policy, DNS, or an internal relay.",
        ],
    },
    {
        "id": "T1090",
        "kind": "technique",
        "title": "Proxy",
        "tactic": "Command and Control",
        "keywords": "proxy tor socks vpn anonymisation relay pivot external proxy",
        "body": (
            "Adversaries route traffic through proxies, Tor or VPN exit nodes to defeat "
            "destination-based controls and to blend with legitimate remote-access traffic. "
            "Tor exit nodes are a high-signal indicator when combined with a single rare "
            "destination and periodic connections."
        ),
        "triage": [
            "Identify whether the source is a known Tor exit node or anonymisation service.",
            "Check the destination set â€” proxies with a single destination suggest C2 tunnelling.",
        ],
        "queries": [
            "network_connection | where asn in (tor_exit_asns) and destination_count_per_host <= 3",
            "proxy_log | where user_agent matches '(?i)tor' and destination not in sanctioned",
        ],
        "remediation": [
            "Block Tor exit nodes at the perimeter where business does not require them.",
            "Investigate the destination for C2 characteristics (see T1071 beaconing).",
        ],
    },
    {
        "id": "T1087",
        "kind": "technique",
        "title": "Account Discovery",
        "tactic": "Discovery",
        "keywords": "account discovery net user whoami quser domain accounts enumeration",
        "body": (
            "Enumeration of local and domain accounts. Typically follows initial access and "
            "precedes privilege escalation or lateral movement. The commands themselves are "
            "dual-use, so weight the process ancestry: a web server worker spawning net user "
            "is far more concerning than an administrator doing the same."
        ),
        "triage": [
            "Identify the parent process and user context.",
            "Check whether a broader enumeration sweep followed (LDAP queries, AD exports).",
        ],
        "queries": [
            "cmdline matches '(?i)(net user|net group|net localgroup|quser|whoami /groups)' and parent not in admin_tools",
        ],
        "remediation": [
            "Restrict enumeration capability where business permits.",
            "Treat a discovery burst from a non-administrator process as a strong pivot signal.",
        ],
    },
    {
        "id": "T1070",
        "kind": "technique",
        "title": "Indicator Removal",
        "tactic": "Defense Evasion",
        "keywords": "log clearing wevtutil clear-eventlog anti-forensics evidence destruction",
        "body": (
            "Clearing, disabling or tampering with event logs to remove evidence of activity. "
            "Any log-clearing event is high severity on its own because it is unambiguous "
            "adversarial intent and destroys investigative evidence."
        ),
        "triage": [
            "Identify which logs were cleared and by which account.",
            "Check whether the account is one an administrator would legitimately clear.",
            "Recover the cleared window from a remote collector if one exists.",
        ],
        "queries": [
            "cmdline matches '(?i)(wevtutil\\s+cl|Clear-EventLog|powershell.*-clear)' | severity: high",
            "event_id=1102,104 | where log_name not in ('System','Application')",
        ],
        "remediation": [
            "Escalate as a deliberate anti-forensics action.",
            "Verify log forwarding to an immutable remote collector is intact.",
            "Establish the full activity window for the account across other telemetry.",
        ],
    },
    {
        "id": "T1562",
        "kind": "technique",
        "title": "Impair Defenses",
        "tactic": "Defense Evasion",
        "keywords": "firewall disable tamper defender disable security tool evasion netsh",
        "body": (
            "Disabling or tampering with firewalls, endpoint protection, or logging to enable "
            "subsequent activity. Like T1070, intent is unambiguous and warrants immediate "
            "escalation regardless of what the adversary did afterwards."
        ),
        "triage": [
            "Confirm which defensive control was disabled and whether it was re-enabled.",
            "Treat the entire preceding time window as attacker-controlled.",
        ],
        "queries": [
            "cmdline matches '(?i)(Set-NetFirewallProfile.*-Enabled False|netsh.*firewall.*off)' | severity: high",
            "service_stopped | where service_name in ('WinDefend','Sysmon','firewalld','sensord)'",
        ],
        "remediation": [
            "Re-enable the control and confirm the agent is healthy and reporting.",
            "Escalate: defensive tampering implies an active, aware operator.",
        ],
    },
    {
        "id": "T1056",
        "kind": "technique",
        "title": "Input Capture",
        "tactic": "Collection",
        "keywords": "keylogger input capture credential harvesting clipboard screen capture",
        "body": (
            "Capturing keystrokes, clipboard contents or screen output to harvest credentials or "
            "spy on the user. Any confirmed keylogging is a high-severity finding regardless "
            "of the other activity on the host."
        ),
        "triage": [
            "Identify the capturing mechanism and its persistence.",
            "Determine the window during which keystrokes were captured.",
        ],
        "queries": [
            "process | where api_call=SetWindowsHookEx and hooked_class matches '(?i)keyboard'",
            "file_created | where filename matches '(?i)(keylog|keystrokes|capture)'",
        ],
        "remediation": [
            "Isolate the host and assume captured credentials are compromised.",
            "Force credential resets for every user who logged into the host during the window.",
        ],
    },
    {
        "id": "T1531",
        "kind": "technique",
        "title": "Account Access Removal",
        "tactic": "Impact",
        "keywords": "account disabled lockout deleted user impact user account removed insider",
        "body": (
            "Availability impact on identities: disabling, deleting, or locking out accounts. "
            "Often paired with ransomware or insider threat. Check for bulk changes in a short "
            "window, which indicates automation rather than a mistake."
        ),
        "triage": [
            "Count accounts affected and the time window.",
            "Identify the operator account and whether it authenticated legitimately.",
        ],
        "queries": [
            "event_id=4725,4722,4724 | group by operator | where affected_accounts > 3 and window_minutes < 15",
        ],
        "remediation": [
            "Restore accounts from the directory backup; freeze the operator account.",
            "Reset credentials for every restored account.",
        ],
    },
]

PLAYBOOKS: list[dict] = [
    {
        "id": "PB-MALWARE",
        "kind": "playbook",
        "title": "Playbook: Suspected Malware Execution",
        "tactic": "Execution",
        "keywords": "malware trojan ransomware virus suspicious process execution quarantined",
        "body": (
            "Standard Tier-1 flow for any endpoint malware detection. Confirm the detection, "
            "establish the execution context, decide containment, and hand off with complete "
            "context so Tier-2 does not repeat your work."
        ),
        "triage": [
            "Confirm the alert is not a known-benign security-tool process (AV, EDR, backup agents).",
            "Capture parent/child process tree and the full command line.",
            "Enrich the file hash and the parent binary hash; check first-seen date for both.",
            "Check the user's other activity in the last 60 minutes for the delivery vector.",
            "Confirm with threat intel whether the hash is a known family and which techniques it maps to.",
        ],
        "queries": [
            "process_name=<suspect> | retrieve ancestry depth=5 within 1h",
            "file_hash=<hash> | where first_seen is null or first_seen > 7d",
        ],
        "remediation": [
            "Isolate the endpoint via EDR if the verdict is true_positive or strongly suspicious.",
            "Do NOT reboot â€” preserve memory for Tier-2 forensics.",
            "Reset the user password if the process ran in a user context.",
            "Sweep the estate for the same hash and the same parent-binary hash.",
        ],
    },
    {
        "id": "PB-PHISHING",
        "kind": "playbook",
        "title": "Playbook: Phishing Report Triage",
        "tactic": "Initial Access",
        "keywords": "phishing email reported suspicious message credential harvest link attachment",
        "body": (
            "Handle user-reported phishing. The goal is to determine whether the message is "
            "malicious, whether anyone else received it, and whether anyone interacted."
        ),
        "triage": [
            "Retrieve the original message with full headers from the mail gateway.",
            "Check the mail-gateway detonation result and SPF/DKIM/DMARC alignment.",
            "Defang every URL and check the domain's age, WHOIS and urlscan history.",
            "Enrich every attachment hash and expand shortened links.",
            "Search the gateway for the campaign: same sender infra, same subject, same attachment hash.",
            "List recipients and identify who opened or clicked.",
        ],
        "queries": [
            "mail_gateway | search sender_domain,subject,attachment_hash within 30d",
            "proxy_log | where url in (phishing_urls) and user_action in (view,download)",
        ],
        "remediation": [
            "Purge from all mailboxes, block sender IP/domain/URLs.",
            "If a click occurred, reset credentials and check for post-click malware execution.",
            "Report to the mail provider and to the impersonated brand if external.",
        ],
    },
    {
        "id": "PB-BRUTEFORCE",
        "kind": "playbook",
        "title": "Playbook: Authentication Abuse / Brute Force",
        "tactic": "Credential Access",
        "keywords": "brute force spray failed login 4625 lockout authentication attack password",
        "body": (
            "Distinguish attack from user error (someone fat-fingering their password generates a "
            "handful of 4625s from one source against one account)."
        ),
        "triage": [
            "Count failed logons by source IP, by account, and by time.",
            "Classify: brute force (few accounts, many attempts) vs spraying (many accounts, few attempts).",
            "Check for any successful 4624 within 10 minutes of the failure cluster.",
            "Check the source IP reputation and whether it is internal or external.",
            "If the source is internal, treat the internal host as compromised and pivot to PB-MALWARE.",
        ],
        "queries": [
            "event_id=4625 | group by source_ip,account | rank by attempts",
            "event_id=4624 | where source_ip in (top_spray_sources) and window after failures",
        ],
        "remediation": [
            "Block or rate-limit the source.",
            "Reset any account that authenticated successfully after the spray.",
            "Enforce MFA and account lockout policy; alert on spray-shaped patterns, not just volume.",
        ],
    },
    {
        "id": "PB-C2",
        "kind": "playbook",
        "title": "Playbook: Command and Control Beacon",
        "tactic": "Command and Control",
        "keywords": "c2 beacon callback command control periodic connection malware dns tunnel",
        "body": (
            "A periodic outbound connection is the strongest single malware indicator. Goal is to "
            "identify the destination, the malware family, and every other host talking to it."
        ),
        "triage": [
            "Compute inter-arrival mean and standard deviation to confirm beaconing (low jitter).",
            "Passive-DNS and WHOIS the destination; check registration age and hosting provider.",
            "Inspect the TLS certificate (issuer, SAN, validity).",
            "Identify the initiating process and its full ancestry.",
            "Query every host's connections to the same destination and to sibling C2 infrastructure.",
        ],
        "queries": [
            "network_connection | where destination in (c2_destinations) group by host",
            "network_connection | group by host,destination | where count > 20 and jitter_minutes < 0.5",
        ],
        "remediation": [
            "Block the destination at proxy, DNS and firewall simultaneously.",
            "Isolate the originating host and run PB-MALWARE.",
            "Hunt the estate-wide for other beacons with the same TLS fingerprint.",
        ],
    },
    {
        "id": "PB-RANSOMWARE",
        "kind": "playbook",
        "title": "Playbook: Ransomware / Mass Encryption",
        "tactic": "Impact",
        "keywords": "ransomware encryption mass file change shadow copy bcdedit impact",
        "body": (
            "Treat as confirmed P1 from first evidence. Do not spend time proving it before "
            "isolating. The priority order is: stop spread, preserve evidence, protect backups, "
            "then scope."
        ),
        "triage": [
            "Isolate the host immediately â€” do not wait for confirmation.",
            "Do not power off if memory forensics is required; note the trade-off explicitly.",
            "Identify patient zero by comparing first-observed encryption timestamps estate-wide.",
            "Verify shadow copies, backup catalogue and offline/immutable copies are intact.",
            "Identify the initial access vector and the account used for encryption.",
            "List every file extension added to build the extension-agnostic recovery script.",
        ],
        "queries": [
            "vssadmin,wbadmin,bcdedit | where cmdline matches '(?i)(delete shadows|delete catalog|recoveryenabled no)'",
            "file_change | group by host | where changed_file_ratio > 0.05 within 1h",
        ],
        "remediation": [
            "P1 â€” isolate all affected hosts; disable the compromised identities.",
            "Confirm and validate offline backups before communicating any RTO.",
            "Rebuild rather than decrypt unless a clean, tested decryptor exists and keys are held.",
            "Post-incident: rotate krbtgt twice, rotate all privileged secrets estate-wide.",
        ],
    },
    {
        "id": "PB-INSIDER",
        "kind": "playbook",
        "title": "Playbook: Suspicious User Activity / Possible Insider",
        "tactic": "Collection",
        "keywords": "insider threat unusual activity bulk download off hours data access privileged user",
        "body": (
            "Handle with care and confidentiality. The goal is factual evidence assembly, not "
            "conclusion. Route conclusions to the appropriate investigation owner."
        ),
        "triage": [
            "Establish the user's baseline: normal hours, normal data volume, normal destinations.",
            "Quantify the deviation precisely with numbers and timestamps.",
            "Check DLP policy hits and any USB/mass-storage events.",
            "Check for personal-drive or personal-cloud usage during working hours.",
            "Confirm the user identity with the manager or HR partner before escalation.",
        ],
        "queries": [
            "file_access | where user in (target) and bytes_read > baseline * 10",
            "usb_event | where user in (target) and device_type='removable'",
        ],
        "remediation": [
            "Preserve evidence with a legal hold before any disruptive action.",
            "Escalate to the insider-risk owner; do not tip off the subject.",
            "Restrict access only if there is an active data-loss risk.",
        ],
    },
    {
        "id": "PB-CLOUD",
        "kind": "playbook",
        "title": "Playbook: Cloud / SaaS Compromise",
        "tactic": "Initial Access",
        "keywords": "oauth consent azure ad entra id suspicious login mfa fatigue service principal consent app",
        "body": (
            "Cloud identity incidents centre on the token, not the password. Consent grants and "
            "service principals are the usual persistence mechanism."
        ),
        "triage": [
            "Enumerate app consent grants and service principals created recently.",
            "Check sign-in logs for unfamiliar user agents, IPs and geographies.",
            "Review conditional-access policy changes and mailbox rules (a common persistence trick).",
            "Check for MFA method registration by unfamiliar devices.",
            "Revoke sessions and refresh tokens for affected identities.",
        ],
        "queries": [
            "audit_log | where operation in ('Add service principal','Add app consent','Add member to role') and actor not in admins",
            "audit_log | where operation='Update user' and changed 'mobilePhone,otherMails' (MFA factor changes)",
        ],
        "remediation": [
            "Revoke all refresh tokens and deactivate the malicious app/service principal.",
            "Remove attacker-added role assignments and mailbox rules.",
            "Enforce MFA, disable legacy authentication, restrict app consent to admins.",
        ],
    },
]

POLICIES: list[dict] = [
    {
        "id": "PO-ESCALATION",
        "kind": "policy",
        "title": "Escalation Matrix and SLA",
        "tactic": "Governance",
        "keywords": "escalation sla severity p1 p2 p3 response time tier 1 tier 2 severity matrix",
        "body": (
            "Escalate immediately, without waiting for full analysis, when any of these hold: "
            "(1) ransomware or destructive behaviour confirmed; (2) credential dumping observed; "
            "(3) a domain admin, krbtgt or Tier-0 asset involved; (4) active data exfiltration; "
            "(5) a customer-data or regulated-data boundary crossed; (6) a malicious insider "
            "signal; (7) a critical asset with confirmed compromise. SLA: P1 15 minutes to "
            "human, P2 1 hour, P3 4 hours, P4 next business day."
        ),
        "triage": [
            "State the trigger that fired, with the evidence that satisfied it.",
            "Do not escalate on severity label alone â€” escalate on evidence.",
        ],
        "queries": [],
        "remediation": [],
    },
    {
        "id": "PO-CONTAINMENT",
        "kind": "policy",
        "title": "Containment Authority and Rollback",
        "tactic": "Governance",
        "keywords": "containment authorisation isolation approval rollback automated action human in the loop",
        "body": (
            "Tier-1 may act without approval on: endpoint isolation, session/token revocation, and "
            "blocking a malicious destination. Everything else requires named-human approval: host "
            "shutdown, account disablement across multiple accounts, deletion of artefacts, "
            "legal-hold actions, and any change that could disrupt business operations. Every "
            "automated action must be logged with the trigger, the evidence, and a rollback path."
        ),
        "triage": [
            "Classify the proposed action against the authority list.",
            "For approval-required actions, produce a one-line justification a human can act on.",
        ],
        "queries": [],
        "remediation": [],
    },
    {
        "id": "PO-HANDOFF",
        "kind": "policy",
        "title": "Tier-1 to Tier-2 Handoff Standard",
        "tactic": "Governance",
        "keywords": "handoff tier 2 escalation report documentation evidence context quality",
        "body": (
            "A handoff is complete when a Tier-2 analyst can act without repeating any Tier-1 "
            "work. Required fields: what happened, when, which assets and identities, the evidence "
            "and where it lives, the verdict with confidence, mapped ATT&CK techniques with "
            "rationale, the containment already performed, outstanding questions, and the "
            "recommended next actions. Explicitly state what you ruled out and how."
        ),
        "triage": [
            "Re-read the draft against the required-fields list before sending.",
            "Include negative findings; they save the most time.",
        ],
        "queries": [],
        "remediation": [],
    },
    {
        "id": "PO-FP",
        "kind": "policy",
        "title": "False Positive Hygiene",
        "tactic": "Governance",
        "keywords": "false positive tuning allowlist known good noise baselining rule tuning",
        "body": (
            "A false positive is a tuning problem, not an analyst failure. Before closing as benign, "
            "answer: is the behaviour actually expected for this host role, is the binary signed by "
            "a trusted vendor, and does the process have a legitimate parent? Record the tuning "
            "recommendation with every benign close so the rule owner can act on it."
        ),
        "triage": [
            "Confirm signer, path and process lineage before declaring benign.",
            "State the exact tuning change that would prevent recurrence.",
        ],
        "queries": [],
        "remediation": [],
    },
]

QUERIES: list[dict] = [
    {
        "id": "Q-SPRAY",
        "kind": "query",
        "title": "Detection: Password Spraying",
        "tactic": "Credential Access",
        "keywords": "spray 4625 many accounts few attempts lockout evasion detection logic",
        "body": (
            "Canonical spray signature: one source touches many distinct accounts with a low "
            "per-account attempt count, avoiding account lockout thresholds. Threshold tuning is "
            "critical â€” pure volume alerts miss sprays and flood on password managers."
        ),
        "triage": ["Aggregate 4625 by source IP over a 15-minute window."],
        "queries": [
            "event_id=4625 | group by source_ip | where distinct_accounts >= 20 and max_attempts_per_account <= 4 | severity: high"
        ],
        "remediation": [],
    },
    {
        "id": "Q-LSASS",
        "kind": "query",
        "title": "Detection: LSASS Access Anomaly",
        "tactic": "Credential Access",
        "keywords": "lsass credential dump comsvcs minidump procdump mimikatz non-system process",
        "body": (
            "Any lsass.exe memory read from a process outside the expected EDR/AV set is a "
            "high-confidence compromise. Allow-list the security products; alert on everything else."
        ),
        "triage": ["Enumerate lsass handles and the owning process."],
        "queries": [
            "process_access | where target='lsass.exe' and source not in edr_allowlist | severity: critical",
            "cmdline matches '(?i)comsvcs\\.dll, MiniDump' | severity: critical"
        ],
        "remediation": [],
    },
    {
        "id": "Q-BEACON",
        "kind": "query",
        "title": "Detection: HTTP Beaconing",
        "tactic": "Command and Control",
        "keywords": "beacon periodic c2 jitter interval statistical analysis http dns",
        "body": (
            "Statistical beaconing detection: for each (host, destination) pair compute the "
            "standard deviation of inter-arrival times in minutes. Low jitter with enough samples "
            "is the discriminator that separates C2 from normal polling."
        ),
        "triage": ["Require >= 20 connections before alerting to control false positives."],
        "queries": [
            "network_connection | group by host,destination | where connections >= 20 and stdev_interval_min < 0.5 and avg_interval_min < 60 | severity: high"
        ],
        "remediation": [],
    },
    {
        "id": "Q-POWERSHELL-ENC",
        "kind": "query",
        "title": "Detection: Encoded PowerShell",
        "tactic": "Execution",
        "keywords": "powershell encoded command base64 hidden window obfuscation",
        "body": (
            "Detect and decode -EncodedCommand. Alerting on the flag alone produces noise from "
            "management tooling, so combine it with the decoded content containing download or "
            "in-memory execution primitives."
        ),
        "triage": ["Base64-decode and interpret as UTF-16LE, then inspect."],
        "queries": [
            "process_name=powershell.exe | where cmdline matches '(?i)-(e|en|enc|encodedcommand)\\s+[A-Za-z0-9+/=]{40,}' | decode base64 utf16le | where contains_any('DownloadString','IEX','FromBase64String') | severity: high"
        ],
        "remediation": [],
    },
    {
        "id": "Q-RANSOM-PRE",
        "kind": "query",
        "title": "Detection: Ransomware Precursors",
        "tactic": "Impact",
        "keywords": "shadow copy deletion bcdedit recovery disabled precursor ransomware early warning",
        "body": (
            "Shadow-copy deletion and recovery-disablement are early-warning indicators that "
            "precede encryption by minutes. Alerting on these buys containment time that a "
            "file-change alert cannot."
        ),
        "triage": ["Correlate with the same host's file-change volume."],
        "queries": [
            "cmdline matches '(?i)(vssadmin delete shadows|wbadmin delete catalog|bcdedit /set .* recoveryenabled no)' | severity: critical"
        ],
        "remediation": [],
    },
    {
        "id": "Q-EXFIL",
        "kind": "query",
        "title": "Detection: Anomalous Outbound Volume",
        "tactic": "Exfiltration",
        "keywords": "exfiltration outbound volume anomaly dlp large upload baseline deviation",
        "body": (
            "Baseline per (host, destination-category) over 30 days, then alert on multiplicative "
            "deviation rather than a fixed byte threshold â€” fixed thresholds are defeated by "
            "slow-and-low transfers."
        ),
        "triage": ["Compare against the 30-day p95 for the same host and category."],
        "queries": [
            "network_flow | group by host,destination_category | where bytes_out > 5 * p95_bytes_out_30d and duration_minutes < 60 | severity: high"
        ],
        "remediation": [],
    },
]


def all_documents() -> list[dict]:
    return TECHNIQUES + PLAYBOOKS + POLICIES + QUERIES


def by_id(doc_id: str) -> dict | None:
    for d in all_documents():
        if d["id"].lower() == doc_id.lower():
            return d
    return None
