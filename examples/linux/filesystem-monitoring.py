# Monitor suspicious file operations on Linux
linux_file_rule = """
title: Suspicious File Access on Linux
logsource:
    category: file_event
    product: linux
detection:
    sel:
        TargetFilename|contains:
            - '/etc/passwd'
            - '/etc/shadow'
            - '/etc/sudoers'
        CommandLine|contains:
            - 'cat'
            - 'cp'
            - 'mv'
    condition: sel
"""

rule = SigmaCollection.from_yaml(linux_file_rule)
ocsf_query = backend.convert(rule)
print("Linux File Event -> OCSF:")
print(ocsf_query[0])
# Output: class_uid=1001 and category_uid=1 and activity_id=1 and file.name contains-all ("/etc/passwd", "/etc/shadow", "/etc/sudoers") and process.cmd_line contains-all ("cat", "cp", "mv")
