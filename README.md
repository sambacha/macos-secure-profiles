# macOS 

    + [The macOS system must allow only applications that have a valid digital signature to run.](#the-macos-system-must-allow-only-applications-that-have-a-valid-digital-signature-to-run)
      - [Check Content](#check-content)
    + [The macOS system must have the security assessment policy subsystem enabled.](#the-macos-system-must-have-the-security-assessment-policy-subsystem-enabled)
      - [Check Content](#check-content-1)
    + [The macOS system must not allow an unattended or automatic logon to the system.](#the-macos-system-must-not-allow-an-unattended-or-automatic-logon-to-the-system)
      - [Check Content](#check-content-2)
    + [The macOS system must set permissions on user home directories to prevent users from having access to read or modify another user's files.](#the-macos-system-must-set-permissions-on-user-home-directories-to-prevent-users-from-having-access-to-read-or-modify-another-user-s-files)
      - [Check Content](#check-content-3)
    + [The macOS system must authenticate peripherals before establishing a connection.](#the-macos-system-must-authenticate-peripherals-before-establishing-a-connection)
      - [Check Content](#check-content-4)
    + [The macOS system must be configured with a firmware password to prevent access to single user mode and booting from alternative media.](#the-macos-system-must-be-configured-with-a-firmware-password-to-prevent-access-to-single-user-mode-and-booting-from-alternative-media)
      - [Check Content](#check-content-5)
      - [Check Content](#check-content-6)
- [cat /etc/pam.d/login | grep -i pam_smartcard.so](#cat--etc-pamd-login---grep--i-pam-smartcardso)
- [login: auth account password session](#login--auth-account-password-session)
    + [The macOS system must be configured with system log files owned by root and group-owned by wheel or admin.](#the-macos-system-must-be-configured-with-system-log-files-owned-by-root-and-group-owned-by-wheel-or-admin)
      - [Check Content](#check-content-7)
    + [The macOS system must be configured with system log files set to mode 640 or less permissive.](#the-macos-system-must-be-configured-with-system-log-files-set-to-mode-640-or-less-permissive)
      - [Check Content](#check-content-8)
    + [The macOS system must be configured with the sudoers file configured to authenticate users on a per -tty basis.](#the-macos-system-must-be-configured-with-the-sudoers-file-configured-to-authenticate-users-on-a-per--tty-basis)
      - [Check Content](#check-content-9)
    + [The macOS system must be configured to prevent password proximity sharing requests from nearby Apple Devices.](#the-macos-system-must-be-configured-to-prevent-password-proximity-sharing-requests-from-nearby-apple-devices)
      - [Check Content](#check-content-10)
    + [The macOS system must be configured to prevent users from erasing all system content and settings.](#the-macos-system-must-be-configured-to-prevent-users-from-erasing-all-system-content-and-settings)
      - [Check Content](#check-content-11)

<small><i><a href='http://ecotrust-canada.github.io/markdown-toc/'>Table of contents generated with markdown-toc</a></i></small>


### The macOS system must allow only applications that have a valid digital signature to run.


Vulnerability Discussion: Gatekeeper settings must be configured correctly to only allow the system to run applications signed with a valid Apple Developer ID code. Administrator users will still have the option to override these settings on a per-app basis. Gatekeeper is a security feature that ensures that applications must be digitally signed by an Apple-issued certificate in order to run. Digital signatures allow the macOS host to verify that the application has not been modified by a malicious third party.


#### Check Content    
Identify any unsigned applications that have been installed on the system:
/usr/sbin/system_profiler SPApplicationsDataType | /usr/bin/grep -B 3 -A 4 -e "Obtained from: Unknown" | /usr/bin/grep -v -e "Location: /Library/Application Support/Script Editor/Templates" -e "Location: /System/Library/" | /usr/bin/awk -F "Location: " '{print $2}' | /usr/bin/sort -u

If any results are returned and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify only applications with a valid digital signature are allowed to run:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(EnableAssessment | AllowIdentifiedDevelopers)'

If the return is null or is not the following, this is a finding:

AllowIdentifiedDevelopers = 1;
EnableAssessment = 1;

Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  



### The macOS system must have the security assessment policy subsystem enabled.


Vulnerability Discussion: Any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Accordingly, software defined by the organization as critical must be signed with a certificate that is recognized and approved by the organization.


#### Check Content    
To check the status of the Security assessment policy subsystem, run the following command:

/usr/sbin/spctl --status 2> /dev/null | /usr/bin/grep enabled

If "assessments enabled" is not returned, this is a finding.

Fix Text: To enable the Security assessment policy subsystem, run the following command:

/usr/bin/sudo /usr/sbin/spctl --master-enable  


### The macOS system must not allow an unattended or automatic logon to the system.


Vulnerability Discussion: Failure to restrict system access to authenticated users negatively impacts operating system security.


#### Check Content    
To check if the system is configured to automatically log on, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableAutoLoginClient

If "com.apple.login.mcx.DisableAutoLoginClient" is not set to "1", this is a finding.

Fix Text: This setting is enforced using the "Login Window Policy" configuration profile.  

CCI: CCI-000366



### The macOS system must set permissions on user home directories to prevent users from having access to read or modify another user's files.


Vulnerability Discussion: Configuring the operating system to use the most restrictive permissions possible for user home directories helps to protect against inadvertent disclosures.

Satisfies: SRG-OS-000480-GPOS-00228, SRG-OS-000480-GPOS-00230


#### Check Content    
To verify that permissions are set correctly on user home directories, use the following commands:

ls -le /Users

Should return a listing of the permissions of the root of every user account configured on the system. For each of the users, the permissions should be:
"drwxr-xr-x+" with the user listed as the owner and the group listed as "staff". The plus(+) sign indicates an associated Access Control List, which should be:
 0: group:everyone deny delete

For every authorized user account, also run the following command:
/usr/bin/sudo ls -le /Users/userid, where userid is an existing user. 

This command will return the permissions of all of the objects under the users' home directory. The permissions for each of the subdirectories should be:
drwx------+ 
 0: group:everyone deny delete

With the exception of the "Public" directory, whose permissions should match the following:
drwxr-xr-x+ 
 0: group:everyone deny delete

If the permissions returned by either of these checks differ from what is shown, this is a finding.

Fix Text: To ensure the appropriate permissions are set for each user on the system, run the following command:

diskutil resetUserPermissions / userid, where userid is the user name for the user whose home directory permissions need to be repaired.  


### The macOS system must authenticate peripherals before establishing a connection.


Vulnerability Discussion: Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.


#### Check Content    
To check that macOS is configured to require authentication to all system preference panes, use the following commands:

/usr/bin/sudo /usr/bin/security authorizationdb read system.preferences | grep -A1 shared

If what is returned does not include the following, this is a finding.
	<key>shared</key>
	<false/>

Fix Text: To ensure that authentication is required to access all system level preference panes use the following procedure:

Copy the authorization database to a file using the following command:
/usr/bin/sudo /usr/bin/security authorizationdb read system.preferences > ~/Desktop/authdb.txt
edit the file to change:
    <key>shared</key>
    <true/>
To read:
    <key>shared</key>
    <false/>

Reload the authorization database with the following command:
/usr/bin/sudo /usr/bin/security authorizationdb write system.preferences < ~/Desktop/authdb.txt  


### The macOS system must be configured with a firmware password to prevent access to single user mode and booting from alternative media.


Vulnerability Discussion: Single user mode and the boot picker, as well as numerous other tools are available on macOS through booting while holding the "Option" key down. Setting a firmware password restricts access to these tools.


#### Check Content    
For Apple Silicon-based systems, this is Not Applicable.

For Intel-based systems, ensure that a firmware password is set, run the following command:

$ sudo /usr/sbin/firmwarepasswd -check

If the return is not "Password Enabled: Yes", this is a finding.

Fix Text: To set a firmware passcode use the following command.

sudo /usr/sbin/firmwarepasswd -setpasswd

Note: If firmware password or passcode is forgotten, the only way to reset the forgotten password is through the use of a machine specific binary generated and provided by Apple. Schedule a support call, and provide proof of purchase before the firmware binary will be generated.  



ule Title: The macOS system must be configured so that the login command requires smart card authentication.


Vulnerability Discussion: Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.


#### Check Content    
For systems that are not utilizing smart card authentication, this is Not Applicable.

To verify that the "login" command has been configured to require smart card authentication, run the following command:

# cat /etc/pam.d/login | grep -i pam_smartcard.so

If the text that returns does not include the line, "auth sufficient pam_smartcard.so" at the TOP of the listing, this is a finding.

Fix Text: Make a backup of the PAM LOGIN settings using the following command:
sudo cp /etc/pam.d/login /etc/pam.d/login_backup_`date "+%Y-%m-%d_%H:%M"`

Replace the contents of "/etc/pam.d/login" with the following:

# login: auth account password session
auth		sufficient	 pam_smartcard.so
auth    optional    pam_krb5.so use_kcminit
auth    optional    pam_ntlm.so try_first_pass
auth    optional    pam_mount.so try_first_pass
auth    required    pam_opendirectory.so try_first_pass
auth    required    pam_deny.so
account  required    pam_nologin.so
account  required    pam_opendirectory.so
password  required    pam_opendirectory.so
session  required    pam_launchd.so
session  required    pam_uwtmp.so
session  optional    pam_mount.so  


### The macOS system must be configured with system log files owned by root and group-owned by wheel or admin.


Vulnerability Discussion: System logs should only be readable by root or admin users. System logs frequently contain sensitive information that could be used by an attacker. Setting the correct owner mitigates this risk.


#### Check Content    
Some system log files are controlled by "newsyslog" and "aslmanager".

The following commands check for log files that exist on the system and print the path to the log with the corresponding ownership. Run them from inside "/var/log". 

```bash
/usr/bin/sudo stat -f '%Su:%Sg:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
/usr/bin/sudo stat -f '%Su:%Sg:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
```

Each command may return zero or more files. 

If there are any system log files that are not owned by "root" and group-owned by "wheel" or "admin", this is a finding.

Service logs may be owned by the service user account or group.

Fix Text: For any log file that returns an incorrect owner or group value, run the following command:

```
/usr/bin/sudo chown root:wheel [log file]
```

[log file] is the full path to the log file in question. If the file is managed by "newsyslog", find the configuration line in the directory "/etc/newsyslog.d/" or the file "/etc/newsyslog.conf" and ensure that the owner:group column is set to "root:wheel" or the appropriate service user account and group. 

If the file is managed by "aslmanager", find the configuration line in the directory "/etc/asl/" or the file "/etc/asl.conf" and ensure that "uid" and "gid" options are either not present or are set to a service user account and group respectively.  



### The macOS system must be configured with system log files set to mode 640 or less permissive.


Vulnerability Discussion: System logs should only be readable by root or admin users. System logs frequently contain sensitive information that could be used by an attacker. Setting the correct permissions mitigates this risk.


#### Check Content    
The following commands check for log files that exist on the system and print the path to the log with the corresponding permissions. Run them from inside "/var/log":

/usr/bin/sudo stat -f '%A:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
/usr/bin/sudo stat -f '%A:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null

Each command may return zero or more files. If the permissions on log files are not "640" or less permissive, this is a finding.

Fix Text: For any log file that returns an incorrect permission value, run the following command:

/usr/bin/sudo chmod 640 [log file]

[log file] is the full path to the log file in question. If the file is managed by "newsyslog", find the configuration line in the directory "/etc/newsyslog.d/" or the file "/etc/newsyslog.conf" and edit the mode column to be "640" or less permissive. 

If the file is managed by "aslmanager", find the configuration line in the directory "/etc/asl/" or the file "/etc/asl.conf" and add or edit the mode option to be "mode=0640" or less permissive.  



### The macOS system must be configured with the sudoers file configured to authenticate users on a per -tty basis.


Vulnerability Discussion: The "sudo" command must be configured to prompt for the administrator's password at least once in each newly opened Terminal window or remote logon session, as this prevents a malicious user from taking advantage of an unlocked computer or an abandoned logon session to bypass the normal password prompt requirement. 

Without the "tty_tickets" option, all open local and remote logon sessions would be authenticated to use sudo without a password for the duration of the configured password timeout window.


#### Check Content    
To check if the "tty_tickets" option is set for "/usr/bin/sudo", run the following command:

/usr/bin/sudo /usr/bin/grep tty_tickets /etc/sudoers

If there is no result, this is a finding.

Fix Text: Edit the "/etc/sudoers" file to contain the line:

Defaults tty_tickets

This line can be placed in the defaults section or at the end of the file



### The macOS system must be configured to prevent password proximity sharing requests from nearby Apple Devices.


Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.


#### Check Content    
To check if allowPasswordProximityRequests is disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowPasswordProximityRequests
  
If the return is not "allowPasswordProximityRequests = 0", this is a finding.

Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  



### The macOS system must be configured to prevent users from erasing all system content and settings.


Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.


#### Check Content    
To check if allowEraseContentAndSettings is disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowEraseContentAndSettings
  
If the return is not "allowEraseContentAndSettings = 0", this is a finding.

Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
