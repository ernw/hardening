<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  

- [Introduction](#introduction)
- [Authentication](#authentication)
  - [Configure the Number of Administrative Accounts (Mandatory)](#configure-the-number-of-administrative-accounts-mandatory)
  - [Check That All Passwords are Shadowed (Mandatory)](#check-that-all-passwords-are-shadowed-mandatory)
  - [Use Strong Hashing Algorithm (Mandatory)](#use-strong-hashing-algorithm-mandatory)
  - [Implement A Secure Password Policy (Mandatory)](#implement-a-secure-password-policy-mandatory)
  - [Configure Account Lockout Policies (Mandatory)](#configure-account-lockout-policies-mandatory)
  - [Enable Password Aging (Mandatory)](#enable-password-aging-mandatory)
  - [Disable rlogin, rsh and rcp (Mandatory)](#disable-rlogin-rsh-and-rcp-mandatory)
  - [Disable telnet (Mandatory)](#disable-telnet-mandatory)
  - [Secure SSH (Mandatory)](#secure-ssh-mandatory)
  - [Secure the X Window System (Mandatory)](#secure-the-x-window-system-mandatory)
- [System Security](#system-security)
  - [Install Updates on a Regular Basis (Mandatory)](#install-updates-on-a-regular-basis-mandatory)
  - [Check for Unused Services (Mandatory)](#check-for-unused-services-mandatory)
  - [Disable Default Services Accounts (Mandatory)](#disable-default-services-accounts-mandatory)
  - [Secure the Storage of Sensitive Data (Mandatory)](#secure-the-storage-of-sensitive-data-mandatory)
  - [Secure the Configuration of Cron (Mandatory)](#secure-the-configuration-of-cron-mandatory)
  - [Check for Global Writeable Paths in the PATH Environment Variable (Mandatory)](#check-for-global-writeable-paths-in-the-path-environment-variable-mandatory)
  - [Restrict mount (Mandatory)](#restrict-mount-mandatory)
  - [Use Specific Filesystem Types (Mandatory)](#use-specific-filesystem-types-mandatory)
  - [Configure Session Timeout (Optional)](#configure-session-timeout-optional)
  - [Remove Unnecessary SUID/GUID Files (Mandatory)](#remove-unnecessary-suidguid-files-mandatory)
  - [Disable Core Dumps (Mandatory)](#disable-core-dumps-mandatory)
  - [Enforce Strict Permissions To the /root Path (Mandatory)](#enforce-strict-permissions-to-the-root-path-mandatory)
  - [Enforce Strict Permissions To the /home Path (Mandatory)](#enforce-strict-permissions-to-the-home-path-mandatory)
  - [Properly Place Home Directories (Optional)](#properly-place-home-directories-optgroupoptgrouptional)
  - [Ensure Mail Distribution to Active Mail Accounts (Mandatory)](#ensure-mail-distribution-to-active-mail-accounts-mandatory)
  - [Remove Unnecessary Software Packages (Mandatory)](#remove-unnecessary-software-packages-mandatory)
  - [Regularly Check for World Readable Directories and Files (Mandatory)](#regularly-check-for-world-readable-directories-and-files-mandatory)
  - [Regularly Check for World Writeable Directories and Files (Mandatory)](#regularly-check-for-world-writeable-directories-and-files-mandatory)
  - [Set umask Globally (Mandatory)](#set-umask-globally-mandatory)
  - [Secure Log Files (Mandatory)](#secure-log-files-mandatory)
  - [Review Log Files Regularly (Mandatory)](#review-log-files-regularly-mandatory)
- [Network Security](#network-security)
  - [Disable NFS (Optional)](#disable-nfs-optional)
  - [Disable SMB (Optional)](#disable-smb-optional)
  - [Disable Default Shares and Permissions (Mandatory)](#disable-default-shares-and-permissions-mandatory)
  - [Restrict Management Access](#restrict-management-access)
  - [Enable Packet Filtering (Optional)](#enable-packet-filtering-optional)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Introduction
In this document, ERNW presents a list of relevant system settings for hardening Linux systems. This document is non-exhaustive, however, it provides a solid base of security hardening measures. We do not discuss system settings that might have a severe impact on functionalities of the operating system and require further testing.
We mark each presented setting as “mandatory” (a setting that **must** be applied) or as “optional” (a setting that **should** be applied). In addition, we mark as “optional” settings that we highly recommend to be applied, however, with the risk that system functionalities become unavailable once the settings are applied.

# Authentication

## Configure the Number of Administrative Accounts (Mandatory)
The file **/etc/passwd** should be reviewed and if necessary, edited, such that only the user **root** is part of the group **root**. The following command can be used to verify this (i.e., that there is only one user with **UID** equal to **0**):  
> awk -F: '($3 == "0") {print}' /etc/passwd

This command should return only the root user.

---

## Check That All Passwords are Shadowed (Mandatory)
The following command can be used to verify that all system passwords are shadowed:
> awk -F: '($2 != "x") {print}' /etc/passwd

This command should return **NO**.

---

## Use Strong Hashing Algorithm (Mandatory)
Ensure that Linux Pluggable Authentication Modules (**PAM**) uses a strong hashing mechanism (e.g., SHA512). This can be configured by setting the value of the ENCRYPT_METHOD parameter in the file **/etc/login.defs**, which we present below:
```
# Note: It is recommended to use a value consistent with
# the PAM modules configuration.
#
ENCRYPT_METHOD SHA512
```
In the snippet above, the value of the ENCRYPT_METHOD parameter is set to SHA512. Note that if the value of this parameter is changed, users should change their password in order for the effect to take place.

Depending on the Linux distribution, more options may be available.

---

## Implement A Secure Password Policy (Mandatory)
Make use of the **PAM** modules **pam_cracklib**, **pam_pwhistory**, and **pam_unix2**. The following password policy is an example (TODO: Where is this located?):
```
min length = 10
lower case = 1
upper case =1
number = 1
passwords to remember (password history) = 5
```
To enforce this policy, add the following lines to the file **/etc/pam.d/common-password**:
```
password  required    pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 minlen=8 retry=5
password  required    pam_pwhistory.so use_authtok remember=3 retry=5
password  required    pam_pwcheck.so remember=5
password  required    pam_unix2.so use_authtok
```

---

## Configure Account Lockout Policies (Mandatory)
The file **/etc/pam.d/common-auth** is used for configuring account lockout policies. We present below example lockout policies, that is, example entries in the **common-auth** file:
```
auth required pam_tally.so onerr=fail no_magic_root unlock_time=180
account required pam_tally.so per_user deny=5 no_magic_root reset
```
The first entry configures the system to count failed logins, or failed **su** attempts, on a user basis and sets the account lock timer to 30 minutes. The second entry configures the system to lock accounts after 5 failed logins, or failed **su** attempts (see the "deny" parameter).

---

## Enable Password Aging (Mandatory)
Apply the following settings:
- In the file **/etc/login.defs**, set the value of the parameter **PASS_MAX_DAYS** (maximum number of password validity) to 180, **PASS_MIN_DAYS** (minimum days a password cannot be changed by the user) to 1, and **PASS_WARN_AGE** (when to start the password reminder) to 30.
- In the file **/etc/default/useradd**, set the value of the parameter **INACTIVE** (when to disable an account after password is expired) to 30 (value missing?), and **EXPIRE** (the date the user account expires) to 90.

---

## Disable rlogin, rsh and rcp (Mandatory)
Check if the **rsh-server** package is installed, if so, remove it.

---

## Disable telnet (Mandatory)
Check if the **telnet-server** package is installed. If installed, this package must be removed.

---

## Secure SSH (Mandatory)
Edit the file **/etc/ssh/sshd_config** as shown below:
```
# Disable root login.
PermitRootLogin no
# Let SSH listen on the management VLAN interface only.
ListenAddress MGMT_VLAN_IP
# Enable privilege separation. This will only let a small part of the
# daemon run with root privileges.
UsePrivilegeSeparation yes
# Only use the more secure SSHv2 protocol.
Protocol 2
# No TCP forwarding and no X11 forwarding.
AllowTcpForwarding no
X11Forwarding no
# Check permissions of configuration files related to SSH on login.
# If this fails, the user won’t be able to login.
StrictModes yes
# Disable host-based authentications.
IgnoreRhosts yes
HostbasedAuthentication no
RhostsRSAAuthentication no
# Ensure that the following line is commented out to disable sftp.
#Subsystem sftp /usr/lib/misc/sftp-server
# Set log level to be verbose.
LogLevel INFO
# Ensure usage of PAM
UsePAM yes
```

---

## Secure the X Window System (Mandatory)
Remove the **X Window System** if it is not needed. If it is needed, disable host-based and cookie-based use of the system. If the **X Window System** must be accessible from remote locations, use **SSH** for session tunneling, as shown below:
> ssh -X remotehost

---

# System Security

## Install Updates on a Regular Basis (Mandatory)
Check for and apply patches with the system package manager or central software distribution tools.

---

## Check for Unused Services (Mandatory)
Evaluate the running services and potentially disable unneeded services or uninstall unecessary services

---

## Disable Default Services Accounts (Mandatory)
* To lock system accounts, run the following command:
> passwd <username> -l

* To replace the shell of a user, run the following command:
> chsh -s /bin/false <username>

This has to be done for all default service accounts.

## Secure the Storage of Sensitive Data (Mandatory)
Sensitive data that is not in active use (e.g. copies of configuration files) must not be stored on the system. If sensitive data must be stored for operational reasons, store this data in encrypted form. This can for example be done in the following ways (where of course the password should be stored in a central password vault):

* Use **zip** and set a password to encrypt the zip file:
> zip --encrypt --recurse-paths target.zip folder_to_encrypt

* Create an archive file and encrypt its contents with **openssl**. This can be done with the following command:
> tar cz folder_to_encrypt | openssl enc -aes-256-cbc -e > out.tar.gz.enc

Decryption can be done as follows:
> cat out.tar.gz.enc  | openssl enc -aes-256-cbc -d

* Create an archive file and encrypt it with **PGP** as follows:
> gpg --encrypt out.tar.gz

* After the data has been encrypted, delete its unencrypted version.

---

## Secure the Configuration of Cron (Mandatory)
To allow access to the configuration of Cron only to the **root** user, run the following commands:
> rm -f /etc/cron.deny /etc/at.deny

> echo root > /etc/cron.allow

> echo root > /etc/at.allow

All cron entries must also be reviewed for referenced scripts. Any script executed by cron must only be writeable by **root**.

---

## Check for Global Writeable Paths in the PATH Environment Variable (Mandatory)
Search the files **/etc/bashrc** and **/etc/profile** for the definition of the PATH variable. Delete the following entries if found:
* “.”
* “..”
* Any directory that is writeable for an unprivileged user or even "other"

---

## Restrict mount (Mandatory)
* For each device configured in the file **/etc/fstab**, make sure that the **user** attribute is not specified.
* For each removable device configured in the file **/etc/fstab**, specify the attributes **nosuid** and **nodev**.

---

## Use Specific Filesystem Types (Mandatory)
Use only filesystem types that allow for access control, such as **Ext2**, **Ext3**, or **ReiserFS**. Do not use **FAT32**, since it does not feature access control.

---

## Configure Session Timeout (Optional)
How a session timeout is configured depends on the used shell. The examples below are valid for the **bash** and **csh** shells:

* When using the **bash** shell, add the following lines to the file **/etc/bashrc**:
```
TMOUT=900
readonly TMOUT
export TMOUT
```

* When using the **csh** shell, add the following line to the file **/etc/csh.cshrc**:
```
set autologout=15
```

---

##	Remove Unnecessary SUID/GUID Files (Mandatory)
* To find all **SUID** and **GUID** files on the system, run the following command:
> find / -perm /u=s,g=s

* Search these files for the SUID bit. If such a bit is found, and the file does not need it, remove it with the following command:
> chmod -s /path/to/file

---

## Disable Core Dumps (Mandatory)
Insert the following lines in the file **/etc/security/limits.conf**:
```
soft core 0
hard core 0
```

---

## Enforce Strict Permissions To the /root Path (Mandatory)
Issue the following command:
> chmod -R 700 /root

---

## Enforce Strict Permissions To the /home Path (Mandatory)
Issue the following commands:
> chmod -R 700 /home

> chmod a+x /home

---

## Properly Place Home Directories (Optional)
User home directories should not be located on **NFS** shares. To the contrary, they should be placed on a local system disk.

---

## Ensure Mail Distribution to Active Mail Accounts (Mandatory)
Edit the file **/etc/aliases** to set a forward rule for **root**.

---

## Remove Unnecessary Software Packages (Mandatory)
* Get a list of installed software packages from the system package manager and review it for unecessary packages.

---

## Regularly Check for World Readable Directories and Files (Mandatory)
Run the following commands:
> find / -perm -0004 -type d -print

> find / -perm -0004 -type f -print

---

## Regularly Check for World Writeable Directories and Files (Mandatory)
Run the following commands:
> find / -perm -0002 -type d -print

> find / -perm -0002 -type f -print

---

## Set umask Globally (Mandatory)
Edit the files **/etc/login.defs** and **/etc/profile** to set **umask** to **077**.

---

## Secure Log Files (Mandatory)
* Run the following commands to set strict permissions to system log files:
> cd /var/log

> /bin/chmod o-w boot.log* httpd/* mail* messages* news/* samba/*

> /bin/chmod o-w wtmp

> /bin/chmod o-rx boot.log* mail* messages*

> /bin/chmod g-w boot.log* httpd/* mail* messages* samba/*

> /bin/chmod g-rx boot.log* mail* messages*

> /bin/chmod o-w httpd/ news/ samba/

> /bin/chmod o-rx httpd/ samba/

* Add the following lines to the file **/etc/syslog.conf**  (use tab as whitespace delimiter):
```
*.warn;*.err		/var/log/syslog
kern.*		/var/log/kernel
```

---

## Review Log Files Regularly (Mandatory)
* To find information on all kinds of problems, review the file **/var/log/messages**.
* For information on failed login attempts, successful login attempts, and reboots, review the file **/var/log/wtmp.1** as shown below:
> last -f wtmp.1

* For detailed login information, review the file **/var/log/auth.log** and issue the command:
> lastlog

---

# Network Security

## Disable NFS (Optional)
If **NFS** is not needed, disable the corresponding service


---

## Disable SMB (Optional)
If **SMB** is not needed, disable the corresponding service

---

## Disable Default Shares and Permissions (Mandatory)
Ensure that no default shares are enabled (e.g. **root** export for **NFS** or **administrative shares** for **SMB**). In addition, make sure that all shares have minimal permissions, set on a need-to-know basis. To list the enabled SMB shares on a system, issue the following commands:
> smbclient -L <hostname>

> showmount -a

---

## Restrict Management Access
Access to administrative network services (such as SSH or Puppet Clients) must be restricted to specific source IP addresses. This can be implemented by using a local firewall or a network security gateway.

---

## Enable Packet Filtering (Optional)
Configure packet filterung using a firewall of choice. Potentially beneficial (from a security perspective) use cases may be:
* Restriction of administrative interfaces (refer also to [Restrict Management Access](#restrict-management-access))

---
