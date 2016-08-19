# Table of Content

[1 Introduction ](#introduction)

[2 Hardening Measures ](#hardening-measures)

[2.1 Patch Management to ensure up-to-date security ](#patch-management-to-ensure-up-to-date-security-mandatory)

[2.2 Use strong passwords for user authentication ](#use-strong-passwords-for-user-authentication-mandatory)

[2.3 Use two-factor authentication for increased security ](#use-two-factor-authentication-for-increased-security-mandatory)

[2.4 Lock down file permissions as much as possible ](#lock-down-file-permissions-as-much-as-possible-mandatory)

[2.5 Restrict database user privileges ](#restrict-database-user-privileges-mandatory)

[2.6 Plugin Management Lifecycle ](#plugin-management-lifecycle-mandatory)

[2.7 Limit admin access by IP ](#limit-admin-access-by-ip-mandatory)

[2.8 Hardening the PHP settings ](#hardening-the-php-settings-mandatory)

[2.9 Change the Wordpress database prefix ](#change-the-wordpress-database-prefix-mandatory)

[2.10 Delete the default admin account ](#delete-the-default-admin-account-mandatory)

[2.11 Disable user registration ](#disable-user-registration-optional)

[2.12 Delete readme.html and install.php files ](#delete-readme.html-and-install.php-files-optional)

[2.13 Move the wp-config.php file above the Wordpress root folder ](#move-the-wp-config.php-file-above-the-wordpress-root-folder-mandatory)

[2.14 Disable the plugin and theme editor ](#disable-the-plugin-and-theme-editor-optional)

# Introduction
ERNW has compiled the most relevant settings for the Wordpress version 4.4.2 into this checklist.
While there is a significant amount of controls that can be applied, this document is supposed to provide a solid baseof hardening measures.
Settings which might have severe impact on the functionality of the webserver system and need a lot of further testing are not part of this checklist.

We have marked each recommended setting in this checklist either with “mandatory” or “optional” to make a clear statement, which setting is a MUST (mandatory) or a SHOULD (optional) from our point of view. “Optional” also means that we recommend to apply this setting, but there may be required functionality on the system that will become unavailable once the setting is applied.

# Hardening Measures

## Patch Management to ensure up-to-date security (Mandatory)
Patch management is a crucial part of running a Wordpress service.
Older versions of Wordpress are not maintained with security updates.
Therefore, immediate starting of the patch lifecycle is recommended after every patch release to ensure the security of the service.   Mandatory

## Use strong passwords for user authentication (Mandatory)
The strength of passwords of user accounts must ensure that an attacker cannot guess these with minor efforts.
Passwords for user accounts should therefore comply with the following policies:

* Avoid the following things when choosing a password
    * A short password
    * A word from a dictionary in any language
    * Any numeric-only or alphanumeric-only password
    * Any permutation of your real name, your user name, the company name, or the name of your Wordpress website
* Use a mixture of numeric, alphanumeric, and special characters
* When it comes to passwords it still counts that longer is better – therefore, use a minimum length of 20 for passwords

## Use two-factor authentication for increased security (Mandatory)
Strong passwords are the first step to tighten the security posture of credentials.
To raise security to the next level it is recommended to install a two-factor authentication plugin.
Two-factor authentication requires besides the username and password credentials another authentication factor, e.g. a PIN code send to or generated on a designated mobile.   Mandatory
A recommended two-factor authentication plugin is the Clef Two-Factor Authentication.

## Lock down file permissions as much as possible (Mandatory)
Wordpress requires that some files are writable by the webserver.
However, it is adviced to lock down these permission as much as possible.
Only loosen these resctrictions on occasions where you need to allow write access and disable the access afterwards again.   Mandatory
In general all files should be owned by the user account.
In cases where the webserver needs write access to files these files should be group-owned by the user account and the webserver.
A recommended permission scheme would be:

- /
  the root Wordpress directory: all files should be writable only by the user account
- /wp-admin/
  the Wordpress administration area: all files should be writable only by the user account
- /wp-includes/
  the Wordpress application logic: all file should be writable only by the user account
- /wp-content/
  user-supplied content: all files should be writable by the user account and the webserver
- /wp-admin/includes/file.php
  the file should be owned be the websever and do not be writeable be the webserver

## Restrict database user privileges (Mandatory)
In general a Wordpress system only requires SELECT, INSERT, UPDATE, and DELETE statements when accessing the underlying database.
Therefore, administrative privileges like DROP, ALTER and GRANT should be revoked from the database user.
Log in on the MySQL instance and execute the following command while replacing databasename and user with the respective values of the Wordpress environment:

    REVOKE DROP, REFERENCES, CREATE ROUTINE, ALTER ROUTINE, CREATE VIEW, SHOW VIEW, EVENT, TRIGGER, EXECUTE ON databasename.* FROM user;

## Plugin Management Lifecycle (Mandatory)
While introducing new functionality plugins can also introduce additional vulnerabilities to the Wordpress installation.
It is therefore necessary to implement a thorough plugin manangement lifecycle, which covers evaluation, integration, patching, and deletion of the plugin within the active Wordpress installation.

- Evaluation: it is recommended to download and use plugins only from reputable sources. Always perform a source code audit to ensure security of the to-be used plugin before integrating it into the actual Wordpress installation.
- Integration: integrate the plugin only into the productive environment after successful testing. Ensure that the configuration of the plugin is properly hardened.
- Patching: Plugins are a vital part of a Wordpress installation with possibly broad privileges. It is therefore necessary to ensure, that plugins are updated as soon as possible if a security relevant update is released. Have a close look at [CVE list for Wordpress](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=wordpress) to be informed about current vulnerabilities within the Wordpress ecosystem.
- Deletion: if a plugin is not needed anymore, it is adviced to delete all plugin-related files from the Wordpress installation. Otherwise attackers might be able to misuse the still available files.

## Limit admin access by IP (Mandatory)
Another layer of protection is added by limiting the administrative access by IP address in the .htaccess file.

1. Create a .htaccess file in the /wp-admin/ folder
2. Insert the following lines including your static internal IP address into the .htaccess file:

    order deny,allow
    deny from all
    allow from xx.xx.xx.xx // ( your static internal IP)

## Hardening the PHP settings (Mandatory)
The php.ini file configurates how the php environment might behave under certain circumstances.
The following options are safe to be disabled in a production environment without breaking further functionality while improving the security posture of the Wordpress installation:   Mandatory

- display\_errors = Off
- expose\_php = Off
- log\_errors = On
- error\_log = /var/log/phperror.log
- disable\_functions=popen,exec,system,passthru,proc\_open,shell\_exec,show\_source,php

## Change the Wordpress database prefix (Mandatory)
Wordpress initializes the database scheme with its default naming scheme using the prefix wp\_ for all tables.
As attackers are aware of this default prefix they prepare their SQL injection attempts to comply with this scheme.
Changing the prefix makes it harder for an attacker to identify the database naming scheme.   Mandatory
To change the prefix perform the following steps:

1. Perform a database backup directly through the database client instead of the Wordpress admin
2. Open a copy of the backup file and find and replace all instances of of wp\_ with the new prefix
3. De-active all plugins in the Wordpress installation
4. Turn on maintenance mode
5. Drop the current database and import the edited backup file
6. Change the database settings in the wp-config.php to the new prefix
7. Re-activate all plugins
8. Refresh the permalink structure by clicking on save

## Delete the default admin account (Mandatory)
Wordpress comes with a default administrative account admin having the user id 1. Attackers leverage this knowledge to bruteforce the login credentials of this administrative account.
It is therefore recommended to create another administrative user via the Wordpress administrative interface.
Afterwards log in with the new administrative account and delete the default administrative account.   Mandatory

## Disable user registration (Optional)
If not needed disable the user registration.
To do this log in as an administrator, go to Settings → General and make sure that “Anyone can register” is unchecked.   Recommended

## Delete readme.html and install.php files (Optional)
Both the readme.html and install.php files are relicts from the Wordpress installation process not needed to reside on a productive system.
It is therefore recommended to delete both files.   Recommended

## Move the wp-config.php file above the Wordpress root folder (Mandatory)
As the wp-config.php contains sensitive information about the configuration of the Wordpress installation it is recommended to move this file to a non-public html folder.   Mandatory
Wordpress looks up this file in the Wordpress root folder. If the system cannot find the wp-config.php it looks in the directory above the Wordpress root.
Moving the wp-config.php to a non-public folder means it will not be accessable from the Internet.

## Disable the plugin and theme editor (Optional)
If not required it is recommended to disable the plugin and the theme editor.
This prevents users and attackers having access to a privileged user account from editing sensitive files.   Recommended
Open the wp-config.php and add the following line:

    define('DISALLOW_FILE_EDIT', true);
