# ERNW Repository of Hardening Guides

This repository contains various hardening guides compiled by ERNW for various purposes. Most of those guides strive to provide a baseline level of hardening and may lack certain hardening options which could increase the security posture even more (but may have impact on operations or required operational effort).

The hardening guides are structured into various categories, represented by folders. Every hardening guide must be used in combination with hardening guides of the parent folders. Let's use the following fictional structure as an example:
* web_application
 * ERNW_Hardening_Web_Application.md
 * wordpress
    * ERNW_Hardening_Wordpress.md
    *  4.4.2
      * ERNW_Hardening_Wordpress_4.4.2.md

In this structure, all three files 'ERNW_Hardening_Web_Application.md', 'ERNW_Hardening_Wordpress.md', and 'ERNW_Hardening_Wordpress_4.4.2.md' need to be taken into account for comprehensive hardening. If there are conflicting options, the most specific option (in this case, from 'ERNW_Hardening_Wordpress_4.4.2.md') must be used.

## Contact us!

Feel free to contact us for questions, additions, spotted mistakes, or -- you name it.

## Other Hardening Sources

The following incomplete list contains several other high quality hardening resources:
* http://dev-sec.io/
* https://benchmarks.cisecurity.org/downloads/benchmarks/
* https://www.owasp.org/index.php/Secure_Configuration_Guide
* https://bettercrypto.org/static/applied-crypto-hardening.pdf
* https://www.team-cymru.org/templates.html
