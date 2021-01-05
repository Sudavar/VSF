/* Security.vcl config VCL file
 * In this file you specify which security/rulesets to configure.
 *
 */

# Comment out any include line to disable the security module.
# Protocol
include "security/rules/protocol.vcl";
# Paths/Files extensions
include "security/rules/paths.vcl";
# Generic attacks
include "security/rules/generic.vcl";
# SQL Injection
include "security/rules/sql.vcl";
include "security/rules/sql.encoded.vcl";
# XSS (Reflected / Stored if post)
include "security/rules/xss.vcl";
include "security/rules/xss.encoded.vcl";

include "security/rules/demo.vcl";
include "security/rules/php.vcl";
include "security/rules/cmd.vcl";
include "security/rules/restricted-file-extensions.vcl";
include "security/rules/content-encoding.vcl";
include "security/rules/content-type.vcl";
include "security/rules/localfiles.vcl";

# Pressidium custom rules
include "security/rules/pressidium/log-failed-wp-logins.vcl";
include "security/rules/pressidium/known-vulnerabilities.vcl";
include "security/rules/pressidium/bash-injection.vcl";
include "security/rules/pressidium/banned-ua.vcl";
include "security/rules/pressidium/post-requests.vcl";
# removed the .com from restricted file extesions

# you may or may not want the following security/rulesets:

# DoS connection throttling
#include "security/rules/dos.vcl";

# check this module, it is rather harsh
#include "security/rules/request.vcl";

# robot countermeasures (edit robot handler to respond to robots)
#include "security/rules/robots.vcl";

# cloak the web server and the clients
#include "security/rules/cloak.vcl";

## User agent checks may be a little too restrictive for your tastes.
#include "security/rules/user-agent.vcl";

## The breach2vcl tool is not perfect...
# include "security/breach.vcl";
