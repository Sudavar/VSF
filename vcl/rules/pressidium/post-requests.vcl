##
# Checks if the request is POSTing to urls containing
# - wp-login.php
# - xmlrpc.php
# - user-login
##
sub vcl_recv {

    # Logs details when someone requests wp-login.php or xmlrpc.php
    if ( req.url ~ "^/xmlrpc\.php" && req.method == "POST" ) {
        std.syslog(169, "security.vcl alert pressidum-rid:" + req.http.Pressidium-RID + " " + req.proto
            + " [custom-pressidium-1]"
            + " [" + req.http.Pressidium-Connecting-IP + "]"
            + " (" + req.http.Pressidium-Proxied + ")"
            + " [" + req.http.X-Forwarded-For + "] "
            + req.method + " " + req.http.host + req.url
            + " (" + req.http.user-agent + ")"
            + " (Pressidium Log sensitive requests) ");
    }
}
