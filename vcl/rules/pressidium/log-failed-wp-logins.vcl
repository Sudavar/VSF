##
# Checks if the request is POSTing to urls containing
# - wp-login.php
# - xmlrpc.php
# - user-login
##
sub vcl_backend_response {

    # Logs details when someone requests wp-login.php or xmlrpc.php
    if ( beresp.http.X-Login-Failed == "1" ) {
        std.syslog(169, "security.vcl alert pressidum-rid:" + bereq.http.Pressidium-RID + " " + bereq.proto
            + " [prsdm-failedlogin-log-1]"
            + " [" + bereq.http.Pressidium-Connecting-IP + "]"
            + " (" + bereq.http.Pressidium-Proxied + ")"
            + " [" + bereq.http.X-Forwarded-For + "] "
            + bereq.method + " " + bereq.http.host + bereq.url
            + " (" + bereq.http.user-agent + ")"
            + " (Pressidium Log sensitive requests) ");
    }
}
