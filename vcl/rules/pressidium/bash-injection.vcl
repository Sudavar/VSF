#verified BASH injection attack, block the user and let the abuse IP management do the rest
# For now
sub sec_bash_sev1 {
    set req.http.X-VSF-Severity = "1";
    call sec_handler;
    return ( synth(429) );
}
##
# Main regex string:
#               :?\(\) {\s?:\s?;\s?}\s?;
#       alt:    :?\(\s*\)\s*{\s*:\s*;\s*}\s*;
#       alt:    :?\(\s*\)\s*{\s*(:|\S*)\s*;\s*}\s*;
#
#
sub vcl_recv {
    set req.http.X-VSF-Module =  "prsdm-vulnerability";

    # Checks if someone tries to inject enviroment variable in bash (CVE-2014-6271,CVE-2014-7169)
    #if ( req.url ~ "^\(\) {" ) {
    #        set req.http.X-VSF-RuleName = "Bash Env. variable injection Attempt";
    #        set req.http.X-VSF-RuleId   = "bash-1";
    #        set req.http.X-VSF-RuleInfo = "Checks if someone tries to inject code in bash environment variable";
    #        call sec_bash_sev1;
    #}
    #newer version
    if ( req.url ~ ":?\(\s*\)\s*{\s*(:|\S*)\s*;\s*}\s*;" ) {
        set req.http.X-VSF-RuleName = "Bash Env. variable injection Attempt";
        set req.http.X-VSF-RuleId   = "bash-2";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to inject code in bash environment variable";
        call sec_bash_sev1;
    }
    if ( req.http.host ~ ":?\(\s*\)\s*{\s*(:|\S*)\s*;\s*}\s*;" ) {
        set req.http.X-VSF-RuleName = "Bash Env. variable injection Attempt";
        set req.http.X-VSF-RuleId   = "bash-3";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to inject code in bash environment variable";
        call sec_bash_sev1;
    }
    if ( req.http.User-Agent ~ ":?\(\s*\)\s*{\s*(:|\S*)\s*;\s*}\s*;" ) {
        set req.http.X-VSF-RuleName = "Bash Env. variable injection Attempt";
        set req.http.X-VSF-RuleId   = "bash-4";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to inject code in bash environment variable using User Agent string";
        call sec_bash_sev1;
    }
    if ( req.http.Cookie ~ ":?\(\s*\)\s*{\s*(:|\S*)\s*;\s*}\s*;" ) {
        set req.http.X-VSF-RuleName = "Bash Env. variable injection Attempt";
        set req.http.X-VSF-RuleId   = "bash-5";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to inject code in bash environment variable using User Agent string";
        call sec_bash_sev1;
    }
    if ( req.http.referer ~ ":?\(\s*\)\s*{\s*(:|\S*)\s*;\s*}\s*;" ) {
        set req.http.X-VSF-RuleName = "Bash Env. variable injection Attempt";
        set req.http.X-VSF-RuleId   = "bash-6";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to inject code in bash environment variable using User Agent string";
        call sec_bash_sev1;
    }
}
