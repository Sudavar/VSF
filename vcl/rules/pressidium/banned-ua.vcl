/**
 * Banned User-Agent strings
 */
sub sec_useragent_sev2 {
    set req.http.X-SEC-Severity = "1";
    call sec_handler;
    return ( synth(429) );
}

sub vcl_recv {
    set req.http.X-VSF-Module =  "prsdm-useragent";

    if ( req.http.user-agent ~ "Powered by Spider-Pig" ) {
        set req.http.X-VSF-RuleName = "Pressidium Banned User-Agent";
        set req.http.X-VSF-RuleID = "ban-1";
        set req.http.X-VSF-RuleInfo = "Checks if User-Agent is in banned list";
        call sec_useragent_sev2;
    }
}
