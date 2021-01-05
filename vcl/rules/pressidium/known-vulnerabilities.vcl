/**
 * verified Pressidium attacks, block the user and let the abuse IP management do the rest
 * For now
 */
sub sec_pressidium_sev1 {
    set req.http.X-VSF-Severity = "1";
    call sec_handler;
    return ( synth(429) );
}
//log and intercept
sub sec_known_vulnerability {
    set req.http.X-VSF-Severity = "1";
    call sec_handler;
}

/* CGI like Proxy vulnerability
 * https://httpoxy.org/
 */
sub vcl_recv {

    if( req.http.proxy ) {
        call sec_known_vulnerability;
        unset req.http.proxy;
    }

}
/**
 * WordPress Genericons Icon Font Package example.html DOM-Based XSS
 * http://osvdb.org/show/osvdb/121727
 * OSVDBID=121727
 */
sub vcl_recv {
    set req.http.X-VSF-Module =  "prsdm-vulnerability";

    # Checks if someone tries to access /wp-content/themes/twentyfifteen/genericons/example.html
    if ( req.url ~ "/wp-content/themes/twentyfifteen/genericons/example.html" ) {
        set req.http.X-VSF-RuleName = "WordPress Genericons Icon Font Package example.html DOM-Based XSS";
        set req.http.X-VSF-RuleId   = "prsdm-vuln-1";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to access genericons example.html";
        call sec_pressidium_sev1;
    }

}

/**
 * Known REVSLIDER WP plugin vulnerabilities
 */
sub vcl_recv {
    set req.http.X-VSF-Module =  "prsdm-vulnerability";

    if ( req.url ~ "wp-admin/admin-ajax.php\?action=revslider_show_image\&img=../wp-config.php" ) {
        set req.http.X-VSF-RuleName = "RevSlider WP Plugin wpvulndbid=7540";
        set req.http.X-VSF-RuleId   = "revslider-1";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to exploit wpvulndbID=7540 of revslider.php vulnerability";
        call sec_pressidium_sev1;
    }

    if ( req.url ~ "temp/update_extract/(showbiz|revslider)/(.*).php" ) {
        set req.http.X-VSF-RuleName = "RevSlider WP Plugin wpvulndbid=7540";
        set req.http.X-VSF-RuleId   = "revslider-2";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to exploit wpvulndbID=7540 of revslider.php vulnerability";
        call sec_pressidium_sev1;
    }
}
