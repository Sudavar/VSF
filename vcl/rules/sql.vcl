
# For now
sub sec_sql_sev1 {
    set req.http.X-VSF-Severity = "1";
    set req.http.X-VSF-Module = "sql";
    call sec_handler;
}

sub vcl_recv {

    # Pressidium: added check for non word character after the keywords in all the following rules

    # Checks if someone tries to use SQL statement in URL: SELECT FROM
    #if (req.url ~ "(?i).+SELECT.+FROM") {
    if (req.url ~ "(?i).+SELECT[^a-zA-Z0-9_-].+FROM[^a-zA-Z0-9_-]") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: SELECT FROM";
        set req.http.X-VSF-RuleID = "1";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: SELECT FROM";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: UNION SELECT
    if (req.url ~ "(?i).+UNION\s+SELECT[^a-zA-Z0-9_-]") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: UNION SELECT";
        set req.http.X-VSF-RuleID = "2";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: UNION SELECT";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: UPDATE SET
    if (req.url ~ "(?i).+UPDATE[^a-zA-Z0-9_-].+SET[^a-zA-Z0-9_-]") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: UPDATE SET";
        set req.http.X-VSF-RuleID = "3";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: UPDATE SET";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: INSERT INTO
    if (req.url ~ "(?i).+INSERT[^a-zA-Z0-9_-].+INTO[^a-zA-Z0-9_-]") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: INSERT INTO";
        set req.http.X-VSF-RuleID = "4";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: INSERT INTO";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: DELETE FROM
    if (req.url ~ "(?i).+DELETE[^a-zA-Z0-9_-].+[^_|&]FROM[^a-zA-Z0-9_-]") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: DELETE FROM";
        set req.http.X-VSF-RuleID = "5";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: DELETE FROM";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: ASCII SELECT
    if (req.url ~ "(?i).+ASCII\(.+SELECT[^a-zA-Z0-9_-]") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: ASCII SELECT";
        set req.http.X-VSF-RuleID = "6";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: ASCII SELECT";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: DROP TABLE
    if (req.url ~ "(?i).+DROP[^a-zA-Z0-9_-].+TABLE[^a-zA-Z0-9_-]") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: DROP TABLE";
        set req.http.X-VSF-RuleID = "7";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: DROP TABLE";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: DROP DATABASE
    if (req.url ~ "(?i).+DROP[^a-zA-Z0-9_-].+DATABASE[^a-zA-Z0-9_-]") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: DROP DATABASE";
        set req.http.X-VSF-RuleID = "8";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: DROP DATABASE";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: SELECT VERSION
    #if (req.url ~ "(?i).+SELECT[^a-zA-Z0-9_-].+VERSION") {
    if (req.url ~ "(?i).+SELECT[^a-zA-Z0-9_-].+VERSION[^a-zA-Z0-9_-]") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: SELECT VERSION";
        set req.http.X-VSF-RuleID = "9";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: SELECT VERSION";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: SHOW CURDATE/CURTIME
    if (req.url ~ "(?i).+SHOW[^a-zA-Z0-9_-].+CUR(DATE|TIME)") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: SHOW CURDATE/CURTIME";
        set req.http.X-VSF-RuleID = "10";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: SHOW CURDATE/CURTIME";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: SELECT SUBSTR
    if (req.url ~ "(?i).+SELECT[^a-zA-Z0-9_-].+SUBSTR[^a-zA-Z0-9_-]") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: SELECT SUBSTR";
        set req.http.X-VSF-RuleID = "11";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: SELECT SUBSTR";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: SELECT INSTR
    if (req.url ~ "(?i).+SELECT[^a-zA-Z0-9_-].+INSTR[^a-zA-Z0-9_-]") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: SELECT INSTR";
        set req.http.X-VSF-RuleID = "12";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: SELECT INSTR";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: SHOW CHARACTER SET
    if (req.url ~ "(?i).+SHOW[^a-zA-Z0-9_-].+CHARACTER[^a-zA-Z0-9_-].+SET[^a-zA-Z0-9_-]") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: SHOW CHARACTER SET";
        set req.http.X-VSF-RuleID = "13";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: SHOW CHARACTER SET";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: BULK INSERT
    if (req.url ~ "(?i).+BULK[^a-zA-Z0-9_-].+INSERT[^a-zA-Z0-9_-]") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: BULK INSERT";
        set req.http.X-VSF-RuleID = "14";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: BULK INSERT";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: INSERT VALUES
    if (req.url ~ "(?i).+INSERT[^a-zA-Z0-9_-].+VALUES[^a-zA-Z0-9_-]") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: INSERT VALUES";
        set req.http.X-VSF-RuleID = "15";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: INSERT VALUES";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: MySQL Comments /* */
    if (req.url ~ "(?i).+\%2F\%2A.+\%2A\%2F") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: Comments";
        set req.http.X-VSF-RuleID = "16";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: Comments";
        call sec_sql_sev1;
    }

    # Checks if someone tries to use SQL statement in URL: SELEC CONCAT
    if (req.url ~ "(?i).+SELECT[^a-zA-Z0-9_-].+CONCAT[^a-zA-Z0-9_-]") {
        set req.http.X-VSF-RuleName = "SQL Injection Attempt: SELECT CONCAT";
        set req.http.X-VSF-RuleID = "17";
        set req.http.X-VSF-RuleInfo = "Checks if someone tries to use SQL statement in URL: SELECT CONCAT";
        call sec_sql_sev1;
    }
}
