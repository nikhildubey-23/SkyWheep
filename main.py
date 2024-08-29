import sql_injection as sqli
import ssrf_attack as ssrf
import test_borken_auth as auth
import test_csp_bypass as csp
import xss_attack as xss
import test_missconfiguration as misconfig
import test_idor as idor
import test_csrf as csrf
import test_path_traversal as pt


target_url = input("Enter the target url : ")

sqli.test_sql_injection(target_url, sqli.sql_payloads) 
# still in working process 