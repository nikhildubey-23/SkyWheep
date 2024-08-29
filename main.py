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

print(" 1. For Server Side Attack")
print(" 2. For Client Side Attack")

attack_selection = input("Enter the attack number you want to perform : ")

if attack_selection == "1":
    print("you have selected Server Side Attack")
    
elif attack_selection == "2":
    print("you have selected Client Side Attack")
    