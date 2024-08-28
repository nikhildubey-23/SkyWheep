import sql_injection as sqli

target_url = input("Enter the target url : ")

sqli.test_sql_injection(target_url, sqli.sql_payloads) 
# still in working process 