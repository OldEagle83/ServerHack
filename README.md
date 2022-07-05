# ServerHack

A brute force/dict attack program that can be very powerful with a little tinkering.
Currently it tries to find the login using a library of known login names, and then brute force the password,
or use a library of known passwords.

For education purposes only.


Exacmple log
2022-07-05 22:01:58,061 [INFO] Connected to ('192.168.1.5', 9093)
2022-07-05 22:01:58,061 [INFO] Trying login names from \files\logins.txt for ('192.168.1.5', 9093)
2022-07-05 22:01:59,186 [INFO] Found login for ('192.168.1.5', 9093): root
2022-07-05 22:01:59,187 [INFO] Trying a brute force on ('192.168.1.5', 9093) with login root
2022-07-05 22:02:00,324 [INFO] Most probable password starts with X
2022-07-05 22:02:01,465 [INFO] Most probable password starts with XP
2022-07-05 22:02:02,588 [INFO] Most probable password starts with XPp
2022-07-05 22:02:03,721 [INFO] Most probable password starts with XPp7
2022-07-05 22:02:04,838 [INFO] Most probable password starts with XPp7w
2022-07-05 22:02:05,976 [INFO] Most probable password starts with XPp7wW
{"login": "root", "password": "XPp7wWd"}

2022-07-05 22:02:05,978 [INFO] Connection success!
2022-07-05 22:02:05,978 [INFO] Found password XPp7wWd
2022-07-05 22:02:05,979 [INFO] Closed the connection to ('192.168.1.5', 9093)
