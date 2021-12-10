# win10harderning
Manual Tasks 

Groups and users

Run script to find any unauthorized files 

UAC settings to max https://articulate.com/support/article/how-to-turn-user-account-control-on-or-off-in-windows-10

Remote desktop group (found in readme)

Start > Settings > Control Panel > Network and Internet > Network and Sharing Center > Change adapter settings
'Internet Protocol version 4 (TCP IPv4), click Properties, click Advanced,
'DNS' tab, uncheck mark 'register this connections address in DNS'
'WINS' tab, select 'Disable NETBIOS over TCP/IP'

shares
Open the Start menu, and type in cmd b. Do not hit enter. Right click, and choose Run as Administrator c. Now, if User account control menu pops up, click yes d. Type in net share e. This lists all the active shares from your computer, we are going to kill these
now f. Type net share /delete INSERT NAME OF NET SHARE HERE 


