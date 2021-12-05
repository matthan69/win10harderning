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


Disable-NetAdapterBinding -Name "Ethernet0" -DisplayName "client*" , "file*" , "QoS*" , "Microsoft Network*" , "Microsoft LLPD*", "Link* Mapper" , "Link* Responder" , "Internet prorocol version 6"
