subdomain(){
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "Processing Subdomains Enumeration and Favicon hashes"
assetfinder --subs-only $1 | httprobe | tee -a file_path/$1.txt | python3 file_path/FavFreak/favfreak.py -o output --shodan
}

dir(){
sudo python3 file_path/dirsearch/dirsearch.py -u $1 -e all -w $2 -t 100 | tee -a $3
}

dirlist(){
sudo python3 file_path/dirsearch/dirsearch.py -L $1 -e all -w $2 -t 100 | tee -a $3
}

subcheck(){
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "Subdomain Takeover Check"
echo -e "-------------------------------"
echo -e "SubJack"
subjack -w file_path/$1.txt -t 100 -o file_path/$1_TOC.txt -ssl -c file_path/go/src/github.com/haccer/subjack/fingerprints.json -v
echo -e "SubOver"

}


sub-tko(){
echo -e "Provide the subdomain file"
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "Subdomain Takeover Check"
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "SubOver"
cp file_path/providers.json file_path/$2/subdomains/
SubOver -l file_path/$2/subdomains/$1.txt | tee -a file_path/$2/subdomains/subover_$1.txt
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "Tko-Subs"
tko-subs -domains="file_path/$2/subdomains/$1.txt" -data="file_path/tko-subs/providers-data.csv" -output="file_path/$2/sub-tko_output.csv"
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "Subzy"
subzy -targets file_path/$2/subdomains/$1.txt | tee -a file_path/$2/subdomains/subzy_$1.txt
echo -e "SubJack"
subjack -w file_path/$2/subdomains/$1.txt -t 100 -o file_path/$2/subjack_$1.txt -ssl -c file_path/subjack/fingerprints.json -v
}

gitdorks(){
python3 file_path/GitDorker/GitDorker.py -tf file_path/GitDorker/token -q $1 -d file_path/Dorks/alldorksv2 -o $2
}

sub(){

amass enum --passive -d $1 -o file_path/$2/subdomains/domains_$1
assetfinder --subs-only $1 | tee -a file_path/$2/subdomains/domains_$1

subfinder -d $1 -o file_path/$2/subdomains/domains_subfinder_$1
cat domains_subfinder_$1 | tee -a file_path/$2/subdomains/domains_$1

sort -u file_path/$2/subdomains/domains_$1 -o file_path/$2/subdomains/domains_$1
cat file_path/$2/subdomains/domains_$1 | filter-resolved | tee -a file_path/$2/subdomains/domains_$1.txt

}


corscanner(){
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "COR Misconfiguration Check"
python file_path/cors_scan.py -i file_path/$1.txt -t 200 -o file_path/$1_COR.txt
}



cloudfail(){
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "Cloudflare By Pass Check"
cd file_path/ 
python3 file_path/CloudFail/cloudfail.py -t $1
cd
}

wayback(){
echo "$1" | waybackurls > /file_path/$2/wayback/urls.txt
}

wordlist(){
gau $1 | unfurl -u keys | tee -a  file_path/$2/wordlists/wordlist_$1.txt ; gau $1 | unfurl -u paths|tee -a  file_path/$2/wordlists/ends_$1.txt; sed 's#/#\n#g'  /Users/karanarora/bbht/programs/$2/wordlists/ends_$1.txt  | sort -u | tee -a  /Users/karanarora/bbht/programs/$2/wordlists/wordlist_$1.txt | sort -u ;rm  /Users/karanarora/bbht/programs/$2/wordlists/ends_$1.txt  | sed -i -e 's/\.css\|\.png\|\.jpeg\|\.jpg\|\.svg\|\.gif\|\.wolf\|\.bmp//g'  /Users/karanarora/bbht/programs/$2/wordlists/wordlist_$1.txt
}

open-redirect(){
nuclei -l file_path/$1/wayback/urls.txt -t file_path/vulnerabilities/open-redirect.yaml
}


scripthunter(){
echo -e "-------------------------------------------------------Script Hunter----------------------------------------------------------------------------------"
echo -e "Script hunting"
cd file_path/scripthunter
./scripthunter.sh $1 | tee -a file_path/results/scripts/$1_Scripts.txt
cd
}

smuggler(){
echo -e "---------------------------------------------------------Smuggler----------------------------------------------------------------------------------"
echo -e "HTTP Request Smuggling Check"
cat file_path/$1.txt | python3 file_path/smuggler/smuggler.py | tee -a file_path/smuggler/$1_smuggler.txt
}


s-endpoints(){
cat $1 | httpx -path '/server-status?full=true' -status-code -content-length | tee -a apacheStatus.txt
grep 200 apacheStatus.txt >> apacheStatus_200.txt

cat $1 | httpx -ports 80,443,8009,8080,8081,8090,8180,8443 -path '/web-console/' -status-code -content-length | tee -a jbossConsole.txt
grep 200 jbossConsole.txt >> jbossConsole_200.txt

cat $1 | httpx -path '/phpinfo.php' -status-code -content-length -title | tee -a phpInfo.txt 
grep 200 phpInfo.txt >> phpInfo_200.txt

}

reconner(){
subdomain $1
subcheck $1
cloudfail $1
corscanner $1
smuggler $1
scripthunter $1
arjun $1
}


