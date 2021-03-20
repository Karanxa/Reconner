subdomain(){
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "Processing Subdomains Enumeration and Favicon hashes"
assetfinder --subs-only $1 | httprobe | tee -a /Users/karanarora/bbht/Subdomains/$1.txt | python3 /Users/karanarora/bbht/tools/FavFreak/favfreak.py -o output --shodan
}

dir(){
sudo ython3 /Users/karanarora/bbht/tools/dirsearch/dirsearch.py -u $1 -e all -w $2 -t 100 | tee -a $3
}

dirlist(){
sudo python3 /Users/karanarora/bbht/tools/dirsearch/dirsearch.py -L $1 -e all -w $2 -t 100 | tee -a $3
}

subcheck(){
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "Subdomain Takeover Check"
echo -e "-------------------------------"
echo -e "SubJack"
subjack -w /Users/karanarora/bbht/Subdomains/$1.txt -t 100 -o /Users/karanarora/bbht/results/subtoc/$1_TOC.txt -ssl -c /Users/karanarora/go/src/github.com/haccer/subjack/fingerprints.json -v
echo -e "SubOver"

}


bbht(){
mkdir /Users/karanarora/bbht/programs/$1
mkdir /Users/karanarora/bbht/programs/$1/subdomains
mkdir /Users/karanarora/bbht/programs/$1/wayback
mkdir /Users/karanarora/bbht/programs/$1/screenshots
mkdir /Users/karanarora/bbht/programs/$1/github
mkdir /Users/karanarora/bbht/programs/$1/wordlists
mkdir /Users/karanarora/bbht/programs/$1/endpoints
mkdir /Users/karanarora/bbht/programs/$1/poc
mkdir /Users/karanarora/bbht/programs/$1/notes
mkdir /Users/karanarora/bbht/programs/$1/imp
}


sub-tko(){
echo -e "Provide the subdomain file"
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "Subdomain Takeover Check"
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "SubOver"
cp /Users/karanarora/providers.json /Users/karanarora/bbht/programs/$2/subdomains/
SubOver -l /Users/karanarora/bbht/programs/$2/subdomains/$1.txt | tee -a /Users/karanarora/bbht/programs/$2/subdomains/subover_$1.txt
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "Tko-Subs"
tko-subs -domains="/Users/karanarora/bbht/programs/$2/subdomains/$1.txt" -data="/Users/karanarora/bbht/tools/tko-subs/providers-data.csv" -output="/Users/karanarora/bbht/programs/$2/sub-tko_output.csv"
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "Subzy"
subzy -targets /Users/karanarora/bbht/programs/$2/subdomains/$1.txt | tee -a /Users/karanarora/bbht/programs/$2/subdomains/subzy_$1.txt
echo -e "SubJack"
subjack -w /Users/karanarora/bbht/programs/$2/subdomains/$1.txt -t 100 -o /Users/karanarora/bbht/programs/$2/subjack_$1.txt -ssl -c /Users/karanarora/go/src/github.com/haccer/subjack/fingerprints.json -v
}

gitdorks(){
python3 /Users/karanarora/bbht/tools/GitDorker/GitDorker.py -tf /Users/karanarora/bbht/tools/GitDorker/token -q $1 -d /Users/karanarora/bbht/tools/GitDorker/Dorks/alldorksv2 -o $2
}

sub(){

amass enum --passive -d $1 -o /Users/karanarora/bbht/programs/$2/subdomains/domains_$1
assetfinder --subs-only $1 | tee -a /Users/karanarora/bbht/programs/$2/subdomains/domains_$1

subfinder -d $1 -o /Users/karanarora/bbht/programs/$2/subdomains/domains_subfinder_$1
cat domains_subfinder_$1 | tee -a /Users/karanarora/bbht/programs/$2/subdomains/domains_$1

sort -u /Users/karanarora/bbht/programs/$2/subdomains/domains_$1 -o /Users/karanarora/bbht/programs/$2/subdomains/domains_$1
cat /Users/karanarora/bbht/programs/$2/subdomains/domains_$1 | filter-resolved | tee -a /Users/karanarora/bbht/programs/$2/subdomains/domains_$1.txt

}


openredirect(){
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "Open Redirect Check"
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
}

corscanner(){
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "COR Misconfiguration Check"
python /Users/karanarora/bbht/tools/CORScanner/cors_scan.py -i /Users/karanarora/bbht/Subdomains/$1.txt -t 200 -o /Users/karanarora/bbht/results/corscan/$1_COR.txt
}



cloudfail(){
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "Cloudflare By Pass Check"
cd /Users/karanarora/bbht/tools/CloudFail/ 
python3 /Users/karanarora/bbht/tools/CloudFail/cloudfail.py -t $1
cd
}

wayback(){
echo "$1" | waybackurls > /Users/karanarora/bbht/programs/$2/wayback/urls.txt
}

wordlist(){
gau $1 | unfurl -u keys | tee -a  /Users/karanarora/bbht/programs/$2/wordlists/wordlist_$1.txt ; gau $1 | unfurl -u paths|tee -a  /Users/karanarora/bbht/programs/$2/wordlists/ends_$1.txt; sed 's#/#\n#g'  /Users/karanarora/bbht/programs/$2/wordlists/ends_$1.txt  | sort -u | tee -a  /Users/karanarora/bbht/programs/$2/wordlists/wordlist_$1.txt | sort -u ;rm  /Users/karanarora/bbht/programs/$2/wordlists/ends_$1.txt  | sed -i -e 's/\.css\|\.png\|\.jpeg\|\.jpg\|\.svg\|\.gif\|\.wolf\|\.bmp//g'  /Users/karanarora/bbht/programs/$2/wordlists/wordlist_$1.txt
}

open-redirect(){
nuclei -l /Users/karanarora/bbht/programs/$1/wayback/urls.txt -t /Users/karanarora/bbht/tools/nuclei-templates/vulnerabilities/open-redirect.yaml
}


scripthunter(){
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "Script hunting"
cd /Users/karanarora/bbht/tools/scripthunter
./scripthunter.sh $1 | tee -a /Users/karanarora/bbht/results/scripts/$1_Scripts.txt
cd
}

smuggler(){
echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
echo -e "HTTP Request Smuggling Check"
cat /Users/karanarora/bbht/Subdomains/$1.txt | python3 /Users/karanarora/bbht/tools/smuggler/smuggler.py | tee -a /Users/karanarora/bbht/results/smuggler/$1_smuggler.txt
}


s-endpoints(){
cat $1 | httpx -path '/server-status?full=true' -status-code -content-length | tee -a apacheStatus.txt
grep 200 apacheStatus.txt >> apacheStatus_200.txt

cat $1 | httpx -ports 80,443,8009,8080,8081,8090,8180,8443 -path '/web-console/' -status-code -content-length | tee -a jbossConsole.txt
grep 200 jbossConsole.txt >> jbossConsole_200.txt

cat $1 | httpx -path '/phpinfo.php' -status-code -content-length -title | tee -a phpInfo.txt 
grep 200 phpInfo.txt >> phpInfo_200.txt

}

recon(){
subdomain $1
subcheck $1
cloudfail $1
openredirect $1
corscanner $1
smuggler $1
scripthunter $1
arjun $1
}

xss(){
gospider -S $1 -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe -o xss_result.txt
}

heartbleed(){
cat $1 | while read line ; do echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep 'server extension "heartbeat" (id=15)' || echo $line: safe; done
}

js-files(){
assetfinder $1| gau|egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)'|while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Zo-9_]+" |sed -e 's, 'var','"$url"?',g' -e 's/ //g'|grep -v '.js'|sed 's/.*/&=xss/g'):echo -e "\e[1;33m$url\n" "\e[1;32m$vars";done | tee -a js_files.txt
}

mscan(){ #runs masscan
sudo masscan -p 4443,2075,2076,6443,3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,744 $1
}

ipinfo(){
curl http://ipinfo.io/$1
}

crawler(){
hakrawler -urls $1 -depth 3 | tee -a crawl_urls.txt
}
