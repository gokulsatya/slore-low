# slore-low

🚀 SOAR-Flow
📌 Project Description
This project demonstrates how to integrate Shuffle SOAR with Wazuh SIEM and TheHive to automate incident response.

✅ Receiving security alerts from Wazuh.
✅ Enriching alerts using external threat intelligence (VirusTotal, AbuseIPDB).
✅ Creating an incident in TheHive for case management.
✅ Sending notifications to a Discord channel.
✅ (Bonus) Auto-mitigating threats (e.g., blocking malicious IPs).

By implementing this SOAR workflow, you can automate security operations, reduce response time, and improve efficiency in a SOC environment.

🔧 Tools Used
Tool	Description
Wazuh SIEM	Security Information & Event Management (SIEM) solution for threat detection.
TheHive	Open-source Security Incident Response Platform (SIRP).
Shuffle	Open-source Security Orchestration, Automation, and Response (SOAR) platform.
VirusTotal API	Used for malware and URL reputation checks.
AbuseIPDB API	Used for checking if an IP address is malicious.
Discord Webhook	Sends alerts to a Discord channel for real-time monitoring.
🛠️ Installation & Setup
VM-1 for Wazuh and TheHive
Specifications

RAM: 12GB+
HDD: 60GB+
OS: Ubuntu 24.04 LTS
1️⃣ Install Wazuh SIEM
Follow the official Wazuh installation guide:
🔗 Wazuh Installation Guide

Update and Upgrade:

apt-get update && apt-get upgrade
Install Wazuh 4.10:

curl -sO https://packages.wazuh.com/4.10/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
Extract Wazuh Credentials:

sudo tar -xvf wazuh-install-files.tar
Wazuh Dashboard Credentials:

User: admin
Password: ***************
Access Wazuh Dashboard:

Open your browser and go to: https://<Public IP of Wazuh>
Wazuh

2️⃣ Install TheHive
Follow the official documentation for installing TheHive:
🔗 TheHive Installation Guide

Install Dependencies:

apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release
Install Java:

wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
Install Cassandra:

wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
Install ElasticSearch:

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
Install TheHive:

wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
Default Credentials for TheHive:

Port: 9000
Credentials: 'admin@thehive.local' with a password of 'secret'
TheHive

VM-2 for Shuffle
Specifications

RAM: 4GB+
HDD: 40GB+
OS: Ubuntu 24.04 LTS
3️⃣ Install Shuffle SOAR
Run the following commands to install Shuffle SOAR on Ubuntu:
🔗 Shuffle Installation Guide

# Install Docker if not already installed
sudo apt update && sudo apt install -y docker.io docker-compose

# Enable and start Docker
sudo systemctl enable docker
sudo systemctl start docker

# Clone the Shuffle repository
git clone https://github.com/Shuffle/Shuffle.git
cd Shuffle

# Build and run Shuffle with Docker Compose
sudo docker-compose up -d
Access Shuffle Web UI at http://YOUR-IP:3001

Shuffle

4️⃣ Create a Discord Webhook
Go to your Discord Server → Settings → Integrations → Webhooks
Click New Webhook → Name it SOC Alerts
Copy the Webhook URL (you will need it later)
Configuration for TheHive
Configure Cassandra
Edit Cassandra Config File:

nano /etc/cassandra/cassandra.yaml
Change Cluster Name:

cluster_name: 'SOAR-Flow'
Update Listen Address:

listen_address: <public IP of TheHive>
Update RPC Address:

rpc_address: <public IP of TheHive>
Update Seed Provider:

- seeds: "<Public IP Of the TheHive>:7000"
Stop Cassandra Service:

systemctl stop cassandra.service
Remove Old Files:

rm -rf /var/lib/cassandra/*
Restart Cassandra Service:

systemctl start cassandra.service
Configure ElasticSearch
Edit ElasticSearch Config File:

nano /etc/elasticsearch/elasticsearch.yml
Update Cluster Name and Host:

cluster.name: thehive
node.name: node-1
network.host: <Public IP of your TheHive instance>
http.port: 9200
discovery.seed_hosts: ["127.0.0.1"]
cluster.initial_master_nodes: ["node-1"]
Start ElasticSearch Service:

systemctl start elasticsearch
systemctl enable elasticsearch
systemctl status elasticsearch
Configure TheHive
Ensure Proper Ownership:

ls -la /opt/thp
chown -R thehive:thehive /opt/thp
Edit TheHive Configuration File:

nano /etc/thehive/application.conf
Update Database and Index Configuration:

db.janusgraph {
  storage {
    backend = cql
    hostname = ["<Public IP of TheHive>"]
    cql {
      cluster-name = SOAR-Flow
      keyspace = thehive
    }
  }
}

index.search {
  backend = elasticsearch
  hostname = ["<Public IP of TheHive>"]
  index-name = thehive
}

application.baseUrl = "http://<Public IP of TheHive>:9000"
Start TheHive Services:

systemctl start thehive
systemctl enable thehive
systemctl status thehive
🔄 Workflow - Automating Incident Response
📌 Workflow Overview
This workflow automates incident response using Shuffle:
1️⃣ Receive alerts from Wazuh SIEM when suspicious activity is detected.
2️⃣ Enrich the alert using VirusTotal & AbuseIPDB API.
3️⃣ Create an incident in TheHive for case tracking.
4️⃣ Send a notification to Discord with alert details.
5️⃣ (Optional) Perform auto-mitigation (e.g., blocking malicious IPs).

📌 Shuffle Workflow Steps
🔹 Step 1: Add Wazuh Alert as Trigger

In Shuffle, create a new workflow and add a Webhook trigger.
Configure Wazuh to send alerts via webhooks.
🔹 Step 2: Enrich Data with VirusTotal & AbuseIPDB

Add an HTTP Request node to check IPs/Hashes using VirusTotal API.
Add another HTTP Request to query AbuseIPDB for malicious IPs.
🔹 Step 3: Create an Incident in TheHive

Use TheHive API to create a new case with alert details.
🔹 Step 4: Send Alert to Discord

Use the Discord Webhook to send a formatted message to a SOC channel.
🔹 Step 5: (Optional) Auto-Mitigation

If the IP is high risk, trigger a firewall rule to block the attacker.
🚀 Running the Workflow
Step 1: Configure Wazuh to Send Alerts to Shuffle
Edit the Wazuh ossec.conf file to send webhook alerts:

<integration>
  <name>custom-webhook</name>
  <hook_url>http://<shuffle-ip>:5001/webhook</hook_url>
  <event_format>json</event_format>
</integration>
Restart Wazuh to apply changes:

sudo systemctl restart wazuh-manager
Step 2: Configure TheHive API Key
Generate an API key in TheHive and add it to Shuffle’s HTTP Request node.

Step 3: Configure Discord Webhook in Shuffle
Use the Discord Webhook URL in the Shuffle HTTP Request node.
Example payload:

{
  "content": "**🚨 New Security Alert 🚨**\n\nIP: 192.168.1.100\nSeverity: High\nSource: Wazuh SIEM"
}
Step 4: Test the Workflow
Trigger an alert in Wazuh (e.g., failed SSH logins).
Verify the incident is created in TheHive.
Check if the alert is sent to Discord.
📌 Example Output
✅ TheHive Incident Created:

[INFO] New Incident Created in TheHive:
- Title: Suspicious SSH Login Attempts
- Severity: High
- Source: Wazuh SIEM
✅ Discord Alert:
Discord Alert Example

🎯 Future Enhancements
🔹 Add auto-mitigation (e.g., blocking attacker IPs via firewall rules).
🔹 Integrate more threat intelligence feeds (e.g., MISP, Shodan API).
🔹 Expand automation to handle different types of incidents.

📜 License
This project is licensed under the MIT License.

