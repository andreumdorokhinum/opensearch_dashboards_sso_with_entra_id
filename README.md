# Opensearch Dashboards: Single Sign On using Azure Entra ID

This manual has been tested with OpenSearch/OpenSearch Dashboards ver. 2.15 on Ubuntu 24.04

## On-prem part
### Install OpenSearch
    sudo apt -y install curl lsb-release gnupg2 ca-certificates
    sudo curl -fsSL https://artifacts.opensearch.org/publickeys/opensearch.pgp| sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/opensearch.gpg
    echo "deb https://artifacts.opensearch.org/releases/bundle/opensearch/2.x/apt stable main" | sudo tee /etc/apt/sources.list.d/opensearch-2.x.list
    sudo apt update -y
    sudo env OPENSEARCH_INITIAL_ADMIN_PASSWORD=__YOUR_VERY_SECURE_PASSWORD_HERE__ apt-get install opensearch=2.15.0
    sudo apt-mark hold opensearch

### Edit configuration
    sudo vim /etc/opensearch/opensearch.yml
        cluster.name: os
        node.name: node-1
        network.host: 0.0.0.0
        http.port: 9200
        cluster.initial_cluster_manager_nodes: ["node-1"]

### Restart the service after editing configuration
    sudo systemctl daemon-reload
    sudo systemctl restart opensearch
    systemctl status opensearch

### Verify installation
    curl -X GET https://localhost:9200 --insecure -u "admin:__YOUR_VERY_SECURE_PASSWORD_HERE__"

### Install OpenSearch Dashboards
    echo "deb https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/2.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/opensearch-2.x.list
    sudo apt update -y
    sudo apt install opensearch-dashboards=2.15.0
    sudo apt-mark hold opensearch-dashboards

### Edit Configuration
    sudo vim /etc/opensearch-dashboards/opensearch_dashboards.yml
        server.host: "0.0.0.0"
        server.ssl.enabled: false
        opensearch.hosts: ["http://localhost:9200"]

### Restart the service after editing configuration
    sudo systemctl restart opensearch-dashboards
    systemctl status opensearch-dashboards

### Verify installation
    wget -qO- --no-check-certificate https://localhost:5601

### Add firewall rules
    sudo ufw enable
    sudo ufw allow 5601
    sudo ufw allow 443
    sudo ufw reload
    sudo ufw status

### Add a certificate from Let's Encrypt
    sudo apt install certbot
    sudo certbot certonly --standalone -d "${YOUR_FQDN}"
    sudo mkdir /etc/opensearch-dashboards/cert_le/
    sudo cp /etc/letsencrypt/live/"${YOUR_FQDN}"/fullchain.pem /etc/opensearch-dashboards/cert_le/
    sudo cp /etc/letsencrypt/live/"${YOUR_FQDN}"/privkey.pem   /etc/opensearch-dashboards/cert_le/

### Edit Configuration
    sudo vim /etc/opensearch-dashboards/opensearch_dashboards.yml
        server.host: '0.0.0.0'
        server.ssl.enabled: true
        server.ssl.certificate: /etc/opensearch-dashboards/cert_le/fullchain.pem
        server.ssl.key: /etc/opensearch-dashboards/cert_le/privkey.pem
        opensearch.hosts: ["https://localhost:9200"]
        opensearch.ssl.verificationMode: none
        opensearch.username: "kibanaserver"
        opensearch.password: "kibanaserver"
        opensearch.requestHeadersAllowlist: [authorization, securitytenant]
        opensearch_security.multitenancy.enabled: true
        opensearch_security.multitenancy.tenants.preferred: ["Private", "Global"]
        opensearch_security.readonly_mode.roles: ["kibana_read_only"]
        opensearch_security.cookie.secure: true
        opensearch_security.auth.multiple_auth_enabled: true
        opensearch_security.auth.type: ["basicauth", "saml"]
        opensearch_security.saml.extra_storage.cookie_prefix: security_authentication_saml
        opensearch_security.saml.extra_storage.additional_cookies: 3
        server.xsrf.allowlist: ["/_opendistro/_security/saml/acs/idpinitiated", "/_opendistro/_security/saml/acs", "/_opendistro/_security/saml/logout"]

### Restart the service after editing configuration
    sudo systemctl restart opensearch-dashboards

## Entra ID Part
### Create an Entra ID Enterprise App
    Entra ID > Enterprise Applications > New Application > Create your own application >
    Give it a name: opensearch_saml >
    Integrate any other application you don't find in the gallery (Non-gallery) > Create
    Select the Enterprise Application > Set up single sign on > SAML

### Basic SAML Configuration
    Identifier (Entity ID): opensearch_saml
    Reply URL (Assertion Consumer Service URL): https://your.fqdn.com:5601/_opendistro/_security/saml/acs
    Sign on URL: https://your.fqdn.com:5601/_opendistro/_security/saml/acs/idpinitiated
    Relay State (Optional): Empty
    Logout Url (Optional): Empty

### Attributes & Claims
    Additional claims:
    Claim name: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname
    Type: SAML
    Value: user.surname

### SAML Certificates
    Download Federation Metadata XML

### Set up opensearch_saml
    Login URL: https://login.microsoftonline.com/llllllll-llll-llll-llll-llllllllllll/saml2
    Microsoft Entra Identifier: https://sts.windows.net/ssssssss-ssss-ssss-ssss-ssssssssssss/

## On-Prem Part Again
> I'm using free Azure services, so Groups are not available for assignment due to my Active Directory plan level.
> In this manual, I will map my surname to a role in OpenSearch Dashboards.
> In your case, most likely your would need to map AD groups to specific roles with different sets of permissions if your AD plan allows it

## Copy Federation Metadata XML
    sudo cp ~/opensearch_saml /usr/share/opensearch/plugins/opensearch-security/

### Edit Security Config
    sudo vim /etc/opensearch/opensearch-security/config.yml
        authc:
          basic_internal_auth_domain:
            description: "Authenticate via HTTP Basic against internal users database"
            http_enabled: true
            transport_enabled: true
            order: 0
            http_authenticator:
              type: basic
              challenge: false
            authentication_backend:
              type: intern
          saml_auth_domain:
            http_enabled: true
            transport_enabled: false
            order: 1
            http_authenticator:
              type: saml
              challenge: true
              config:
                idp:
                  metadata_file: /usr/share/opensearch/plugins/opensearch-security/opensearch_saml.xml
                  entity_id: https://sts.windows.net/ssssssss-ssss-ssss-ssss-ssssssssssss/
                sp:
                  entity_id: opensearch_saml
                kibana_url: https://your.fqdn.com:5601
                exchange_key: '1837bc2c546d46c705204cf9f857b90b1dbffd2a7988451670119945ba39a10b' # generated by: openssl rand -hex 32
                roles_key: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname
            authentication_backend:
              type: noop

### Refresh Security Settings
    sudo /etc/opensearch/securityadmin_demo.sh

### OpenSearch Dashboards
    Create role your_surname
    Add permissions: cluster_all
    Create user: saml_user with __ANOTHER_VERY_SECURE_PASSWORD__
    Map saml_user to the backend role your_surname

### Validate the setup
    firefox https://your.fqdn.com:5601
    or, alternatively:
    Entra ID > Enterprise Applications > opensearch_saml > Set up single sign on > Test single sign-on with opensearch_saml

## Troubleshooting
### Check permissions 
on all Linux files that must be accessible by OpenSearch and OpenSearch Dashboards
### Check validity of YAML files
    sudo apt install yamllint
    sudo yamllint /etc/opensearch-dashboards/opensearch_dashboards.yml | grep -v long
    sudo yamllint /etc/opensearch/opensearch.yml | grep -v long
    sudo yamllint /etc/opensearch/opensearch-security/config.yml | grep -v long
### Different ways to generate an exchange_key
    openssl rand -hex 32
    printf "${WHATEVER_TEXT}" | openssl dgst -sha256
### Enable verbose logging
    sudo vim /etc/opensearch-dashboards/opensearch_dashboards.yml
        logging.verbose: true
        opensearch.logQueries: true
### Enable debug logging for SAML authentication
    sudo vim /etc/opensearch/log4j2.properties
        logger.token.name = com.amazon.dlic.auth.http.saml.Token
        logger.token.level = debug
### Import certificates to sign XML
    sudo keytool -importcert -file opensearch.cer -keystore /etc/ssl/certs/java/cacerts -alias opensearch -storepass changeit # the default password is actually "changeit"
### Make sure that
        entity_id is
    'https://sts.windows.net/ssssssss-ssss-ssss-ssss-ssssssssssss'
        instead of
    'https://sts.windows.net/ssssssss-ssss-ssss-ssss-ssssssssssss/'
### If there are issues with accessing Metadata XML file, use metadata_url instead of metadata_file
      metadata_url: https://login.microsoftonline.com/llllllll-llll-llll-llll-llllllllllll/federationmetadata/2007-06/federationmetadata.xml?appid=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
