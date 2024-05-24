#!/bin/bash

# Log in to Azure (this will open a browser for authentication)
az login

# Set the desired subscription
az account set --subscription "Dev_Azure_10000_CloudSandbox1"

# Directory to store the outputs
mkdir -p azure_scan_results
cd azure_scan_results

# Install necessary extensions
extensions=(
    "azure-firewall"
    "virtual-wan"
    "bastion"
    "ip-group"
    "virtual-network-manager"
    "front-door"
)

for ext in "${extensions[@]}"; do
    az extension add --name $ext
done

# Fetching resource groups
resource_groups=$(az group list --query "[].name" -o tsv)

# Fetching VM names
vm_names=$(az vm list --query "[].name" -o tsv)

# Fetching Web App names
webapp_names=$(az webapp list --query "[].name" -o tsv)

# Fetching location for Network Watcher
location=$(az network watcher list --query "[0].location" -o tsv)

# Commands to execute
commands=(
    "az network public-ip list --query \"[].{Name:name, IPAddress:ipAddress, DNSSettings:dnsSettings}\" --output json"
    "az network nsg list --query \"[].{Name:name, SecurityRules:securityRules, DefaultSecurityRules:defaultSecurityRules}\" --output json"
    "az network vnet list --query \"[].{Name:name, AddressSpace:addressSpace, Subnets:subnets, DNSSettings:dnsSettings}\" --output json"
    "az network private-endpoint list --query \"[].{Name:name, NetworkInterfaces:networkInterfaces, PrivateLinkServiceConnections:privateLinkServiceConnections}\" --output json"
    "az network nat gateway list --query \"[].{Name:name, PublicIPAddresses:publicIpAddresses, Subnets:subnets}\" --output json"
    "az network lb list --query \"[].{Name:name, FrontendIPConfigurations:frontendIpConfigurations, BackendPools:backendAddressPools, LoadBalancingRules:loadBalancingRules}\" --output json"
    "az network application-gateway list --query \"[].{Name:name, FrontendIPConfigurations:frontendIpConfigurations, BackendPools:backendAddressPools, HTTPSettings:httpSettingsCollection}\" --output json"
    "az network route-table list --query \"[].{Name:name, Routes:routes, Subnets:subnets}\" --output json"
    "az network application-gateway waf-policy list --query \"[].{Name:name, PolicySettings:policySettings, Rules:customRules}\" --output json"
    "az network firewall policy list --query \"[].{Name:name, Rules:ruleCollectionGroups, Settings:threatIntelMode}\" --output json"
    "az network firewall list --query \"[].{Name:name, IPConfigurations:ipConfigurations, Rules:rules}\" --output json"
    "az network vhub list --query \"[].{Name:name, AddressPrefixes:addressPrefixes, RouteTables:routeTables}\" --output json"
    "az network asg list --query \"[].{Name:name, SecurityRules:securityRules}\" --output json"
    "az network bastion list --query \"[].{Name:name, IPConfigurations:ipConfigurations}\" --output json"
    "az network ddos-protection list --query \"[].{Name:name, ProtectionPlanSettings:protectionPlanSettings}\" --output json"
    "az network private-link-service connection list --query \"[].{Name:name, ConnectionStatus:connectionStatus, PrivateLinkServiceID:privateLinkServiceId}\" --output json"
    "az network dns outbound-endpoint list --query \"[].{Name:name, IPConfigurations:ipConfigurations}\" --output json"
    "az network dns forwarding-rule-set list --query \"[].{Name:name, Rules:forwardingRules}\" --output json"
    "az network vwan list --query \"[].{Name:name, Properties:properties, Hubs:hubs}\" --output json"
    "az network service-endpoint policy list --query \"[].{Name:name, Definitions:serviceEndpointPolicyDefinitions}\" --output json"
    "az network private-link-service list --query \"[].{Name:name, Properties:properties, IPConfigurations:ipConfigurations}\" --output json"
    "az network express-route gateway list --query \"[].{Name:name, Properties:properties, Connections:connections}\" --output json"
    "az network express-route circuit list --query \"[].{Name:name, Properties:properties, Peerings:peerings}\" --output json"
    "az network vpn-site list --query \"[].{Name:name, Properties:properties, IPConfigurations:ipConfigurations}\" --output json"
    "az network public-ip prefix list --query \"[].{Name:name, Properties:properties, IPRanges:ipPrefixes}\" --output json"
    "az network ip-group list --query \"[].{Name:name, Properties:properties, IPAddresses:ipAddresses}\" --output json"
    "az acr list --query \"[].{Name:name, Properties:properties, NetworkRules:networkRules}\" --output json"
    "az aks list --query \"[].{Name:name, Properties:properties, NodePools:nodePools}\" --output json"
    "az cosmosdb list --query \"[].{Name:name, Properties:properties, ConnectionStrings:connectionStrings}\" --output json"
    "az webapp list --query \"[].{Name:name, Properties:properties, Configurations:configurations}\" --output json"
    "az keyvault list --query \"[].{Name:name, Properties:properties, AccessPolicies:accessPolicies}\" --output json"
)

# Function to execute a command and handle its output
execute_command() {
    local cmd="$1"
    local output_file="$(echo $cmd | grep -o -P '(?<=az ).*?(?= list)').json"
    echo "Executing: $cmd"
    eval $cmd > "$output_file" 2> "${output_file%.json}.log"
    if [ $? -ne 0 ]; then
        echo "Error executing $cmd, see ${output_file%.json}.log for details."
    else
        echo "Output successfully saved to $output_file"
    fi
}

# Execute general commands in parallel
for cmd in "${commands[@]}"; do
    execute_command "$cmd" &
done

# Wait for all background processes to finish
wait

# Resource group dependent commands
resource_group_commands=(
    "az network vnet-gateway list --resource-group"
    "az network vpn-connection list --resource-group"
    "az network local-gateway list --resource-group"
    "az network manager list --resource-group"
    "az cdn waf policy list --resource-group"
    "az network front-door waf-policy list --resource-group"
    "az search service list --resource-group"
    "az webapp deployment slot list --resource-group"
    "az vm extension list --resource-group"
)

# Execute resource group dependent commands in parallel
for rg in $resource_groups; do
    for cmd in "${resource_group_commands[@]}"; do
        execute_command "$cmd $rg" &
    done
done

# Wait for all background processes to finish
wait

# Location dependent command
network_watcher_cmd="az network watcher connection-monitor list --location $location --query \"[].{Name:name, Properties:properties, Endpoints:endpoints}\" --output json"
execute_command "$network_watcher_cmd" &

# Wait for the location dependent command to finish
wait

echo "All commands executed. Check the azure_scan_results directory for output files."
