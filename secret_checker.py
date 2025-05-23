from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.core.exceptions import HttpResponseError
from datetime import datetime, timezone
import requests
import logging
import sys


credential = DefaultAzureCredential(
    exclude_environment_credential=False,
    exclude_managed_identity_credential=False,
    exclude_workload_identity_credential=False
)


logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("secret-checker")


SUBSCRIPTION_ID = "6e3955f4-2bc1-4b2a-8f53-068aaf959011"
TEAMS_WEBHOOK_URL = "https://fhtw.webhook.office.com/webhookb2/30e2eb09-562e-4c61-9fb8-111d86f903dc@084fcc17-2a37-4c44-968f-5b2d634b2b6f/IncomingWebhook/edb573f2f66c4229b603517f6a4ec2ed/55775e09-900b-46cf-8c46-92e617c54576/V2BVlEOCZ1hcr7tAa0wFdXB103MvMjyH9dTuZPxl0oVQo1"




def resolve_app_id_from_sp(sp_object_id, credential):
    """Resolve App ID from Service Principal Object ID."""
    token = credential.get_token("https://graph.microsoft.com/.default").token
    url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_object_id}"
    headers = {"Authorization": f"Bearer {token}"}
    
    response = requests.get(url, headers=headers)

    if response.status_code == 404:
        logger.warning(f"Service Principal {sp_object_id} not found.")
        return None, "Unknown"
    
    response.raise_for_status()
    sp_data = response.json()
    sp_name = sp_data.get("displayName", "Unknown")
    logger.info(f"Resolved SP {sp_object_id} to App ID {sp_data.get('appId')} ({sp_name})")
    return sp_data.get("appId"), sp_name



def get_app_credentials(app_id, credential):
    """Fetch credentials (client secrets) for a given Application ID."""
    token = credential.get_token("https://graph.microsoft.com/.default").token
    url = f"https://graph.microsoft.com/v1.0/applications?$filter=appId eq '{app_id}'"
    headers = {"Authorization": f"Bearer {token}"}


    response = requests.get(url, headers=headers)
    
    if response.status_code == 404 or response.status_code != 200:
        logger.warning(f"Application {app_id} not found: {response.status_code}")
        return [], "Unknown"

        
    app_data = response.json().get("value", [])
    
    if not app_data:
        logger.warning(f"No application data found for appId {app_id}")
        return [], "Unknown"

        
    app_name = app_data[0].get("displayName", "Unknown")
    object_id = app_data[0].get("id")
    


    url = f"https://graph.microsoft.com/v1.0/applications/{object_id}/passwordCredentials"
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        logger.warning(f"Could not get credentials for app {app_id}: {response.status_code}")
        return [], app_name

    credentials = response.json().get("value", [])
    logger.info(f"Found {len(credentials)} credentials for app {app_id} ({app_name})")
    return credentials, app_name




def send_teams_alert(sp_name, app_name, cred_name, days_left, expiry_date):
    """Send a Teams alert with severity information."""
    try:
        if days_left <= 0:
            severity = "CRITICAL"
            message = f"**{severity}: SECRET EXPIRED**\n\nSecret '{cred_name}' for service principal '{sp_name}' ({app_name}) **HAS EXPIRED** on {expiry_date.strftime('%Y-%m-%d')}!\n\n**ACTION REQUIRED: Please renew this secret immediately.**"
        elif days_left <= 7:
            severity = "HIGH"
            message = f"**{severity}: SECRET EXPIRING SOON**\n\nSecret '{cred_name}' for service principal '{sp_name}' ({app_name}) will expire in **{days_left} days** (on {expiry_date.strftime('%Y-%m-%d')})!\n\n**ACTION REQUIRED: Please renew this secret within the next {days_left} days.**"
        else:
            severity = "MODERATE"
            message = f"**{severity}: SECRET EXPIRATION NOTICE**\n\nSecret '{cred_name}' for service principal '{sp_name}' ({app_name}) will expire in **{days_left} days** (on {expiry_date.strftime('%Y-%m-%d')}).\n\n**ACTION RECOMMENDED: Plan to renew this secret soon.**"
        
        payload = {"text": message}
        response = requests.post(TEAMS_WEBHOOK_URL, json=payload)
        
        if response.status_code == 200:
            logger.info(f"Teams alert sent ({severity}) for {sp_name}/{cred_name}")
        else:
            logger.error(f"Teams alert failed: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"Error sending Teams alert: {str(e)}")





def debug_azure_permissions(credential):
    """Debug Azure permissions by testing direct API access."""
    logger.info("\n==================================================================")
    logger.info("==================== DEBUGGING AZURE PERMISSIONS ====================")
    logger.info("==================================================================\n")
    
    #test w. identity info
    try:
        logger.info("Getting workload identity information...")
        url = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"
        
        headers = {"Metadata": "true"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            identity_info = response.json()
            client_id = identity_info.get("client_id", "Unknown")
            logger.info(f"Pod is using identity with client ID: {client_id}")
            logger.info(f"Expected client ID: 484f08c6-8725-4710-aea8-9ab62bd696d0")
        else:
            logger.error(f"Failed to get identity info: {response.status_code}")
    except Exception as e:
        logger.error(f"Error getting identity info: {str(e)}")
    

    # to test subscription access
    try:
        logger.info("\nTesting subscription access...")
        mgmt_token = credential.get_token("https://management.azure.com/.default").token
        headers = {"Authorization": f"Bearer {mgmt_token}"}
        
        url = f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}?api-version=2020-01-01"
        response = requests.get(url, headers=headers)
        logger.info(f"Subscription info status: {response.status_code}")

        if response.status_code == 200:
            sub_info = response.json()
            logger.info(f"Subscription name: {sub_info.get('displayName')}")
        else:
            logger.error(f"Subscription error: {response.text}")
    except Exception as e:
        logger.error(f"Subscription access error: {str(e)}")
    


    # to test role assignments access with details
    try:
        logger.info("\nTesting role assignments access...")
        url = f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
        response = requests.get(url, headers=headers)
        logger.info(f"Role assignments API status: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            assignments = data.get("value", [])
            logger.info(f"Found {len(assignments)} role assignments")
            if len(assignments) > 0:
                for i, assignment in enumerate(assignments[:3]):  # Show first 3 only
                    logger.info(f"Assignment {i+1}: principalId={assignment.get('properties', {}).get('principalId')}")
            else:
                logger.warning("Empty role assignments array returned - permission issue or no assignments")
                logger.info(f"Full response: {data}")
        else:
            logger.error(f"Role assignments error: {response.text}")
    except Exception as e:
        logger.error(f"Role assignments error: {str(e)}")
    


    # to test Microsoft Graph access
    try:
        logger.info("\nTesting Microsoft Graph API access...")
        graph_token = credential.get_token("https://graph.microsoft.com/.default").token
        headers = {"Authorization": f"Bearer {graph_token}"}
        
        url = "https://graph.microsoft.com/v1.0/servicePrincipals?$top=5"
        response = requests.get(url, headers=headers)
        logger.info(f"Service Principals API status: {response.status_code}")

        if response.status_code == 200:
            sps = response.json().get("value", [])
            logger.info(f"Found {len(sps)} service principals")
            if len(sps) > 0:
                for i, sp in enumerate(sps[:3]):  # Show first 3 only
                    logger.info(f"SP {i+1}: {sp.get('displayName')} ({sp.get('id')})")
            else:
                logger.warning("No service principals returned - permission issue")
        else:
            logger.error(f"Service principals error: {response.text}")
    except Exception as e:
        logger.error(f"Graph API error: {str(e)}")
    
    logger.info("\n==================================================================\n")



# getting expiring secrets
def get_expiring_secrets():
    """Main logic to scan expiring secrets."""
    logger.info("Starting secret expiration check")
    
    try:
        logger.info(f"Initializing Azure credentials for subscription {SUBSCRIPTION_ID}")
        
        # DEBUG FUNCTION - Make sure this is running
        logger.info("============= RUNNING DEBUG CHECKS =============")
        debug_azure_permissions(credential)
        logger.info("================================================")
        
        auth_client = AuthorizationManagementClient(credential, SUBSCRIPTION_ID)
        
        today = datetime.now(timezone.utc)
        scope = f"/subscriptions/{SUBSCRIPTION_ID}"
        expiring_secrets = set()
        
        # Stats for reporting
        stats = {
            "role_assignments": 0,
            "service_principals": 0,
            "secrets_total": 0,
            "secrets_expiring": 0
        }

        logger.info("Scanning all role assignments...")

        for role_assignment in auth_client.role_assignments.list_for_scope(scope):
            stats["role_assignments"] += 1
            sp_id = role_assignment.principal_id
            principal_type = role_assignment.principal_type

            if principal_type != "ServicePrincipal":
                logger.info(f"Skipping principal {sp_id} of type {principal_type}")
                continue

            stats["service_principals"] += 1
            logger.info(f"Checking Service Principal: {sp_id}")

            try:
                app_id, sp_name = resolve_app_id_from_sp(sp_id, credential)
                if not app_id:
                    continue

                credentials, app_name = get_app_credentials(app_id, credential)
                stats["secrets_total"] += len(credentials)

                for cred in credentials:
                    cred_name = cred.get("displayName", "Unknown")
                    expiry = datetime.fromisoformat(cred["endDateTime"].replace("Z", "+00:00") 
                                                  if "Z" in cred["endDateTime"] 
                                                  else cred["endDateTime"])
                    days_left = (expiry - today).days
                    
                    # Check expiration date
                    if days_left <= 0:
                        logger.info(f"CRITICAL: Secret '{cred_name}' for {sp_name} HAS EXPIRED on {expiry.strftime('%Y-%m-%d')}")
                    elif days_left <= 7:
                        logger.info(f"HIGH: Secret '{cred_name}' for {sp_name} expires in {days_left} days ({expiry.strftime('%Y-%m-%d')})")
                    else:
                        logger.info(f"MEDIUM: Secret '{cred_name}' for {sp_name} expires in {days_left} days ({expiry.strftime('%Y-%m-%d')})")

                    # Alert for secrets expiring in the next 30 days or already expired
                    if days_left <= 30:
                        stats["secrets_expiring"] += 1
                        secret_key = f"{sp_id}_{cred.get('keyId', '')}"
                        
                        if secret_key not in expiring_secrets:
                            expiring_secrets.add(secret_key)
                            send_teams_alert(sp_name, app_name, cred_name, days_left, expiry)

            except HttpResponseError as e:
                logger.error(f"Azure error for SP {sp_id}: {e.message}")
            except Exception as e:
                logger.error(f"General error for SP {sp_id}: {str(e)}")

        # Log summary
        logger.info("=== Summary ===")
        logger.info(f"Role assignments scanned: {stats['role_assignments']}")
        logger.info(f"Service principals found: {stats['service_principals']}")
        logger.info(f"Total secrets found: {stats['secrets_total']}")
        logger.info(f"Expiring secrets (≤30 days): {stats['secrets_expiring']}")
        
    except Exception as e:
        logger.error(f"Error in main function: {str(e)}")
        sys.exit(1)





        

if __name__ == "__main__":
    get_expiring_secrets()
