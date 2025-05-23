# SecretExpirationChecker

SecretExpirationChecker is a tool designed to automatically detect expiring client secrets associated with Azure Active Directory (Microsoft Entra ID) service principals. 

Developed as part of a Bachelor thesis at the University of Applied Sciences Technikum Wien, the solution uses Azure Workload Identity for authentication and is intended for deployment in Microsoft Azure Kubernetes environments .

## Features

- Scans Microsoft Entra ID for service principals  
- Detects and reports expiring client secrets  
- Uses Microsoft Graph API for querying metadata  
- Authenticates using Azure Workload Identity 
- Sends alerting to dedicated Microsoft Teams Channel 
- Designed for automated, periodic execution in AKS  

This tool enables secret management and reduces the risk of service disruptions caused by expired credentials.
