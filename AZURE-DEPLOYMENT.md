# 🚀 Azure App Service Deployment Guide

## Prerequisites
- Azure subscription
- Azure CLI installed locally (optional but recommended)
- GitHub repository with your code

## Method 1: Deploy via Azure Portal (Recommended for beginners)

### Step 1: Create Azure App Service
1. Go to [Azure Portal](https://portal.azure.com)
2. Click "Create a resource" → "Web App"
3. Configure:
   - **Subscription**: Your Azure subscription
   - **Resource Group**: Create new (e.g., "it-ticketing-rg")
   - **Name**: Your app name (e.g., "it-ticketing-system")
   - **Publish**: Code
   - **Runtime stack**: Node 18 LTS
   - **Operating System**: Linux
   - **Region**: Choose closest to your users
   - **Pricing**: F1 (Free) or B1 (Basic - $13/month)

### Step 2: Configure Deployment
1. In your App Service → **Deployment Center**
2. Choose **GitHub** as source
3. Authorize GitHub access
4. Select:
   - **Repository**: cgolden15/it-ticketing
   - **Branch**: main
5. Click **Save**

### Step 3: Configure Environment Variables
1. Go to **Configuration** → **Application settings**
2. Add these environment variables:
   ```
   SESSION_SECRET = [Generate a 32+ character random string]
   DB_PATH = /home/data/tickets.db
   NODE_ENV = production
   WEBSITE_RUN_FROM_PACKAGE = 1
   ```
3. Click **Save**

### Step 4: Enable Persistent Storage (Important!)
1. Go to **Configuration** → **General settings**
2. Set **File system** to **Enabled**
3. Click **Save**

## Method 2: Deploy via Azure CLI

### Step 1: Login and Setup
```bash
# Login to Azure
az login

# Create resource group
az group create --name it-ticketing-rg --location "East US"

# Create App Service plan
az appservice plan create --name it-ticketing-plan --resource-group it-ticketing-rg --sku F1 --is-linux

# Create web app
az webapp create --resource-group it-ticketing-rg --plan it-ticketing-plan --name YOUR-APP-NAME --runtime "NODE|18-lts" --deployment-local-git
```

### Step 2: Configure App Settings
```bash
az webapp config appsettings set --resource-group it-ticketing-rg --name YOUR-APP-NAME --settings SESSION_SECRET="your-super-strong-secret" DB_PATH="/home/data/tickets.db" NODE_ENV="production" WEBSITE_RUN_FROM_PACKAGE="1"
```

### Step 3: Deploy from GitHub
```bash
az webapp deployment source config --resource-group it-ticketing-rg --name YOUR-APP-NAME --repo-url https://github.com/cgolden15/it-ticketing --branch main --manual-integration
```

## Post-Deployment Steps

### 1. Verify Deployment
- Your app will be available at: `https://YOUR-APP-NAME.azurewebsites.net`
- Check the **Deployment Center** for build status
- View **Log stream** for any errors

### 2. Initialize Database
The database will be automatically initialized on first run via the `postinstall` script.

### 3. Change Default Passwords
- Login with: `admin` / `admin123`
- Immediately change the admin password
- Delete or change the sample staff account

### 4. Custom Domain (Optional)
1. Go to **Custom domains**
2. Add your domain
3. Configure DNS settings
4. Add SSL certificate

## Monitoring and Maintenance

### View Logs
```bash
az webapp log tail --resource-group it-ticketing-rg --name YOUR-APP-NAME
```

### Scale Up/Down
```bash
# Scale to Basic tier (better performance)
az appservice plan update --name it-ticketing-plan --resource-group it-ticketing-rg --sku B1

# Scale back to Free tier
az appservice plan update --name it-ticketing-plan --resource-group it-ticketing-rg --sku F1
```

### Backup Database
The SQLite database is stored in `/home/data/` and persists between deployments when file system is enabled.

## Troubleshooting

### Common Issues
1. **App won't start**: Check Application settings and ensure all required environment variables are set
2. **Database errors**: Verify file system is enabled and DB_PATH is correct
3. **502 errors**: Check logs in Log stream, usually Node.js startup issues

### Useful URLs
- **App URL**: `https://YOUR-APP-NAME.azurewebsites.net`
- **SCM/Kudu**: `https://YOUR-APP-NAME.scm.azurewebsites.net`
- **Log Stream**: Available in Azure Portal

## Cost Optimization
- **Free Tier (F1)**: Good for testing, has limitations (60 min/day runtime)
- **Basic Tier (B1)**: ~$13/month, no runtime limitations
- **Shared Tier (D1)**: ~$10/month, middle ground option

## Security Considerations
- Always use HTTPS in production (automatically enabled)
- Regularly update the SESSION_SECRET
- Monitor access logs
- Consider Application Insights for monitoring