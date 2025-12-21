# Passbook Example Commands

A complete walkthrough of passbook commands with examples.

---

## 1. Initial Setup

### Initialize a New Store
```bash
# Create a new passbook store with your organization settings
passbook init --org "My Company" --domain "mycompany.com" --remote "git@github.com:mycompany/secrets.git"

# Or use the interactive setup wizard
passbook setup
```

### Clone an Existing Store
```bash
# Join an existing team by cloning their store
passbook clone git@github.com:mycompany/secrets.git
```

---

## 2. Authentication

### Login
```bash
# Login with your email (sends verification code)
passbook login
# Enter your email: alice@mycompany.com
# Check email for verification code
# Enter code: ABC123
```

### Check Current User
```bash
passbook whoami
# Output:
# Email:      alice@mycompany.com
# Roles:      admin
# Public Key: age1abc123...
```

### Logout
```bash
passbook logout
```

---

## 3. Managing Credentials

### Add a Credential
```bash
# Add with generated password
passbook cred add -n main -u admin@github.com -g github.com

# Add with specific password
passbook cred add -n team-account -u bot@company.com -p "mysecretpass" github.com

# Add with longer generated password (32 chars)
passbook cred add -n api-key -u service@aws.com -g -l 32 aws.amazon.com
```

### List Credentials
```bash
# List all
passbook cred list

# Filter by website
passbook cred list --website github.com

# Filter by tag
passbook cred list --tag production
```

### Show a Credential
```bash
# Show full details
passbook cred show github.com/main

# Show password only
passbook cred show -p github.com/main

# Copy password to clipboard
passbook cred show -c github.com/main
```

### Copy Password to Clipboard
```bash
passbook cred copy github.com/main
# Password copied! Clears in 45 seconds
```

### Edit a Credential
```bash
passbook cred edit github.com/main
# Interactive prompts to update username, password, notes
```

### Remove a Credential
```bash
# With confirmation prompt
passbook cred rm github.com/main

# Force delete (no prompt)
passbook cred rm -f github.com/main
```

---

## 4. Managing Projects & Environment Variables

### Create a Project
```bash
# Create with default stages (dev, staging, prod)
passbook project create backend-api

# Create with description
passbook project create backend-api -d "Main backend service"

# Create with custom stages
passbook project create backend-api --stage dev --stage prod
```

### List Projects
```bash
passbook project list
```

### Set Environment Variables
```bash
# Set a secret variable (default)
passbook env set backend-api dev "DATABASE_URL=postgres://localhost/dev"

# Set a non-secret variable
passbook env set backend-api dev "LOG_LEVEL=debug" --secret=false

# Set multiple variables
passbook env set backend-api dev "API_KEY=key123"
passbook env set backend-api dev "REDIS_URL=redis://localhost:6379"
passbook env set backend-api staging "DATABASE_URL=postgres://staging-db/app"
passbook env set backend-api prod "DATABASE_URL=postgres://prod-db/app"
```

### Show Environment Variables
```bash
# Show with masked secrets
passbook env show backend-api dev

# Show as .env format (reveals values)
passbook env show --dotenv backend-api dev

# Show as export format
passbook env show --export backend-api dev
```

### List Environments
```bash
# List all projects
passbook env list

# List stages for a project
passbook env list --project backend-api
```

### Export Environment
```bash
# Export to stdout
passbook env export backend-api dev

# Export to file
passbook env export -o .env backend-api dev

# Export as JSON
passbook env export -f json backend-api dev

# Export as shell exports
passbook env export -f export backend-api dev
```

### Import from .env File
```bash
passbook env import backend-api dev .env.local
```

### Run Command with Environment
```bash
# Run a command with env vars injected
passbook env exec backend-api dev -- npm start

# Run tests with staging environment
passbook env exec backend-api staging -- npm test

# Run any command
passbook env exec backend-api prod -- ./deploy.sh
```

### Remove Environment Variable
```bash
passbook env rm backend-api dev LOG_LEVEL
```

### Remove a Project
```bash
# With confirmation
passbook project rm backend-api

# Force delete
passbook project rm -f backend-api
```

---

## 5. Team Management

### List Team Members
```bash
passbook team list
```

### Invite a New Member
```bash
# Invite with default role (dev)
passbook team invite bob@mycompany.com

# Invite with specific roles
passbook team invite bob@mycompany.com --role dev --role staging-access

# Invite as admin
passbook team invite carol@mycompany.com --role admin
```

### Grant Additional Roles
```bash
# Give someone staging access
passbook team grant bob@mycompany.com staging-access

# Give someone production access
passbook team grant bob@mycompany.com prod-access

# Make someone an admin
passbook team grant bob@mycompany.com admin
```

### View Member's Roles
```bash
passbook team roles bob@mycompany.com
```

### Revoke Access
```bash
# Remove a team member entirely
passbook team revoke bob@mycompany.com

# Force (no confirmation)
passbook team revoke -f bob@mycompany.com
```

---

## 6. Per-Secret Access Control

### Credential Access
```bash
# See who can access a credential
passbook cred access list github.com/main

# Grant read access to specific user
passbook cred access grant github.com/main bob@mycompany.com --level read

# Grant write access
passbook cred access grant github.com/main carol@mycompany.com --level write

# Revoke access
passbook cred access revoke github.com/main bob@mycompany.com
```

### Environment Access
```bash
# See who can access an environment
passbook env access list backend-api prod

# Grant read access to production
passbook env access grant backend-api prod bob@mycompany.com --level read

# Grant write access
passbook env access grant backend-api prod carol@mycompany.com --level write

# Revoke access
passbook env access revoke backend-api prod bob@mycompany.com
```

---

## 7. Syncing

### Manual Sync
```bash
# Full sync (pull + push)
passbook sync

# Pull only
passbook sync --pull

# Push only
passbook sync --push
```

---

## 8. Complete Workflow Example

```bash
# === INITIAL SETUP ===
passbook init --org "Acme Corp" --domain "acme.com" --remote "git@github.com:acme/secrets.git"

# === ADD TEAM MEMBERS ===
passbook team invite alice@acme.com --role admin
passbook team invite bob@acme.com --role dev
passbook team invite carol@acme.com --role staging-access
passbook team invite dave@acme.com --role prod-access

# === ADD CREDENTIALS ===
passbook cred add -n bot -u acme-bot@github.com -g github.com
passbook cred add -n live -u acme@stripe.com -g stripe.com
passbook cred add -n main -u admin@aws.com -g aws.amazon.com

# === CREATE PROJECTS ===
passbook project create api -d "Main API service"
passbook project create frontend -d "React frontend app"
passbook project create worker -d "Background job processor"

# === SET DEV ENVIRONMENT ===
passbook env set api dev "DATABASE_URL=postgres://localhost/api_dev"
passbook env set api dev "REDIS_URL=redis://localhost:6379"
passbook env set api dev "API_SECRET=dev-secret-key"
passbook env set api dev "LOG_LEVEL=debug" --secret=false

# === SET STAGING ENVIRONMENT ===
passbook env set api staging "DATABASE_URL=postgres://staging-db/api"
passbook env set api staging "REDIS_URL=redis://staging-redis:6379"
passbook env set api staging "API_SECRET=staging-secret-key"

# === SET PROD ENVIRONMENT ===
passbook env set api prod "DATABASE_URL=postgres://prod-db/api"
passbook env set api prod "REDIS_URL=redis://prod-redis:6379"
passbook env set api prod "API_SECRET=super-secret-prod-key"

# === RESTRICT PRODUCTION ACCESS ===
# Only allow specific people to access production secrets
passbook env access grant api prod dave@acme.com --level write
passbook env access grant api prod alice@acme.com --level write

# === DEVELOPER WORKFLOW ===
# Bob (dev role) can run the app locally:
passbook env exec api dev -- npm run dev

# Carol (staging-access) can deploy to staging:
passbook env exec api staging -- ./deploy.sh staging

# Dave (prod-access) can deploy to production:
passbook env exec api prod -- ./deploy.sh production

# === CI/CD USAGE ===
# Export env for CI pipeline
passbook env export -o .env api staging
docker build --secret id=env,src=.env -t api:latest .

# Or inject directly
passbook env exec api staging -- docker-compose up -d

# === SYNC CHANGES ===
passbook sync
```

---

## Role Reference

| Role | Dev Env | Staging Env | Prod Env | Write Creds | Team Mgmt |
|------|---------|-------------|----------|-------------|-----------|
| `dev` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `staging-access` | ✓ | ✓ | ✗ | ✗ | ✗ |
| `prod-access` | ✓ | ✓ | ✓ | ✓ | ✗ |
| `admin` | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## Tips

1. **Flags before arguments**: Always put flags before positional arguments
   ```bash
   # Correct
   passbook cred add -n name -u user -g website.com

   # Wrong (flags ignored)
   passbook cred add website.com -n name -u user -g
   ```

2. **Clipboard auto-clear**: Password is automatically cleared from clipboard after 45 seconds

3. **Git auto-sync**: Changes are automatically committed and pushed (if configured)

4. **Per-secret vs role-based**: By default, secrets use role-based access. Use `access grant` to switch to per-secret control.
