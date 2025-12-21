# passbook

team password manager for sharing credentials and environment variables.

```bash
passbook init      # start a new store
passbook clone     # join an existing team
```

## how it works

secrets are encrypted with [age](https://github.com/FiloSottile/age) and stored in a git repo. each team member has their own key pair - secrets are encrypted for all recipients who should have access.

the git repo is the single source of truth. when you add a credential or update an env var, it's encrypted and committed. teammates pull to get the latest secrets. no central server needed - just a shared git remote (github, gitlab, etc). you get version history, branching, and collaboration for free.
