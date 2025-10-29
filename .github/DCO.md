# Developer Certificate of Origin (DCO)

This project requires all contributors to sign off on their commits using the Developer Certificate of Origin (DCO). This is a simple way to certify that you wrote or have the right to submit the code you are contributing to the project.

## What is DCO?

The DCO is an attestation attached to every contribution made by every developer. In the commit message of the contribution, the developer simply adds a `Signed-off-by` statement and thereby agrees to the DCO, which you can find at [developercertificate.org](https://developercertificate.org/).

## How to Sign Your Commits

### For New Commits

When making a new commit, use the `-s` or `--signoff` flag:

```bash
git commit -s -m "Your commit message"
```

This will automatically add the `Signed-off-by` line to your commit message.

### For Existing Commits

If you forget to sign off on a commit, you can amend it:

```bash
# For the last commit
git commit --amend --signoff --no-edit

# For multiple commits, use interactive rebase
git rebase --signoff HEAD~N  # where N is the number of commits
```

After amending commits, you'll need to force push:

```bash
git push --force-with-lease
```

### Configure Git to Always Sign Off

You can configure git to always sign your commits:

```bash
git config --global commit.gpgsign true
```

Or set up an alias for convenience:

```bash
git config --global alias.cs 'commit --signoff'
```

Then use `git cs` instead of `git commit`.

## What the DCO Signature Looks Like

Your commits should include a line that looks like this:

```
Signed-off-by: Your Name <your.email@example.com>
```

This will be automatically added when you use the `--signoff` flag.

## Why Do We Require DCO?

The DCO helps ensure that:

1. **Legal Clarity**: We have clear documentation that contributors have the right to submit their code
2. **Open Source Compliance**: The project maintains proper licensing and contribution tracking
3. **Community Trust**: Contributors can be confident about the legal status of the codebase

## Automated Checking

Our CI/CD pipeline automatically checks all commits in pull requests for DCO signatures. PRs with unsigned commits will fail the DCO check and cannot be merged until all commits are properly signed.

## Need Help?

If you're having trouble with DCO signatures or need assistance, please:

1. Check the error messages in the CI/CD pipeline for specific guidance
2. Review this documentation
3. Open an issue if you need further assistance

Thank you for helping us maintain a legally compliant and trustworthy open source project! 🎯