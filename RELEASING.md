# Release Process

This document describes how to publish new versions of `@nacho-labs/nachos-dlp` to npm.

## Prerequisites

1. **npm Login**: Ensure you're logged in to npm with an account that has publish access to the `@nacho-labs` organization:
   ```bash
   npm login
   ```

2. **Clean Working Directory**: Ensure all changes are committed and the working directory is clean:
   ```bash
   git status
   ```

3. **Tests Pass**: Ensure all tests pass before releasing:
   ```bash
   npm test
   npm run lint
   npm run build
   ```

## Manual Release

### Option 1: Version + Publish (Recommended)

Use the combined release scripts that handle both versioning and publishing:

```bash
# For a patch release (0.0.1 -> 0.0.2)
npm run release:patch

# For a minor release (0.0.1 -> 0.1.0)
npm run release:minor

# For a major release (0.0.1 -> 1.0.0)
npm run release:major
```

These scripts will:
1. Bump the version in `package.json`
2. Create a git commit with the version number
3. Create a git tag (e.g., `v0.0.2`)
4. Build the project (via `prepublishOnly` hook)
5. Publish to npm

### Option 2: Manual Step-by-Step

If you prefer to control each step:

```bash
# 1. Bump the version
npm run version:patch  # or version:minor, version:major

# 2. Push the commit and tags
git push origin main --follow-tags

# 3. Publish to npm
npm run publish:npm
```

## After Publishing

### When Using Combined Release Scripts (Option 1)

The combined scripts (`release:patch`, `release:minor`, `release:major`) handle versioning, committing, and publishing. After they complete:

1. **Push Tags**: Push the version commit and tags to GitHub:
   ```bash
   git push origin main --follow-tags
   ```

2. **Verify**: Check that the package is available on npm:
   ```bash
   npm view @nacho-labs/nachos-dlp
   ```

3. **Create GitHub Release** (optional): Go to GitHub and create a release from the new tag with release notes.

### When Using Manual Step-by-Step (Option 2)

After manually publishing with `npm run publish:npm`:

1. **Push Tags**: Push the version commit and tags to GitHub (if not already done):
   ```bash
   git push origin main --follow-tags
   ```

2. **Verify**: Check that the package is available on npm:
   ```bash
   npm view @nacho-labs/nachos-dlp
   ```

3. **Create GitHub Release** (optional): Go to GitHub and create a release from the new tag with release notes.

## CI/CD Automated Publishing

The repository has a CI workflow configured for automated publishing:

- Location: `.github/workflows/ci.yml`
- Currently **disabled** (commented out)
- When enabled, it will automatically publish to npm on every push to `main`

### To Enable Automated Publishing:

1. **Add npm Token**: Add your npm token as a GitHub secret named `NPM_TOKEN`
   - Go to: Repository Settings → Secrets and variables → Actions → New repository secret
   - Get token from: https://www.npmjs.com/settings/YOUR_USERNAME/tokens
   - Use an "Automation" token type

2. **Uncomment Publish Step**: In `.github/workflows/ci.yml`, uncomment these lines:
   ```yaml
   - run: npm publish --access public
     env:
       NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
   ```

3. **Version Workflow**: Consider adding a workflow that:
   - Runs on manual trigger or version tags
   - Bumps version automatically based on commit messages (conventional commits)
   - Creates releases with changelogs

## Version Numbering

Follow [Semantic Versioning](https://semver.org/):

- **Patch** (0.0.x): Bug fixes, internal changes
- **Minor** (0.x.0): New features, backward compatible
- **Major** (x.0.0): Breaking changes

## Troubleshooting

### "npm ERR! code E403" - Forbidden

- Ensure you're logged in: `npm whoami`
- Verify you have publish access to `@nacho-labs` organization
- Check that the package name is correct in `package.json`

### "npm ERR! You need a paid account to publish scoped packages"

- This shouldn't happen with the `--access public` flag
- Verify `.npmrc` has `access=public`

### "Working directory is not clean"

- Commit or stash all changes before running version scripts
- The `npm version` command requires a clean git working directory

## Resources

- [npm Publishing Documentation](https://docs.npmjs.com/packages-and-modules/contributing-packages-to-the-registry)
- [Semantic Versioning](https://semver.org/)
- [npm version Documentation](https://docs.npmjs.com/cli/v10/commands/npm-version)
