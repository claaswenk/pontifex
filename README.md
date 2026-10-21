# pontifex

## Local development: Using pre-commit hooks

To ensure that your code meets our quality and security standards—and to prevent failed CI pipelines, we use [pre-commit](https://pre-commit.com/).

This automatically runs checks before every commit (such as scanning for secrets with **Gitleaks** and linting the `Containerfile` with **Hadolint**).

### Setup (One-time)

1. **Install pre-commit:**
   If you don't have it installed yet, install it via pip or Homebrew:
   ```bash
   pip install pre-commit
   # or on macOS:
   brew install pre-commit
   ```

2. **Enable Git hooks in the repository:**
    Run the following command in the root directory of the project:
    ```
    pre-commit install
    ```
