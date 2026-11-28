# Administrator guide

The administrator uses everything in the [User guide](guide-user.md) and additionally manages the users. There is exactly one administrator.

## First start

1. Start the stack as described in the README. `./scripts/init-env.sh` creates `.env` and prints the `INITIAL_API_KEY`.
2. Open `https://127.0.0.1:8443` and follow **Create the administrator** on the sign-in page.
3. Enter the setup key (`INITIAL_API_KEY`), a name and a password (at least 12 characters) twice, then press **Create administrator**. You are signed in.

The setup works once. Afterwards the page answers "Setup is already complete".

## Users

The page **Users** is visible only to the administrator.

| Task | How |
|---|---|
| Add a user | **Add a user**: name (3-64 characters, lower case letters, digits, `.`, `_`, `-`) and a first password (at least 12 characters). Hand both to the user. |
| Set a new password | Type it into the row and press **Set**. The user is signed out everywhere and has to replace it at the next sign-in. |
| Delete a user | **Delete**. Their devices, pictures and sessions are deleted too. |

- The user chooses their own password at the first sign-in, so you do not know it afterwards.
- Your own row has no **Set** and no **Delete**. Change your password on the **Account** page.
- There is no password reset for the administrator account. Keep the password safe.

## Forgot password of a user

1. Page **Users**: set a new password and tell it to the user over a trusted channel.
2. Alternative over the API: issue a one-time reset token that the user redeems without signing in. It is valid for 15 minutes and works once. See `reset-token` and `reset-password` in [API examples](api.md).

## Operation

- Secrets, ports and addresses are in `.env`. Never commit it.
- Wake-on-LAN, access from other machines, releases and the CI pipeline: README.
- Requests are logged per container: [Logging](logging.md).
- `podman compose down -v` deletes the database and the certificates.
