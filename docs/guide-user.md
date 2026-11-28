# User guide

For everybody with an account. The administrator has the same functions and a few more: [Administrator guide](guide-admin.md).

## Sign in

1. Open the address of your Pontifex, e.g. `https://127.0.0.1:8443`, and accept the certificate warning once.
2. Enter username and password.
3. If the administrator chose your password, the page **Choose your password** opens first. Enter the current password, then a new one (at least 12 characters, different from the current one) twice.

After 5 failed attempts sign-in is blocked for 15 minutes. You are signed out after 30 minutes without activity and after 12 hours at the latest.

## Devices

The page **Devices** shows the total, online and offline count and one row per device with state, name, address, MAC address and latency. It refreshes every 10 seconds.

| Task | How |
|---|---|
| Add a device | **Add a device**: name (1-64 characters, unique among your devices), address (host name or IP), MAC address. A picture is optional. At most 100 devices. |
| Wake | **Wake** in the row. The message means the packet was sent, not that the device is up. Wait 5 seconds before the next try. |
| Edit | **Edit**: change name, address, MAC address or picture, then **Save**. |
| Delete | **Delete** in the row. |

A device is online if it answers on one of the ports 22, 80, 443, 445 or 3389. To be woken, it needs Wake-on-LAN enabled; see the README.

Only you see your devices. Addresses of this host (loopback), link-local and multicast addresses are refused.

## Account

The page **Account** shows your name, role and device count.

- **Profile picture:** choose a PNG, JPEG or WebP of at most 200 KB and press **Save picture**.
- **Change password:** current password, new password twice. All your other sessions are signed out.
- **Sign out:** top right.

## Forgot your password

Ask the administrator to set a new one. You get a temporary password and choose your own at the next sign-in.

Renaming or deleting your own account is possible over the API only: [API examples](api.md).
