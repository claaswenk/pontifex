#!/bin/bash
# Fix TLS key permissions for containers

echo "Fixing TLS key permissions..."
sudo chmod 644 /home/sphinx2/Documents/SecurityByDesign/pontifex/secrets/certs/backend/tls.key
sudo chmod 644 /home/sphinx2/Documents/SecurityByDesign/pontifex/secrets/certs/database/tls.key
echo "Done! The containers should now be able to read the TLS keys."
