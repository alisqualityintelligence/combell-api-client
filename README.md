# Combell API
Client for the [Combell.com API](https://api.combell.com/v2/documentation) (v2).

This implementation is far from a complete. Currently supported are
 * Accounts (get)
 * MySQL Databases (get and create)
 * SSH (toggle enabled/disabled, add keys)
 * PHP (set version, memory limit)
 * Web (toggle gzip, http2, Let's Encrypt and Auto-redirect to HTTPS)

# Usage
Here's a very general example of how to use it.
```php
<?php

use Symfony\Component\Console\Output\ConsoleOutput;

$client = CombellAPI\Client::create('key', 'secret', new ConsoleOutput);

// re-initialize PHP for web and CLI
foreach ($client->getAccounts() as $account) {
    $domain = $account['identifier'];

    $client->configurePHP($domain);

    $client->configureSSH($domain, false);
    $client->configureSSH($domain, true, [
        'abc123 #my SSH key'
    ]);
}
```
