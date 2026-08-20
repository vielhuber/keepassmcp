#!/usr/bin/env php
<?php
declare(strict_types=1);

foreach (
    [__DIR__ . '/../vendor/autoload.php', __DIR__ . '/../../../autoload.php', __DIR__ . '/../../../../autoload.php']
    as $autoloadPath
) {
    if (is_file($autoloadPath)) {
        require_once $autoloadPath;
        break;
    }
}

use vielhuber\simplemcp\simplemcp;

$projectDirectory = getcwd();
if ($projectDirectory === false) {
    $projectDirectory = dirname(__DIR__);
}
$envPath = $projectDirectory . '/.env';
if (!is_file($envPath) && file_put_contents($envPath, "MCP_TOKEN=\nKEEPASS_DATABASE=\nKEEPASS_PASSWORD=\n") === false) {
    fwrite(STDERR, 'keepass-mcp-server: failed to create ' . $envPath . PHP_EOL);
    exit(1);
}

new simplemcp(name: 'keepass-mcp-server', log: 'mcp-server.log', discovery: __DIR__, auth: 'static', env: $envPath);

