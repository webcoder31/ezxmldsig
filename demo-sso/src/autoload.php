<?php
/**
 * Loads the library, its dependencies, the classes of the token demo (whose
 * certificates, receiver and replay store the SSO demo reuses) and those of
 * the SSO demo (namespace webcoder31\ezxmldsig\DemoSso).
 *
 * None of them is declared in composer.json: the demos are not part of the
 * package.
 */

require_once dirname(__DIR__, 2) . '/demo/src/autoload.php';

spl_autoload_register(function ($class) {
    $prefix = 'webcoder31\\ezxmldsig\\DemoSso\\';
    if (0 === strncmp($class, $prefix, strlen($prefix)))
    {
        $file = __DIR__ . '/' . substr($class, strlen($prefix)) . '.php';
        if (is_file($file))
        {
            require $file;
        }
    }
});
