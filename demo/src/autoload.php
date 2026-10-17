<?php
/**
 * Loads the library, its dependencies and the classes of the demo.
 *
 * The classes of the demo (namespace webcoder31\ezxmldsig\Demo) are not
 * declared in composer.json: the demo is not part of the package.
 */

require_once dirname(__DIR__, 2) . '/vendor/autoload.php';

spl_autoload_register(function ($class) {
    $prefix = 'webcoder31\\ezxmldsig\\Demo\\';
    if (0 === strncmp($class, $prefix, strlen($prefix)))
    {
        $file = __DIR__ . '/' . substr($class, strlen($prefix)) . '.php';
        if (is_file($file))
        {
            require $file;
        }
    }
});
