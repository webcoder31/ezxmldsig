<?php declare(strict_types = 1);

/*
 * Part of the ApiGen setup of bin/gen-docs, which loads this file before
 * ApiGen starts (PHP auto_prepend_file): it lets the services of
 * bin/apigen/apigen.neon name the classes of this directory, which ApiGen's
 * own autoloader does not know.
 *
 * These classes work around defects of the pinned image of bin/gen-docs:
 * phpdoc-parser trims each paragraph of a docblock
 * (/src/vendor/phpstan/phpdoc-parser/src/Parser/PhpDocParser.php:275), and
 * ApiGen drops the empty text nodes that stand for its blank lines
 * (/src/src/Analyzer/NodeVisitors/PhpDocResolver.php:286), then joins the
 * remaining ones with a space (/src/src/Renderer/Latte/LatteFunctions.php:264).
 * The indentation and the blank lines being lost, the lists, nested lists and
 * code blocks of the docblocks are not rendered (see PhpDocResolver.php). Do
 * not remove them while the image behaves so.
 *
 * A class is only loaded when ApiGen asks for it, once ApiGen's autoloader,
 * which loads the parent class, is registered.
 */

spl_autoload_register(static function (string $class): void {
	if ($class === 'webcoder31\ezxmldsig\ApiGen\PhpDocResolver') {
		require __DIR__ . '/PhpDocResolver.php';
	}
});
