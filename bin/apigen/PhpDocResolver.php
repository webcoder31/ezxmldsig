<?php declare(strict_types = 1);

/*
 * Part of the ApiGen setup of bin/gen-docs: gives back to the docblocks the
 * blank lines and the indentation that ApiGen and phpdoc-parser drop, without
 * which the generated pages lose their lists, nested lists and code blocks.
 * Do not remove it while they behave as described below.
 *
 * phpdoc-parser returns one text node per paragraph of a docblock, and an
 * empty text node for each blank line. In the pinned image of bin/gen-docs:
 *
 * - phpdoc-parser trims each paragraph
 *   (/src/vendor/phpstan/phpdoc-parser/src/Parser/PhpDocParser.php:275,
 *   trim() in parseText()): the indentation of its first line is lost, so a
 *   nested list item or a paragraph of a list item comes out of its list;
 *
 * - ApiGen drops the empty text nodes
 *   (/src/src/Analyzer/NodeVisitors/PhpDocResolver.php:286, array_filter() in
 *   resolvePhpDocTextNode()), then joins the remaining ones with a space
 *   (/src/src/Renderer/Latte/LatteFunctions.php:264, implode(' ') in
 *   descriptionText()) before converting the description from Markdown
 *   (LatteFunctions.php:118, GithubFlavoredMarkdownConverter): every blank
 *   line is lost, the paragraphs end up on the same line, and a list or a
 *   fenced code block that follows a paragraph is not recognized.
 *
 * No markup of the docblocks can avoid it: a blank line is the only way
 * Markdown ends a paragraph, and indentation the only way it nests a list.
 *
 * The class below replaces ApiGen's resolver (service analyze.phpDocResolver,
 * see bin/apigen/apigen.neon). It gives each paragraph back the indentation
 * of its first line, read in the docblock itself, and merges each run of text
 * nodes into a single text node, joined with line breaks, so that the blank
 * lines are back before ApiGen resolves the inline tags ({@link}, {@see}) of
 * the text. If a new image changes the resolver, this class fails to load or
 * to be wired, and bin/gen-docs stops with an error.
 */

namespace webcoder31\ezxmldsig\ApiGen;

use ApiGen\Analyzer\NodeVisitors\PhpDocResolver as ApiGenPhpDocResolver;
use PhpParser\Node;
use PHPStan\PhpDocParser\Ast\PhpDoc\PhpDocNode;
use PHPStan\PhpDocParser\Ast\PhpDoc\PhpDocTextNode;

/**
 * Resolves the docblocks as ApiGen does, but keeps their blank lines and the
 * indentation of their paragraphs.
 */
class PhpDocResolver extends ApiGenPhpDocResolver
{
	/** @var string[] lines of the docblock being resolved, without their comment markers */
	protected array $docLines = [];


	public function enterNode(Node $node): null|int|Node
	{
		$doc = $node->getDocComment();
		$this->docLines = [];

		if ($doc !== null) {
			// The comment markers are those phpdoc-parser removes (Lexer::TOKEN_PHPDOC_EOL).
			foreach (preg_split('#\r?\n#', $doc->getText()) as $line) {
				$this->docLines[] = preg_replace('#^[\t ]*(?:\*(?!/) ?)?#', '', $line);
			}
		}

		return parent::enterNode($node);
	}


	protected function resolvePhpDoc(PhpDocNode $phpDoc): PhpDocNode
	{
		$children = [];
		$paragraphs = [];
		$cursor = 0;

		foreach ($phpDoc->children as $child) {
			if ($child instanceof PhpDocTextNode) {
				$paragraphs[] = $this->indent($child->text, $cursor);
				continue;
			}

			if ($paragraphs !== []) {
				$children[] = new PhpDocTextNode(implode("\n", $paragraphs));
				$paragraphs = [];
			}

			$children[] = $child;
		}

		if ($paragraphs !== []) {
			$children[] = new PhpDocTextNode(implode("\n", $paragraphs));
		}

		return parent::resolvePhpDoc(new PhpDocNode($children));
	}


	/**
	 * Prefixes a paragraph with the indentation of its first line in the
	 * docblock, looked for from line $cursor on, then moves $cursor past it.
	 * A paragraph that is not found is returned as is.
	 */
	protected function indent(string $text, int &$cursor): string
	{
		if ($text === '') {
			return $text;
		}

		$first = trim(strtok($text, "\n"), " \t");

		for ($i = $cursor; $i < count($this->docLines); $i++) {
			if (trim($this->docLines[$i], " \t") === $first) {
				$cursor = $i + substr_count($text, "\n") + 1;
				return substr($this->docLines[$i], 0, strspn($this->docLines[$i], " \t")) . $text;
			}
		}

		return $text;
	}
}
