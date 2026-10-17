<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Demo\Api;
use webcoder31\ezxmldsig\Demo\Receiver;
use webcoder31\ezxmldsig\Demo\ReplayStore;

/**
 * The JSON API of the demo, its replay memory, and the files of its
 * interface: a value of a token never reads as markup, and the page loads
 * nothing from other servers.
 */
class DemoApiTest extends TestCase
{
    const SCRIPT = '<script>alert(1)</script>';

    private static function publicFile($name)
    {
        return file_get_contents(dirname(__DIR__) . '/demo/public/' . $name);
    }

    /**
     * Sends a request to the API and returns [status, raw JSON, decoded].
     */
    private function request(Api $api, $method, $path, $body = null)
    {
        list($status, $response) = $api->handle($method, $path, is_null($body) ? '' : json_encode($body));
        $json = Api::encode($response);
        $this->assertIsString($json);

        return [$status, $json, json_decode($json, true)];
    }

    private function api()
    {
        return new Api(new ReplayStore($this->tempFile('replay.json', '')));
    }

    public function testAScriptInTheDataIsNeitherMarkupInTheResponsesNorLost()
    {
        $api = $this->api();
        $data = ['name' => self::SCRIPT, 'nested' => ['value' => '"\'&<>']];

        list($status, $issueJson, $issued) = $this->request($api, 'POST', '/api/issue', ['data' => $data]);
        $this->assertSame(200, $status);
        $this->assertNull($issued['error']);
        // The issuer code quotes the data.
        $this->assertStringContainsString(var_export(self::SCRIPT, true), $issued['code']);

        list($status, $json, $verified) = $this->request($api, 'POST', '/api/verify', ['xml' => $issued['xml']]);
        $this->assertSame(200, $status);
        $this->assertTrue($verified['accepted']);
        $this->assertSame($data, $verified['data']);

        // The response holds the value, and the token, with "<" and ">"
        // escaped: "<script>" is written \u003Cscript\u003E (chr(92) is a
        // backslash).
        $this->assertStringNotContainsString('<', $json);
        $this->assertStringNotContainsString('>', $json);
        $this->assertStringContainsString(chr(92) . 'u003Cscript' . chr(92) . 'u003E', $json);
        $this->assertStringNotContainsString('<', $issueJson);
        $this->assertStringContainsString(chr(92) . 'u003Cds:Signature', $issueJson);
    }

    public function testAnErrorQuotingTheTokenIsNotMarkupEither()
    {
        list($status, $json) = $this->request($this->api(), 'POST', '/api/issue', ['data' => [self::SCRIPT => 'x']]);

        $this->assertSame(400, $status);
        $this->assertStringContainsString('Invalid key', $json);
        $this->assertStringNotContainsString('<', $json);
    }

    public function testTheReceiverRefusesAReplayedTokenThroughTheApi()
    {
        $api = $this->api();
        list(, , $issued) = $this->request($api, 'POST', '/api/issue', []);

        list(, , $first) = $this->request($api, 'POST', '/api/verify', ['xml' => $issued['xml']]);
        list(, , $second) = $this->request($api, 'POST', '/api/verify', ['xml' => $issued['xml']]);

        $this->assertTrue($first['accepted']);
        $this->assertSame(1, $first['replayMemory']);
        $this->assertFalse($second['accepted']);
        $this->assertSame('Token already used!', end($second['steps'])['message']);

        list(, , $cleared) = $this->request($api, 'POST', '/api/replay/clear', []);
        $this->assertSame(0, $cleared['replayMemory']);
        list(, , $third) = $this->request($api, 'POST', '/api/verify', ['xml' => $issued['xml']]);
        $this->assertTrue($third['accepted']);
    }

    public function provideInvalidRequests()
    {
        return [
            'unknown endpoint' => ['POST', '/api/nope', [], 404],
            'not JSON' => ['POST', '/api/verify', null, 400],
            'unknown receiver setting' => ['POST', '/api/verify', ['xml' => 'x', 'receiver' => ['trustEverything' => true]], 400],
            'time to live out of bounds' => ['POST', '/api/verify', ['xml' => 'x', 'receiver' => ['ttl' => 0]], 400],
            'unknown algorithm' => ['POST', '/api/issue', ['algorithms' => ['signatureAlgorithm' => 'RSA_1_5']], 400],
            'unknown attack' => ['POST', '/api/attack', ['id' => 'nope'], 400],
            'empty value' => ['POST', '/api/issue', ['data' => ['a' => '']], 400],
            'too deep' => ['POST', '/api/issue', ['data' => ['a' => ['b' => ['c' => ['d' => ['e' => 'f']]]]]], 400],
        ];
    }

    /**
     * @dataProvider provideInvalidRequests
     */
    public function testAnInvalidRequestIsRefused($method, $path, $body, $expectedStatus)
    {
        $api = $this->api();
        list($status, $response) = $api->handle($method, $path, is_null($body) ? 'not json' : json_encode($body));

        $this->assertSame($expectedStatus, $status);
        $this->assertArrayHasKey('error', $response);
    }

    public function testTheReplayMemoryIsKeptInItsFile()
    {
        $path = $this->tempFile('memory.json', '');
        $id = str_repeat('ab', 16);

        $this->assertTrue((new ReplayStore($path))->add($id, 60)['added']);
        $again = (new ReplayStore($path))->add($id, 60);
        $this->assertFalse($again['added']);
        $this->assertSame(1, $again['size']);

        // An identifier is forgotten once its retention is over.
        (new ReplayStore($path))->add(str_repeat('cd', 16), 0);
        $this->assertSame(1, (new ReplayStore($path))->size());

        (new ReplayStore($path))->clear();
        $this->assertSame(0, (new ReplayStore($path))->size());
    }

    public function testTheReceiverCodeFollowsItsConfiguration()
    {
        $code = Receiver::fromArray([
            'ca' => false,
            'pin' => true,
            'subject' => false,
            'decrypt' => false,
            'ttl' => 45,
            'replay' => false,
            'algorithms' => ['signatureAlgorithm' => 'RSA_SHA512'],
        ])->phpCode();

        $this->assertStringContainsString("'signerCertPath' => 'certs/sign.cert.pem'", $code);
        $this->assertStringNotContainsString('caCertPath', $code);
        $this->assertStringNotContainsString('expectedSubject', $code);
        $this->assertStringContainsString("'signatureAlgorithm' => XMLDSigToken::RSA_SHA512", $code);
        $this->assertStringContainsString('XMLDSigToken::analyzeXMLToken($xml, $options)', $code);
        $this->assertStringContainsString('isOutOfDate(45)', $code);
        $this->assertStringContainsString('Replay: NOT checked', $code);
    }

    /**
     * The script of the page builds no markup from strings: values are
     * written with textContent.
     */
    public function testThePageScriptBuildsNoMarkupFromStrings()
    {
        $script = self::publicFile('app.js');

        foreach (['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'DOMParser'] as $sink)
        {
            $this->assertStringNotContainsString($sink, $script, $sink);
        }
    }

    public function testThePageLoadsNothingFromOtherServers()
    {
        foreach (['index.html', 'app.css', 'app.js', 'favicon.svg'] as $name)
        {
            // The SVG namespace is a name, not a resource.
            $source = str_replace('http://www.w3.org/2000/svg', '', self::publicFile($name));
            $this->assertDoesNotMatchRegularExpression('#https?://|//[a-z0-9.-]+\.[a-z]{2,}/|@import#i', $source, $name);
        }

        // The entry point forbids it too.
        $this->assertStringContainsString("default-src 'none'", self::publicFile('index.php'));
    }
}
