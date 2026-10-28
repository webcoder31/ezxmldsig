<?php

require dirname(__DIR__) . '/vendor/autoload.php';
require __DIR__ . '/TestCase.php';
require __DIR__ . '/SealTestCase.php';
foreach (glob(__DIR__ . '/helpers/*.php') as $helper)
{
    require $helper;
}
require dirname(__DIR__) . '/demo/src/autoload.php';
require dirname(__DIR__) . '/demo-sso/src/autoload.php';
