<?php

namespace OpenStack\Test\Networking\v2\Models;

use GuzzleHttp\Message\Response;
use OpenStack\Networking\v2\Api;
use OpenStack\Networking\v2\Models\Network;
use OpenStack\Test\TestCase;

class NetworkTest extends TestCase
{
    private $network;

    public function setUp()
    {
        parent::setUp();

        $this->rootFixturesDir = dirname(__DIR__);

        $this->network = new Network($this->client->reveal(), new Api());
        $this->network->id = 'networkId';
    }

    public function test_it_creates()
    {
        $opts = [
            'name' => 'foo',
            'shared' => false,
            'adminStateUp' => true
        ];

        $expectedJson = ['network' => [
            'name' => $opts['name'],
            'shared' => $opts['shared'],
            'admin_state_up' => $opts['adminStateUp'],
        ]];

        $req = $this->setupMockRequest('POST', 'v2.0/networks', $expectedJson);
        $this->setupMockResponse($req, 'network-post');

        $this->assertInstanceOf(Network::class, $this->network->create($opts));
    }

    public function test_it_bulk_creates()
    {
        $opts = [
            [
                'name' => 'foo',
                'shared' => false,
                'adminStateUp' => true
            ],
            [
                'name' => 'bar',
                'shared' => true,
                'adminStateUp' => false
            ],
        ];

        $expectedJson = [
            'networks' => [
                [
                    'name' => $opts[0]['name'],
                    'shared' => $opts[0]['shared'],
                    'admin_state_up' => $opts[0]['adminStateUp']
                ],
                [
                    'name' => $opts[1]['name'],
                    'shared' => $opts[1]['shared'],
                    'admin_state_up' => $opts[1]['adminStateUp']
                ],
            ],
        ];

        $req = $this->setupMockRequest('POST', 'v2.0/networks', $expectedJson);
        $this->setupMockResponse($req, 'networks-post');

        $networks = $this->network->bulkCreate($opts);

        $this->assertInternalType('array', $networks);
        $this->assertCount(2, $networks);
    }

    public function test_it_updates()
    {
        // Updatable attributes
        $this->network->name = 'foo';
        $this->network->shared = true;
        $this->network->adminStateUp = false;

        $expectedJson = ['network' => [
            'name' => 'foo',
            'shared' => true,
            'admin_state_up' => false,
        ]];

        $request = $this->setupMockRequest('PUT', 'v2.0/networks/networkId', $expectedJson);
        $this->setupMockResponse($request, 'network-put');

        $this->assertInstanceOf(Network::class, $this->network->update());
    }

    public function test_it_retrieves()
    {
        $request = $this->setupMockRequest('GET', 'v2.0/networks/networkId');
        $this->setupMockResponse($request, 'network-get');

        $this->network->retrieve();

        $this->assertEquals('networkId', $this->network->id);
        $this->assertEquals('fakenetwork', $this->network->name);
        $this->assertEquals('ACTIVE', $this->network->status);
    }

    public function test_it_deletes()
    {
        $request = $this->setupMockRequest('DELETE', 'v2.0/networks/networkId');
        $this->setupMockResponse($request, new Response(204));

        $this->network->delete();
    }
}
