const assert = require('node:assert/strict');
const test = require('node:test');
const http = require('node:http');
const { once } = require('node:events');
const { createHash } = require('node:crypto');
const { installLiveResponseBuffer } = require('../scripts/browser_live_responses.cjs');

test('each concurrent media request reads its fresh native body before fulfillment', async () => {
  const body = Buffer.from('complete native body '.repeat(500));
  let requests = 0;
  const server = http.createServer((request, response) => {
    requests++;
    assert.equal(request.headers.range, 'bytes=0-');
    response.writeHead(206, {
      'Content-Type': 'text/html',
      'Content-Length': body.length,
      'Content-Range': `bytes 0-${body.length - 1}/${body.length}`,
    });
    response.write(body.subarray(0, 100));
    setTimeout(() => response.end(body.subarray(100)), 20);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    let handler;
    const receipt = {};
    await installLiveResponseBuffer(
      {
        route: async (pattern, callback) => {
          assert.equal(pattern, '**/*');
          handler = callback;
        },
      },
      receipt,
    );
    const url = `http://127.0.0.1:${server.address().port}/native`;
    let fulfilled = 0;
    let disposed = 0;
    await Promise.all(
      [1, 2].map(async () => {
        let native;
        let received;
        await handler({
          request: () => ({ method: () => 'GET', url: () => url, postDataBuffer: () => null }),
          fetch: async (options) => {
            assert.deepEqual(options, { maxRedirects: 0, timeout: 0 });
            const response = await fetch(url, { headers: { Range: 'bytes=0-' } });
            native = {
              body: async () => {
                received = Buffer.from(await response.arrayBuffer());
                return received;
              },
              status: () => response.status,
              headers: () => Object.fromEntries(response.headers),
              dispose: async () => {
                disposed++;
              },
            };
            return native;
          },
          fulfill: async (options) => {
            assert.equal(options.response, native);
            assert.deepEqual(received, body);
            assert.equal(native.status(), 206);
            assert.equal(native.headers()['content-range'], `bytes 0-${body.length - 1}/${body.length}`);
            fulfilled++;
          },
          abort: async () => {
            assert.fail('a complete native response must not abort');
          },
        });
      }),
    );
    assert.equal(requests, 2);
    assert.equal(fulfilled, 2);
    assert.equal(disposed, 2);
    assert.equal(receipt.live_response_buffering, true);
    assert.equal(receipt.buffered_responses.length, 2);
    for (const row of receipt.buffered_responses) {
      assert.equal(row.body_sha256, createHash('sha256').update(body).digest('hex'));
      assert.equal(row.body_bytes, body.length);
      assert.equal(row.status, 206);
      assert.equal(row.fulfilled, true);
    }
  } finally {
    server.closeAllConnections();
    server.close();
    await once(server, 'close');
  }
});

test('native forwarding failures abort and retain failed response evidence', async () => {
  let handler;
  const receipt = {};
  await installLiveResponseBuffer(
    {
      route: async (_pattern, callback) => {
        handler = callback;
      },
    },
    receipt,
  );
  let aborted = false;
  await handler({
    request: () => ({
      method: () => 'POST',
      url: () => 'https://example.invalid/native',
      postDataBuffer: () => Buffer.from('native-payload'),
    }),
    fetch: async () => {
      throw new Error('native transport failed');
    },
    fulfill: async () => {
      assert.fail('a failed native response must never be fulfilled');
    },
    abort: async (reason) => {
      assert.equal(reason, 'failed');
      aborted = true;
    },
  });
  assert.equal(aborted, true);
  assert.equal(receipt.buffered_responses.length, 1);
  assert.equal(receipt.buffered_responses[0].fulfilled, false);
  assert.equal(receipt.buffered_responses[0].error, 'Error');
});

for (const failure of ['body', 'dispose']) {
  test(`native ${failure} failure remains explicit failed evidence`, async () => {
    let handler;
    const receipt = {};
    await installLiveResponseBuffer(
      {
        route: async (_pattern, callback) => {
          handler = callback;
        },
      },
      receipt,
    );
    let aborted = false;
    let disposed = false;
    await handler({
      request: () => ({ method: () => 'GET', url: () => 'https://example.invalid/native', postDataBuffer: () => null }),
      fetch: async () => ({
        body: async () => {
          if (failure === 'body') throw new TypeError('native body unavailable');
          return Buffer.from('native');
        },
        status: () => 200,
        dispose: async () => {
          disposed = true;
          if (failure === 'dispose') throw new TypeError('native cleanup failed');
        },
      }),
      fulfill: async () => {
        assert.equal(failure, 'dispose');
      },
      abort: async () => {
        aborted = true;
      },
    });
    assert.equal(disposed, true);
    assert.equal(aborted, failure === 'body');
    assert.equal(receipt.buffered_responses[0].fulfilled, failure === 'dispose');
    assert.equal(receipt.buffered_responses[0].error, 'TypeError');
  });
}
