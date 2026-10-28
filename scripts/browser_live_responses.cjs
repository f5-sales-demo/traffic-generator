// Forward each browser request only after its fresh native HTTP body is complete.
const { createHash } = require('node:crypto');
async function installLiveResponseBuffer(page, receipt) {
  receipt.live_response_buffering = false;
  receipt.buffered_responses = [];
  await page.route('**/*', async (route) => {
    const request = route.request();
    const row = {
      method: request.method(),
      request_sha256: createHash('sha256')
        .update(
          JSON.stringify([
            request.method(),
            request.url(),
            createHash('sha256')
              .update(request.postDataBuffer() || Buffer.alloc(0))
              .digest('hex'),
          ]),
        )
        .digest('hex'),
      fulfilled: false,
    };
    receipt.buffered_responses.push(row);
    let response;
    try {
      // The browser follows each redirect through the same owned network boundary.
      // The enclosing native scenario retains its declared hard deadline.
      response = await route.fetch({ maxRedirects: 0, timeout: 0 });
      const body = await response.body();
      row.status = response.status();
      row.body_bytes = body.length;
      row.body_sha256 = createHash('sha256').update(body).digest('hex');
      // Retain the original response object: status, headers, and body stay native.
      await route.fulfill({ response });
      row.fulfilled = true;
    } catch (error) {
      row.error = error.name;
      await route.abort('failed');
    } finally {
      if (response) {
        try {
          await response.dispose();
        } catch (error) {
          row.error = error.name;
        }
      }
    }
  });
  receipt.live_response_buffering = true;
}
module.exports = { installLiveResponseBuffer };
