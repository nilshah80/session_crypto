-- wrk script for /session/init benchmark
-- Generates unique nonce per request using thread id + counter

local counter = 0
local thread_id = 0

function setup(thread)
    thread:set("id", thread_id)
    thread_id = thread_id + 1
end

function init(args)
    thread_id = wrk.thread:get("id") or 0
    math.randomseed(os.time() + thread_id * 1000)
end

request = function()
    counter = counter + 1
    -- Create truly unique nonce: thread_id + counter + random
    local nonce = string.format("wrk-%d-%d-%d-%d", thread_id, counter, os.clock() * 1000000, math.random(999999999))
    local timestamp = tostring(os.time() * 1000)

    -- Pre-generated valid P-256 public key (65 bytes, base64 encoded)
    local body = '{"keyAgreement":"ECDH_P256","clientPublicKey":"BGOf/r8knErP7ftu9/7UYFALq6j0TE6B139mCvRQg89BS6WQHqC3jkirzztakyvQIstxEGBoKulLPh492WrFWCM=","ttlSec":1800}'

    return wrk.format("POST", "/session/init", {
        ["Content-Type"] = "application/json",
        ["X-Nonce"] = nonce,
        ["X-Timestamp"] = timestamp
    }, body)
end
