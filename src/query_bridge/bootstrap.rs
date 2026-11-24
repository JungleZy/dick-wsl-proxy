// Fixed read-only WSL query bootstrap.
#[cfg(windows)]
pub(super) const BOOTSTRAP: &str = r#"import json, os, select, signal, sys, time
buffer = bytearray()
def receive(limit):
    deadline = time.monotonic() + 60
    while True:
        end = buffer.find(b'\n')
        if end >= 0:
            if end + 1 > limit:
                raise ValueError('request_limit')
            line = bytes(buffer[:end])
            del buffer[:end + 1]
            return json.loads(line)
        if len(buffer) >= limit:
            raise ValueError('request_limit')
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([0], [], [], remaining)[0]:
            return None
        chunk = os.read(0, min(4096, limit - len(buffer)))
        if not chunk:
            if buffer:
                raise ValueError('incomplete_request')
            return None
        buffer.extend(chunk)
def emit(value):
    print(json.dumps(value, separators=(',', ':'), ensure_ascii=True), flush=True)
def reason(error):
    return ''.join(c if 32 <= ord(c) < 127 else '?' for c in str(error))[:512] or 'query_failed'
try:
    signal.alarm(65)
    initial = receive(131072)
    if initial is None:
        sys.exit(0)
    if not isinstance(initial, dict) or set(initial) != {'kernel', 'plan'} or not isinstance(initial['kernel'], str):
        raise ValueError('invalid_bootstrap')
    kernel = {'__name__': 'wsl_proxy_readonly_query'}
    exec(compile(initial['kernel'], '<embedded-kernel>', 'exec'), kernel)
    plan = kernel['validate']({'operation': 'precheck', 'plan': initial['plan'], 'protocol': None, 'peer': None})
    kernel['guard'](plan)
    prepared = kernel['prepare_lookup'](plan)
    del initial
    emit({'kind': 'ready'})
    sequence = 0
    while True:
        signal.alarm(65)
        request = receive(2048)
        if request is None:
            break
        signal.alarm(12)
        require = kernel['require']
        require(isinstance(request, dict) and set(request) == {'id', 'lookups'}, 'invalid_query')
        require(type(request['id']) is int and request['id'] == sequence + 1 and request['id'] <= 0xffffffffffffffff, 'invalid_query_sequence')
        lookups = request['lookups']
        # An empty request is the host's idle keepalive: it is answered
        # without opening a conntrack socket.
        require(isinstance(lookups, list) and 0 <= len(lookups) <= 16, 'invalid_query_count')
        keys = []
        for item in lookups:
            require(isinstance(item, dict) and set(item) == {'protocol','peer'} and item['protocol'] in ('tcp','udp'), 'invalid_query_item')
            if isinstance(item['peer'], str) and item['peer'].startswith('['):
                peer = kernel['endpoint6'](item['peer'])
                require('ipv6' in plan and peer[0] == kernel['endpoint6']('[' + plan['ipv6']['guest'] + ']:1')[0], 'invalid_query_peer')
            else:
                peer = kernel['endpoint'](item['peer'])
                require(peer[0] == plan['guest'], 'invalid_query_peer')
            keys.append((item['protocol'], item['peer']))
        sequence = request['id']
        try:
            # One exact kernel lookup per key on a fresh socket: no table dump,
            # snapshot or cached answer. The lookups are interleaved with their
            # decoding, so all of it is reported as kernel read time.
            read_start = time.monotonic_ns()
            origins = []
            ct = kernel['Conntrack']() if keys else None
            try:
                for protocol, peer in keys:
                    if peer.startswith('['):
                        origins.extend(kernel['exact6_queries'](plan, ct, [(protocol, peer)]))
                    else:
                        origins.extend(kernel['exact_queries'](prepared, ct, [(protocol, peer)]))
            finally:
                if ct is not None:
                    ct.close()
            kernel_read_us = (time.monotonic_ns() - read_start) // 1000
            decode_lookup_us = 0
            require(0 <= kernel_read_us + decode_lookup_us <= 12000000, 'invalid_query_timing')
            emit({'kind': 'origins', 'id': sequence, 'origins': origins, 'kernel_read_us': kernel_read_us, 'decode_lookup_us': decode_lookup_us})
        except (kernel['Failure'], OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
            emit({'kind': 'lookup_error', 'id': sequence, 'error': reason(error)})
except Exception as error:
    emit({'kind': 'fatal', 'error': reason(error)})
    sys.exit(1)
"#;
