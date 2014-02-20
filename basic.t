# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket; # 'no_plan';
use URI::Escape;

repeat_each(1);

plan tests => repeat_each() * 2 * blocks();

run_tests();

__DATA__

=== TEST 1: hash=md5
--- http_config
    upstream backend {
        server localhost:$TEST_NGINX_SERVER_PORT;
        server 127.0.0.2:80;
        server 127.0.0.3:80;
        server 127.0.0.4:80;
        server 127.0.0.5:80;
        sticky name=route hash=md5;
    }
--- config
    location /backend {
	rewrite /backend /frontend break;
        proxy_pass http://backend;
	proxy_set_header Host $host;
    }
    location /frontend {
        echo -n $echo_client_request_headers;
    }
--- request
GET /backend
--- response_headers
Set-Cookie: route=908c1a9fb15095f454c085282da20d92

=== TEST 2: hash=sha1
--- http_config
    upstream backend {
        server localhost:$TEST_NGINX_SERVER_PORT;
        server 127.0.0.2:80;
        server 127.0.0.3:80;
        server 127.0.0.4:80;
        server 127.0.0.5:80;
        sticky name=route hash=sha1;
    }
--- config
    location /backend {
	rewrite /backend /frontend break;
        proxy_pass http://backend;
	proxy_set_header Host $host;
    }
    location /frontend {
        echo -n $echo_client_request_headers;
    }
--- request
GET /backend
--- response_headers
Set-Cookie: route=4262de333a18749d31416a617184734678797276

=== TEST 3: hmac=md5
--- http_config
    upstream backend {
        server localhost:$TEST_NGINX_SERVER_PORT;
        server 127.0.0.2:80;
        server 127.0.0.3:80;
        server 127.0.0.4:80;
        server 127.0.0.5:80;
        sticky name=route hmac=md5 hmac_key=secret;
    }
--- config
    location /backend {
	rewrite /backend /frontend break;
        proxy_pass http://backend;
	proxy_set_header Host $host;
    }
    location /frontend {
        echo -n $echo_client_request_headers;
    }
--- request
GET /backend
--- response_headers
Set-Cookie: route=d20fd0a9eb6864058781ed6104e4c9fd

=== TEST 4: hmac=sha1
--- http_config
    upstream backend {
        server localhost:$TEST_NGINX_SERVER_PORT;
        server 127.0.0.2:80;
        server 127.0.0.3:80;
        server 127.0.0.4:80;
        server 127.0.0.5:80;
        sticky name=route hmac=sha1 hmac_key=secret;
    }
--- config
    location /backend {
	rewrite /backend /frontend break;
        proxy_pass http://backend;
	proxy_set_header Host $host;
    }
    location /frontend {
        echo -n $echo_client_request_headers;
    }
--- request
GET /backend
--- response_headers
Set-Cookie: route=34734c8d4b451151897b62db281c0b055e035adc

=== TEST 5: hmac=sha1 hmac_key=secret2
--- http_config
    upstream backend {
        server localhost:$TEST_NGINX_SERVER_PORT;
        server 127.0.0.2:80;
        server 127.0.0.3:80;
        server 127.0.0.4:80;
        server 127.0.0.5:80;
        sticky name=route hmac=sha1 hmac_key=secret2;
    }
--- config
    location /backend {
	rewrite /backend /frontend break;
        proxy_pass http://backend;
	proxy_set_header Host $host;
    }
    location /frontend {
        echo -n $echo_client_request_headers;
    }
--- request
GET /backend
--- response_headers
Set-Cookie: route=959bfc3973750a198925a3aedf9570f5d9b7e6f8

=== TEST 6: domain=.example.com
--- http_config
    upstream backend {
        server localhost:$TEST_NGINX_SERVER_PORT;
        server 127.0.0.2:80;
        server 127.0.0.3:80;
        server 127.0.0.4:80;
        server 127.0.0.5:80;
        sticky domain=.example.com;
    }
--- config
    location /backend {
	rewrite /backend /frontend break;
        proxy_pass http://backend;
	proxy_set_header Host $host;
    }
    location /frontend {
        echo -n $echo_client_request_headers;
    }
--- request
GET /backend
--- response_headers
Set-Cookie: route=908c1a9fb15095f454c085282da20d92; Domain=.example.com

=== TEST 7: path=/example
--- http_config
    upstream backend {
        server localhost:$TEST_NGINX_SERVER_PORT;
        server 127.0.0.2:80;
        server 127.0.0.3:80;
        server 127.0.0.4:80;
        server 127.0.0.5:80;
        sticky path=/example;
    }
--- config
    location /backend {
	rewrite /backend /frontend break;
        proxy_pass http://backend;
	proxy_set_header Host $host;
    }
    location /frontend {
        echo -n $echo_client_request_headers;
    }
--- request
GET /backend
--- response_headers
Set-Cookie: route=908c1a9fb15095f454c085282da20d92; Path=/example

=== TEST 8: expires=1h
--- http_config
    upstream backend {
        server localhost:$TEST_NGINX_SERVER_PORT;
        server 127.0.0.2:80;
        server 127.0.0.3:80;
        server 127.0.0.4:80;
        server 127.0.0.5:80;
        sticky expires=1h;
    }
--- config
    location /backend {
	rewrite /backend /frontend break;
        proxy_pass http://backend;
	proxy_set_header Host $host;
    }
    location /frontend {
        echo -n $echo_client_request_headers;
    }
--- request
GET /backend
--- response_headers
Set-Cookie: route=908c1a9fb15095f454c085282da20d92; Max-Age=3600

=== TEST 9: text=md5
--- http_config
    upstream backend {
        server localhost:$TEST_NGINX_SERVER_PORT;
        server 127.0.0.2:80;
        server 127.0.0.3:80;
        server 127.0.0.4:80;
        server 127.0.0.5:80;
        sticky name=route text=md5;
    }
--- config
    location /backend {
	rewrite /backend /frontend break;
        proxy_pass http://backend;
	proxy_set_header Host $host;
    }
    location /frontend {
        echo -n $echo_client_request_headers;
    }
--- request
GET /backend
--- response_headers
Set-Cookie: route=f6082e846954099610d58161bf189f37

=== TEST 10: text=sha1
--- http_config
    upstream backend {
        server localhost:$TEST_NGINX_SERVER_PORT;
        server 127.0.0.2:80;
        server 127.0.0.3:80;
        server 127.0.0.4:80;
        server 127.0.0.5:80;
        sticky name=route text=sha1;
    }
--- config
    location /backend {
	rewrite /backend /frontend break;
        proxy_pass http://backend;
	proxy_set_header Host $host;
    }
    location /frontend {
        echo -n $echo_client_request_headers;
    }
--- request
GET /backend
--- response_headers
Set-Cookie: route=17305d40bf37f65329da1850efddd32840891e32

=== TEST 11: text=raw
--- http_config
    upstream backend {
        server localhost:$TEST_NGINX_SERVER_PORT;
        server 127.0.0.2:80;
        server 127.0.0.3:80;
        server 127.0.0.4:80;
        server 127.0.0.5:80;
        sticky name=route text=raw;
    }
--- config
    location /backend {
	rewrite /backend /frontend break;
        proxy_pass http://backend;
	proxy_set_header Host $host;
    }
    location /frontend {
        echo -n $echo_client_request_headers;
    }
--- request
GET /backend
--- response_headers
Set-Cookie: route=127.0.0.1:1984

=== TEST 12: no_fallback
--- http_config
    upstream backend {
        server localhost:$TEST_NGINX_SERVER_PORT;
        server 127.0.0.2:80;
        server 127.0.0.3:80;
        server 127.0.0.4:80;
        server 127.0.0.5:80;
        sticky no_fallback;
    }
--- config
    location /backend {
	rewrite /backend /frontend break;
        proxy_pass http://backend;
	proxy_set_header Host $host;
    }
    location /frontend {
        echo -n $echo_client_request_headers;
    }
--- request
GET /backend
--- response_headers
Set-Cookie: route=908c1a9fb15095f454c085282da20d92

=== TEST 13: secure
--- http_config
    upstream backend {
        server localhost:$TEST_NGINX_SERVER_PORT;
        server 127.0.0.2:80;
        server 127.0.0.3:80;
        server 127.0.0.4:80;
        server 127.0.0.5:80;
        sticky secure;
    }
--- config
    location /backend {
	rewrite /backend /frontend break;
        proxy_pass http://backend;
	proxy_set_header Host $host;
    }
    location /frontend {
        echo -n $echo_client_request_headers;
    }
--- request
GET /backend
--- response_headers
Set-Cookie: route=908c1a9fb15095f454c085282da20d92; Secure

=== TEST 14: httponly
--- http_config
    upstream backend {
        server localhost:$TEST_NGINX_SERVER_PORT;
        server 127.0.0.2:80;
        server 127.0.0.3:80;
        server 127.0.0.4:80;
        server 127.0.0.5:80;
        sticky httponly;
    }
--- config
    location /backend {
	rewrite /backend /frontend break;
        proxy_pass http://backend;
	proxy_set_header Host $host;
    }
    location /frontend {
        echo -n $echo_client_request_headers;
    }
--- request
GET /backend
--- response_headers
Set-Cookie: route=908c1a9fb15095f454c085282da20d92; HttpOnly

