# Configuration

What follows is a brief explanation and breakdown of the less self-explanatory `rotproxy` configuration fields. The default configuration can be generated with `rotproxy init-conf`.

### Webroot and endpoints
`webroot_route` is the webroot to serve on, which can be a sub-path. Leave empty to serve on the root of the domain.

`auth_endpoint`, `login_endpoint`, `logout_endpoint` are the paths to the various endpoints, while `login_route` is the path to the HTML login page. Note that these will be appended to `webroot_route`. 

Example:
```
webroot_route = "rotproxy"
auth_endpoint = "apiv1/auth"
login_endpoint = "login"
logout_endpoint = "logout"
login_page = "html"
```

This means that the main page is hosted on `/rotproxy/html`, when one types their login information it will POST to `rotproxy/login` while the auth endpoint is `/rotproxy/apiv1/auth`. 

### Redirects
The `login_redirect` and `logout_redirect` settings take URLs to which a user will be automatically redirected on login/logout. These are static routes, but one can also pass the request parameter `redirect=` to specify where a user should be redirected.

### Magic routing
`magic_str` is the magic number that is used together with time to calculate a BLAKE3 hash that is used to hide the `login_page`, `login_endpoint` and `logout_endpoint` routes. Critically it is not used to hide `auth_endpoint` as that has to be reachable by the web server and ideally it should not even be externally resolvable.
This hash is placed after `webroot_route` but before any other route. Using the example in the section above, the login page would be `/rotproxy/{hash}/html`.

`magic_bytes` sets how many bytes the BLAKE3 hash will use. Keep in mind that the resulting hash is returned in hex so a value of `32` bytes in the end equals a `64` character string.

`magic_str_duration` sets how often the hash will rotate using [humantime](https://docs.rs/humantime/latest/humantime/). The max value is every 24h.
`magic_str_char_range` is the range that sets which parts of the hash will be used.

The concept of the magic route is to mask the login page from access unless one is privy to the conditions set in the configuration, at which point one has to go through the process of calculating it.

Note that the time used in the hash is always “floored” to the nearest multiple of the set duration. This means that any smaller units of time that are irrelevant to the current interval are effectively zeroed out. For example:

- With a duration of `1h`, the minutes and seconds are set to `0`.  
  - `14:37:52` → `14:00:00`
- With a duration of `30m`, the minutes are rounded down to the nearest multiple of `30`, and seconds are set to `0`.  
  - `14:12:47` → `14:00:00`  
  - `14:35:20` → `14:30:00`
- With a duration of `15m`, minutes are rounded down to the nearest multiple of 15, and seconds are set to `0`.  
  - `09:08:12` → `09:00:00`  
  - `09:29:59` → `09:15:00`
- With a duration of `45s`, only the seconds are rounded down to the nearest multiple of 45, while minutes and hours remain unchanged.  
  - `10:05:32` → `10:05:00`  
  - `10:05:50` → `10:05:45`

This flooring ensures that the hash remains constant for the entire duration interval and only changes when the timestamp moves into the next multiple of the set duration.

Example:
```
magic_str = "rotproxy"
magic_str_duration = "1h"
magic_str_char_range = "0:10"
```

So to obtain the hash I should take `rotproxy`, add a `:`, and the current UTC timestamp `1743498000`. So I should take the string `rotproxy:1743498000`, hash it using BLAKE3 and then pick the first 10 characters (`0:10`).

There are many, **many** ways for the end user to do this, I would personally recommend using [CyberChef](https://github.com/gchq/CyberChef).

This feature can be turned off by simply setting `magic_str` to empty.

### Trusted proxies
IPs of proxies to trust.

Example:
```
trusted_proxies = ["127.0.0.1", "10.10.10.2"]
```

### Rate limiting 
There are various values that control different aspects of the rate limiting logic. Basically every failed login attempt counts as a strike for that IP, both for that IP, _**and**_ _that specific user and IP combination_. The strikes are removed using a sliding window applied to each strike, so strikes will be removed _one after the other_ and _**not**_ all at once.  
Here's an example with the default options:
```
rate_limit_max_user_attempts = 3
rate_limit_user_window = 1800
rate_limit_max_ip_attempts = 4
rate_limit_ip_window = 1800
```
So if IP `A` attempts to login as user `admin` and fails 3 times, that IP cannot attempt to login as `admin` until it loses one of it's 3 strikes (as specified by `rate_limit_max_user_attempts`), which will happen after 1800 seconds (as specified by `rate_limit_user_window`). At this point `A` will be able to attempt as `admin` 1 more time, but if that fails the number of strikes would again be 3 and thus `A` would be restricted again.  `rate_limit_max_ip_attempts` specifies the number of overall attempts an IP can do, so by specifying a higher number of `ip_attempts` one can allow IP to attempt login as another user, `n` more times. By default this number is 1 higher to allow for username typos.  
Remember, a failed login counts towards both IP and user strikes, but note that upon successful login, all strikes are removed.   

There is one final setting for the rate limiter: `rate_limit_bg_prune_job`. This sets how often the background cleanup job runs to remove expired strikes from the in-memory database. It does not directly affect bans, it just helps clear up some memory and mitigates against spam attacks that clog up memory.

Note that bans do not survive across server restarts.

### Cookies & sessions
rotproxy uses a single cookie to track logged in sessions & preserve them across server reboots, a new secure cookie key can be generated using `rotproxy gen-cookie`.   
`cookie_secure` specifies whether the `Secure` attribute is set on the cookie. Note that `SameSite` is always set to `Strict` and that `HttpOnly` is always set.  
For the rest of the cookie options, I recommend reading up on cookies, for instance [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies).


The length of a session can be configured by `session_ttl`. Setting `session_abs_ttl` determines the absolute length of a session, in other words the amount of time after which, regardless of interaction, rotproxy will ask for a re-login. This can be disabled by setting it to `0`. 

### Encryption
```
hash_mem_cost = 64
hash_time_cost = 3
hash_parallel_cost = 4
```
These 3 settings can be used to harden the Argon2 hashing. These defaults are taken from BitWarden and are technically above standard recommendations. For more information on whether to change these and what to, see [here](https://en.wikipedia.org/wiki/Argon2#Recommended_minimum_parameters) or [here](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#introduction). These values can be adjusted to reduce memory usage or computational time. However, to maintain security, decreasing memory usage should be balanced by increasing computational time, and decreasing computational time should be balanced by increasing memory usage.