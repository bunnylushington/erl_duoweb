duoweb
=====

An OTP library implementing the client side for Duo Security's web
based 2FA.  Two functions are exported, `sign_request/4` and
`verify_response/4`.  The latter returns an empty list on failure.

Ported this directly from [duosecurity/duo_perl](https://github.com/duosecurity/duo_perl); thanks to the original author(s).

Brief Nitrogen Example
-------

``` erlang
-module(duo).
-include_lib("nitrogen_core/include/wf.hrl").
-export([ main/0, iframe/0 ]).

main() -> 
  case wf:request_method() of
    get -> #template{ file="duo-tf.html" };
    post -> verify_response()
  end.

iframe() -> 
  Request = duoweb:sign_request(ikey(), skey(), akey(),
                                wf:session(authenticated_username)),
  Data = [{"host", api_hostname()}, {"sig-request", Request}],
  #iframe{ data_fields=Data, html_id="duo_iframe"}.

verify_response() -> 
  case duoweb:verify_response(ikey(), skey(), akey(), wf:q(sig_response) of
    [] -> 
      wf:clear_session(),
      wf:redirect("invalid_login");
    Username -> 
      wf:user(Username),
      wf:redirect("valid_login")
  end.
  
ikey() -> "xxx...",
skey() -> "yyy...",
akey() -> "zzz...",
api_hostname() -> "xyzzy.example.com"

```

