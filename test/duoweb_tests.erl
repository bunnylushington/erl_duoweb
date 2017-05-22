-module(duoweb_tests).
-include_lib("eunit/include/eunit.hrl").

-define(IKEY, "DIXXXXXXXXXXXXXXXXXX").
-define(WRONG_KEY, "DIXXXXXXXXXXXXXXXXXY").
-define(SKEY, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef").
-define(AKEY, "useacustomerprovidedapplicationsecretkey").
-define(USER, "testuser").

-define(INVALID_RESPONSE, "AUTH|INVALID|SIG").

-define(EXPIRED_RESPONSE, "AUTH|"
        "dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTMwMDE1Nzg3NA==|"
        "cb8f4d60ec7c261394cd5ee5a17e46ca7440d702").

-define(FUTURE_RESPONSE, "AUTH|"
        "dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0Mw==|"
        "d20ad0d1e62d84b00a3e74ec201a5917e77b6aef").

-define(WRONG_PARAMS_RESPONSE, "AUTH|"
        "dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNT"
        "cyNzI0M3xpbnZhbGlkZXh0cmFkYXRh|"
        "6cdbec0fbfa0d3f335c76b0786a4a18eac6cdca7").

-define(WRONG_PARAMS_APP, "APP|"
        "dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNT"
        "cyNzI0M3xpbnZhbGlkZXh0cmFkYXRh|"
        "7c2065ea122d028b03ef0295a4b4c5521823b9b5").


sign_request_test() -> ?assert(true).

