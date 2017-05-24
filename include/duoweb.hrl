-define(DUO_PREFIX, "TX").
-define(APP_PREFIX, "APP").
-define(AUTH_PREFIX, "AUTH").

-define(DUO_EXPIRE, 300).
-define(APP_EXPIRE, 3600).

-define(IKEY_LEN, 20).
-define(SKEY_LEN, 40).
-define(AKEY_LEN, 40).

-define(USER_ERR,
        "The username passed to sign_request/4 is invalid.").

-define(IKEY_ERR,
        "The Duo integration key passed to sign_request/4 is invalid.").

-define(SKEY_ERR,
        "The Duo secret key passed to sign_request/4 is invalid.").

-define(AKEY_ERR,
        io_lib:format(
          "The application secret key passed to sign_request/4 must be at least"
          " ~B characters.", [?AKEY_LEN])).

-define(UNKNOWN_ERR, "An unknown error occured.").


%%%%
% FOR TESTING
%%%%
-define(NOTEST, true).
-include_lib("eunit/include/eunit.hrl").

-ifdef(TEST).
-define(IKEY, "DIXXXXXXXXXXXXXXXXXX").
-define(WRONG_IKEY, "DIXXXXXXXXXXXXXXXXXY").
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
-endif.
