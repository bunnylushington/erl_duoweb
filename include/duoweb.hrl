-define(DUO_PREFIX, "TX").
-define(APP_PREFIX, "APP").
-define(AUTH_PREFIX, "AUTH").

-define(DUO_EXPIRE, 300).
-define(APP_EXPIRE, 3600).

-define(IKEY_LEN, 20).
-define(SKEY_LEN, 40).
-define(AKEY_LEN, 40).

-define(USER_ERR,
        "The username passwed to sign_request/4 is invalid.").

-define(IKEY_ERR,
        "The Duo integration key passed to sign_request/4 is invalid.").

-define(SKEY_ERR,
        "The Duo secret key passed to sign_request/4 is invalid.").

-define(AKEY_ERR,
        io_lib:format(
          "The application secret key passed to sign_request/4 must be at least"
          " ~B characters.", [?AKEY_LEN])).

-define(UNKNOWN_ERR, "An unknown error occured.").
