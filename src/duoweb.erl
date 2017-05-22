%%%-------------------------------------------------------------------
%%% @author Bunny Lushington <bunny@bapi.us>
%%% @doc
%%% An Erlang port of Duo Security's DuoWeb Perl module.  
%%% @end
%%%-------------------------------------------------------------------

-module(duoweb).
-include("include/duoweb.hrl").

%% API exports
-export([ 
          sign_request/4
        , verify_response/4
        ]).


%%====================================================================
%% API functions
%%====================================================================

%% @doc
%% Generate a signed request for Duo authentication.
%%
%% The returned value should be passed into the Duo.init() call in the
%% rendered web page used for Duo authentication.
%%
%% @param IKey Duo integration key
%% @param SKey Duo secret key
%% @param AKey application secret key
%% @param Username primary-authenticated username
-spec sign_request(IKey :: string(),
                   SKey :: string(),
                   AKey :: string(),
                   Username :: string()) -> string().
sign_request(IKey, _, _, _) when IKey =/= ?IKEY_LEN -> 
  err(ikey);
sign_request(_, SKey, _, _) when SKey =/= ?SKEY_LEN -> 
  err(skey);
sign_request(_, _, AKey, _) when AKey < ?AKEY_LEN -> 
  err(akey);
sign_request(IKey, SKey, AKey, Username) -> 
  case is_valid_username(Username) of
    true -> 
      DuoSig = sign_vals(SKey, Username, IKey, ?DUO_PREFIX, ?DUO_EXPIRE),
      AppSig = sign_vals(AKey, Username, IKey, ?APP_PREFIX, ?APP_EXPIRE),
      string:join([DuoSig, AppSig], ":");
    false -> 
      err(user)
  end.

%% @doc 
%% Validate the signed response returned from Duo.
%% 
%% Returns the username of the authenticated user or 
%% an empty list if secondary authenication was denied.
%%
%% @param IKey Duo integration key
%% @param SKey Duo secret key
%% @param AKey application secret key
%% @param Response signed response posted to the server
-spec verify_response(IKey :: string(),
                      SKey :: string(),
                      AKey :: string(),
                      Response :: string()) -> string() | [].

verify_response(IKey, SKey, AKey, Response) -> 
  [AuthSig, AppSig] = re:split(Response, ":"),
  AuthUser = parse_vals(SKey, AuthSig, ?AUTH_PREFIX, IKey),
  AppUser =  parse_vals(AKey, AppSig,  ?APP_PREFIX,  IKey),
  case AppUser =:= AuthUser of
    true -> AuthUser;
    false -> []
  end.
  


%%====================================================================
%% Internal functions
%%====================================================================

sign_vals(Key, Username, IKey, Prefix, Expire) -> 
  Expiration = integer_to_list(epoch() + Expire),
  Data = base64:encode_to_string(pipe_join([Username, IKey, Expiration])),
  Payload = pipe_join(Prefix, Data),
  hex_hmac(Key, Payload).

parse_vals(Key, Response, Prefix, IKey) -> 
  [ResPrefix, ResPayload, ResSig] = pipe_split(Response),
  Sig = hex_hmac(key, pipe_join(ResPrefix, ResPayload)),
  [Username, ResIKey, Expires] = 
    pipe_split(base64:decode_to_string(ResPayload)),
  case (ResPrefix =:= Prefix
        andalso hex_hmac(Key, Sig) == hex_hmac(Key, ResSig)
        andalso ResIKey =:= IKey
        andalso Expires >= epoch()) of
    true -> Username;
    false -> []
  end.

hex_hmac(Key, Payload) -> 
  <<Mac:160/integer>> = crypto:hmac(sha, Key, Payload),
  lists:flatten(io_lib:format("~40.16.0b", [Mac])).

pipe_join(A, B) -> 
  pipe_join([A, B]).

pipe_join(StringList) -> 
  string:join(StringList, "|").

pipe_split(String) -> 
  re:split(String, "\\|").

is_valid_username(String) -> 
  case string:chr(String, "|") of
    0 -> true;
    _ -> false
  end.
  
epoch() ->
  {MS, S, _} = erlang:timestamp(),
  MS * 1000000 + S.

err(user) -> err_msg(?USER_ERR);
err(ikey) -> err_msg(?IKEY_ERR);
err(skey) -> err_msg(?SKEY_ERR);
err(akey) -> err_msg(?AKEY_ERR);
err(_)    -> err_msg(?UNKNOWN_ERR).

err_msg(Msg) -> 
  pipe_join("ERR", Msg).
