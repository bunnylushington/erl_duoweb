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
sign_request(IKey, _, _, _) when 
    not is_list(IKey) orelse length(IKey) =/= ?IKEY_LEN -> err(ikey);
sign_request(_, SKey, _, _) when 
    not is_list(SKey) orelse length(SKey) =/= ?SKEY_LEN -> err(skey);
sign_request(_, _, AKey, _) when 
    not is_list(AKey) orelse length(AKey) < ?AKEY_LEN -> err(akey);
sign_request(_, _, _, User) when 
    not is_list(User) orelse length(User) =:= 0 -> err(user);
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
  [AuthSig, AppSig] = re:split(Response, ":", [{return,list}]),
  AuthUser = parse_vals(SKey, AuthSig, ?AUTH_PREFIX, IKey),
  AppUser =  parse_vals(AKey, AppSig,  ?APP_PREFIX,  IKey),
  case AppUser =:= AuthUser of
    true ->  AuthUser;
    false -> []
  end.
  



%%====================================================================
%% Internal functions
%%====================================================================

sign_vals(Key, Username, IKey, Prefix, Expire) -> 
  Expiration = integer_to_list(epoch() + Expire),
  Data = base64:encode_to_string(pipe_join([Username, IKey, Expiration])),
  Payload = pipe_join(Prefix, Data),
  Sig = hex_hmac(Key, Payload),
  pipe_join([Prefix, Data, Sig]).

parse_vals(Key, Response, Prefix, IKey) -> 
  confirm_vals(Key, pipe_split(Response), Prefix, IKey).

confirm_vals(Key, [ResPrefix, ResPayload, ResSig], Prefix, IKey) -> 
  Sig = hex_hmac(Key, pipe_join(ResPrefix, ResPayload)),
  [Username, ResIKey, Expires] = 
    try pipe_split(base64:decode_to_string(ResPayload)) of
        [U, R, E] -> [U, R, E];
        _ -> [ [], [], [] ]
    catch
      _:_ -> [ [], [], [] ]
    end,
  case (ResPrefix =:= Prefix
        andalso hex_hmac(Key, Sig) == hex_hmac(Key, ResSig)
        andalso ResIKey =:= IKey
        andalso list_to_integer(Expires) >= epoch()) of
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
  re:split(String, "\\|", [{return,list}]).

is_valid_username(String) -> 
  case string:chr(String, $|) of
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

err_msg(Msg) -> pipe_join("ERR", Msg).



%%====================================================================
%% Test functions
%%====================================================================
-ifdef(TEST).

split_token(T) -> re:split(T, ":", [{return,list}]).
join_token(A, B) -> string:join([A, B], ":").

invalid_sign_request_test_() -> 
  [ 
    ?_assertEqual(sign_request(?IKEY, ?SKEY, ?AKEY, ""), err(user)) 
  , ?_assertEqual(sign_request(?IKEY, ?SKEY, ?AKEY, xx), err(user)) 
  , ?_assertEqual(sign_request(?IKEY, ?SKEY, ?AKEY, "in|valid"), err(user)) 
  , ?_assertEqual(sign_request("invalid", ?SKEY, ?AKEY, ?USER), err(ikey))
  , ?_assertEqual(sign_request(invalid, ?SKEY, ?AKEY, ?USER), err(ikey))
  , ?_assertEqual(sign_request(?IKEY, "invalid", ?AKEY, ?USER), err(skey))
  , ?_assertEqual(sign_request(?IKEY, invalid, ?AKEY, ?USER), err(skey))
  , ?_assertEqual(sign_request(?IKEY, ?SKEY, "invalid", ?USER), err(akey))
  , ?_assertEqual(sign_request(?IKEY, ?SKEY, invalid, ?USER), err(akey))
  ].

valid_sign_request_test_() ->
  [A, B] = split_token(sign_request(?IKEY, ?SKEY, ?AKEY, ?USER)),
  [ 
    ?_assert(length(A) > 0)
  , ?_assert(length(B) > 0) 
  ].

verify_test_() ->
  BadKey = string:copies("XY", 20),
  [_, Invalid] = split_token(sign_request(?IKEY, ?SKEY, BadKey, ?USER)),
  [_, Valid]   = split_token(sign_request(?IKEY, ?SKEY, ?AKEY, ?USER)),
  [ 
    ?_assertEqual([], verify_response(?IKEY, ?SKEY, ?AKEY, 
                                      join_token(?INVALID_RESPONSE, Valid)))
    
  , ?_assertEqual([], verify_response(?IKEY, ?SKEY, ?AKEY,
                                      join_token(?EXPIRED_RESPONSE, Valid)))

  , ?_assertEqual([], verify_response(?IKEY, ?SKEY, ?AKEY,
                                      join_token(?FUTURE_RESPONSE, Invalid)))

  , ?_assertEqual(?USER, verify_response(?IKEY, ?SKEY, ?AKEY,
                                         join_token(?FUTURE_RESPONSE, Valid)))

  , ?_assertEqual([], verify_response(?IKEY, ?SKEY, ?AKEY,
                                      join_token(?FUTURE_RESPONSE, 
                                                 ?WRONG_PARAMS_APP)))
   
  , ?_assertEqual([], verify_response(?IKEY, ?SKEY, ?AKEY, 
                                      join_token(?WRONG_PARAMS_RESPONSE,
                                                 Valid)))

  , ?_assertEqual([], verify_response(?WRONG_IKEY, ?SKEY, ?AKEY,
                                      join_token(?FUTURE_RESPONSE, Valid)))
  ].

-endif.


