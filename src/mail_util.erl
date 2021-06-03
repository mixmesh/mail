-module(mail_util).
-export([get_arg/1, get_arg/4,
         strip_path/1,
         mktemp/1, mktemp/0,
         inject_headers/2,
         inject_footer/2]).

-include_lib("apptools/include/shorthand.hrl").

%%
%% Exported: get_arg
%%

-type type() :: none | integer | fun().
-spec get_arg(binary(), [string:grapheme_cluster()], type(), [binary()]) ->
                     {ok, any(), [binary()]} |
                     {error, no_arguments | bad_value | syntax_error}.

get_arg([]) ->
    {error, no_arguments};
get_arg([Arg|Rest]) ->
    {ok, string:uppercase(Arg), Rest}.

get_arg(_Keyword, _Separator, _Type, []) ->
    {error, no_arguments};
get_arg(Keyword, Separator, Type, [Arg|Rest]) ->
    case string:lexemes(Arg, Separator) of
        [Name, Value] ->
            case string:uppercase(Name) of
                Keyword ->
                    case Type of
                        none ->
                            {ok, Value, Rest};
                        integer ->
                            try
                                {ok, ?b2i(Value), Rest}
                            catch
                                _ ->
                                    {error, bad_value}
                            end;
                        Do when is_function(Do) ->
                            try
                                {ok, Do(Value), Rest}
                            catch
                                _ ->
                                    {error, bad_value}
                            end
                    end;
                _ ->
                    get_arg(Keyword, Separator, Type, Rest)
            end;
        _ ->
            {error, syntax_error}
    end.

%%
%% Exported: strip_path
%%

-spec strip_path(binary()) -> string().

strip_path(Path) ->
    string:strip(string:strip(?b2l(Path), left, $<), right, $>).

%%
%% Exported: mktemp
%%

-spec mktemp(binary()) -> binary().

mktemp(Dir) ->
  filename:join([Dir, ?i2b(erlang:unique_integer([positive]))]).

-spec mktemp() -> binary().

mktemp() ->
    ?i2b(erlang:unique_integer([positive])).

%%
%% Exported: inject_headers
%%

inject_headers(Mail, []) ->
    Mail;
inject_headers(Mail, NewHeaders) ->
    case binary:split(Mail, <<"\r\n\r\n">>) of
        [Headers, Body] ->
            ?l2b([Headers, <<"\r\n">>,
                  lists:map(fun({Name, Value}) ->
                                    [Name, <<": ">>, Value, <<"\r\n">>]
                            end, NewHeaders),
                  <<"\r\n">>,
                  Body]);
        _ ->
            Mail
    end.

%%
%% Exported: inject_footer
%%

inject_footer(Mail, Footer) ->
    case binary:split(Mail, <<"\r\n\r\n">>) of
        [Headers, Body] ->
            case is_plain_text(Headers) of
                yes ->
                    ?l2b([Headers, <<"\r\n\r\n">>,
                          string:trim(Body, trailing),
                          Footer, <<"\r\n">>]);
                no ->
                    Mail
            end;
        [_] ->
            Mail
    end.

is_plain_text(Headers) ->
    case binary:match(Headers, <<"Content-Type: text/plain">>) of
        {_Start, _Length} ->
            yes;
        nomatch ->
            case binary:match(Headers, <<"Content-Type:">>) of
                nomatch ->
                    yes;
                _ ->
                    no
            end
    end.
