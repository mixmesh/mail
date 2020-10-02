-module(mail_util).
-export([get_arg/1, get_arg/4, strip_path/1, mktemp/1, mktemp/0]).

-include_lib("apptools/include/shorthand.hrl").

%% Exported: get_arg

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

%% Exported: strip_path

-spec strip_path(binary()) -> string().

strip_path(Path) ->
    string:strip(string:strip(?b2l(Path), left, $<), right, $>).

%% Exported: mktemp

-spec mktemp(binary()) -> binary().

mktemp(Dir) ->
  filename:join([Dir, ?i2b(erlang:unique_integer([positive]))]).

-spec mktemp() -> binary().

mktemp() ->
    ?i2b(erlang:unique_integer([positive])).
