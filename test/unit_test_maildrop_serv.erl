-module(unit_test_maildrop_serv).
-export([start/0]).

-include_lib("mail/include/maildrop_serv.hrl").

start() ->
    _ = file:delete("/tmp/file_index"),
    ok = file:write_file("/tmp/foo.dat", <<"bar">>),
    {ok, Pid} = maildrop_serv:start_link("/tmp"),
    ok = maildrop_serv:lock(Pid),
    {ok, _} = maildrop_serv:write(Pid, "/tmp/foo.dat"),
    1 = length(maildrop_serv:list(Pid)),
    {ok, _} = maildrop_serv:write(Pid, "/tmp/foo.dat"),
    {ok, _} = maildrop_serv:write(Pid, "/tmp/foo.dat"),
    {ok, #mail{message_number = MessageNumber}} =
        maildrop_serv:write(Pid, "/tmp/foo.dat"),
    {ok, #mail{message_number = MessageNumber}} =
        maildrop_serv:read(Pid, MessageNumber),
    4 = length(maildrop_serv:list(Pid)),
    ok = maildrop_serv:delete(Pid, 1),
    3 = length(maildrop_serv:list(Pid)),
    ok = maildrop_serv:undelete(Pid),
    4 = length(maildrop_serv:list(Pid)),
    ok = maildrop_serv:remove(Pid),
    ok = maildrop_serv:stop(Pid).
