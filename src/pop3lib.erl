-module(pop3lib).
-export([start_link/3, stop/1]).

%% https://tools.ietf.org/html/rfc1939

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/serv.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("mail/include/pop3lib.hrl").

-define(FILE_CHUNK_SIZE, 8192).

-record(state,
        {parent        :: pid(),
         options       :: #pop3lib_options{},
         listen_socket :: ssl:sslsocket(),
         acceptors     :: [pid()]}).

%% Exported: start_link

-spec start_link(
        inet:socket_address(), inet:port_number(), #pop3lib_options{}) ->
          serv:spawn_server_result().

start_link(IpAddress, Port, Options) ->
    ?spawn_server(
       fun(Parent) -> init(Parent, IpAddress, Port, Options) end,
       fun initial_message_handler/1).

%% Exported: stop

-spec stop(pid()) -> ok | {error, timeout}.

stop(Pid)  ->
    serv:call(Pid, stop).

%%
%% Server
%%

initial_message_handler(
  #state{
     options =
         #pop3lib_options{
            initial_servlet_state = InitialServletState,
            patch_initial_servlet_state = PatchInitialServletState} = Options} =
      State) ->
    case PatchInitialServletState of
        not_set ->
            {swap_message_handler, fun message_handler/1};
        _ ->
            PatchedServletState = PatchInitialServletState(InitialServletState),
            {swap_message_handler, fun message_handler/1,
             State#state{
               options = Options#pop3lib_options{
                           initial_servlet_state = PatchedServletState}}}
    end.

init(Parent, IpAddress, Port, Options) ->
    {ok, ListenSocket} =
        ssl:listen(Port,
                   [{active, false},
                    {ip, IpAddress},
                    {reuseaddr, true},
                    {packet, line},
                    {mode, binary},
                    %% https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices
                    %%{verify_type, verify_none},
                    {secure_renegotiate, true},
                    %%{versions, ['tlsv1.2']},
                    {honor_cipher_order, true},
                    %%{ciphers, "ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-ECDSA-AES128-SHA ECDHE-ECDSA-AES256-SHA ECDHE-ECDSA-AES128-SHA256 ECDHE-ECDSA-AES256-SHA384 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA ECDHE-RSA-AES128-SHA256 ECDHE-RSA-AES256-SHA384 DHE-RSA-AES128-GCM-SHA256 DHE-RSA-AES256-GCM-SHA384 DHE-RSA-AES128-SHA DHE-RSA-AES256-SHA DHE-RSA-AES128-SHA256 DHE-RSA-AES256-SHA256"},
                    {certfile, ?b2l(Options#pop3lib_options.cert_filename)},
                    {reuse_sessions, true}]),
    self() ! accepted,
    {ok, #state{parent = Parent,
                options = Options,
                listen_socket = ListenSocket,
                acceptors = []}}.

message_handler(
  #state{parent = Parent,
         options = Options,
         listen_socket = ListenSocket,
         acceptors = Acceptors} = State) ->
    receive
        {call, From, stop} ->
            ok = ssl:close(ListenSocket),
            {stop, From, ok};
        accepted ->
            Owner = self(),
            Pid =
                proc_lib:spawn_link(
                  fun() -> acceptor(Owner, Options, ListenSocket) end),
            {noreply, State#state{acceptors = [Pid|Acceptors]}};
        {system, From, Request} ->
            {system, From, Request};
        {'EXIT', Parent, Reason} ->
            ok = ssl:close(ListenSocket),
            exit(Reason);
        {'EXIT', Pid, normal} ->
            case lists:member(Pid, Acceptors) of
                true ->
                    {noreply,
                     State#state{acceptors = lists:delete(Pid, Acceptors)}};
                false ->
                    ?error_log({not_an_acceptor, Pid}),
                    noreply
            end;
        UnknownMessage ->
            ?error_log({unknown_message, UnknownMessage}),
            noreply
    end.

acceptor(Owner, #pop3lib_options{
                   greeting = Greeting,
                   initial_servlet_state = InitialServletState} = Options,
         ListenSocket) ->
    {ok, Socket} = ssl:transport_accept(ListenSocket),
    case ssl:handshake(Socket) of
        {ok, SSLSocket} ->
            Owner ! accepted,
            ok = send(SSLSocket, ok, Greeting),
            ok = read_lines(SSLSocket, Options,
                            #channel{mode = authorization,
                                     servlet_state = InitialServletState}),
            ssl:close(SSLSocket);
        {error, _Reason} ->
            Owner ! accepted
    end.

%%
%% Read lines
%%

read_lines(Socket, #pop3lib_options{timeout = Timeout} = Options, Channel) ->
    case ssl:recv(Socket, 0, Timeout) of
        {ok, Line} ->
            ?dbg_log({line, Line}),
            case handle_line(Socket, Options, Channel, Line) of
                #response{action = break,
                          status = Status,
                          info = Info} = Response ->
                    ?dbg_log({break, Response}),
                    ok = send(Socket, Status, Info);
                #response{action = continue,
                          status = Status,
                          info = Info,
                          body = Body,
                          channel = UpdatedChannel} = Response ->
                    ?dbg_log({continue, Response}),
                    case Body of
                        not_set ->
                            ok = send(Socket, Status, Info);
                        {file, Filename} ->
                            ok = send_file(Socket, Status, Filename);
                        {file, Filename, N} ->
                            ok = send_file(Socket, Status, Filename, N);
                        Lines when is_list(Lines) ->
                            ok = send_multi_lines(Socket, Status, Info, Lines)
                    end,
                    if
                        UpdatedChannel == not_set ->
                            read_lines(Socket, Options, Channel);
                        true ->
                            read_lines(Socket, Options, UpdatedChannel)
                    end
            end;
        {error, closed} ->
            ?dbg_log(socket_closed),
            ok;
        {error, timeout} ->
            ?dbg_log(socket_timeout),
            ok;
        {error, Reason} ->
            ?error_log({network_error, Reason}),
            ok
    end.

handle_line(_Socket, Options,
            #channel{mode = Mode, authorized = Authorized} = Channel, Line) ->
    [Command|Args] = string:lexemes(string:chomp(Line), " "),
    case string:uppercase(Command) of
        %% https://tools.ietf.org/html/rfc1939#page-6
        <<"STAT">> when Mode == transaction ->
            apply_servlet(stat, Options, Channel, Args);
        %% https://tools.ietf.org/html/rfc1939#page-6
        <<"LIST">> when Mode == transaction ->
            apply_servlet(list, Options, Channel, Args);
        %% https://tools.ietf.org/html/rfc1939#page-8
        <<"RETR">> when Mode == transaction ->
            apply_servlet(retr, Options, Channel, Args);
        %% https://tools.ietf.org/html/rfc1939#page-8
        <<"DELE">> when Mode == transaction ->
            apply_servlet(dele, Options, Channel, Args);
        %% https://tools.ietf.org/html/rfc1939#page-9
        <<"NOOP">> ->
            #response{};
        %% https://tools.ietf.org/html/rfc1939#page-10
        <<"RSET">> when Mode == transaction ->
            apply_servlet(rset, Options, Channel, Args);
        %% https://tools.ietf.org/html/rfc1939#page-5
        %% https://tools.ietf.org/html/rfc1939#page-10
        <<"QUIT">> ->
            apply_servlet(quit, Options, Channel, Args);
        %% https://tools.ietf.org/html/rfc1939#page-11
        <<"TOP">> when Mode == transaction ->
            apply_servlet(top, Options, Channel, Args);
        %% https://tools.ietf.org/html/rfc1939#page-11
        <<"UIDL">> when Mode == transaction ->
            apply_servlet(uidl, Options, Channel, Args);
        %% https://tools.ietf.org/html/rfc1939#page-13
        <<"USER">> when Mode == authorization andalso not Authorized ->
            apply_servlet(user, Options, Channel, Args);
        %% https://tools.ietf.org/html/rfc1939#page-14
        <<"PASS">> when Mode == password ->
            apply_servlet(pass, Options, Channel, Args);
        %% https://tools.ietf.org/html/rfc5034
        <<"CAPA">> ->
            apply_servlet(capa, Options, Channel, Line);
        %% https://tools.ietf.org/html/rfc5034
        <<"AUTH">> when Mode == authorization andalso not Authorized ->
            apply_servlet(auth, Options, Channel, Args);
        _ ->
            apply_servlet(any, Options, Channel, Line)
    end.

apply_servlet(Command, #pop3lib_options{servlets = Servlets}, Channel, Args) ->
    case lists:keysearch(Command, #servlet.command, Servlets) of
        {value, #servlet{handler = Handler}} ->
            Handler(Channel, Args);
        false ->
            case lists:keysearch(any, #servlet.command, Servlets) of
                {value, #servlet{handler = Handler}} ->
                    Handler(Channel, Args);
                false ->
                    #response{
                       status = err,
                       info = <<"bad command sequence or command not implemented">>}
            end
    end.

send_file(Socket, Status, Filename) ->
    ?dbg_log({file_send, Status, Filename}),
    ok = send(Socket, Status),
    {ok, File} = file:open(Filename, [read, binary]),
    send_file_chunks(Socket, File).

send_file_chunks(Socket, File) ->
    case file:read(File, ?FILE_CHUNK_SIZE) of
        {ok, Chunk} ->
            ?dbg_log({send_file_chunks, ok, Chunk}),
            ok = ssl:send(Socket, Chunk),
            send_file_chunks(Socket, File);
        eof ->
            ?dbg_log({send_file_chunks, eof}),
            ok = ssl:send(Socket, <<".\r\n">>),
            file:close(File);
        {error, Reason} ->
            ?error_log({chunk_failure, Reason}),
            file:close(File)
    end.

send_file(Socket, Status, Filename, N) ->
  ?dbg_log({file_send_lines, Status, Filename, N}),
  ok = send(Socket, Status),
  {ok, File} = file:open(Filename, [read, binary]),
  send_file_lines(Socket, File, headers, N).

send_file_lines(Socket, File, Mode, N) ->
    case file:read_line(File) of
        eof ->
            ok = ssl:send(Socket, <<".\r\n">>),
            file:close(File);
        {error, Reason} ->
            ?error_log({line_failure, Reason}),
            ok = ssl:send(Socket, <<".\r\n">>),
            file:close(File);
        _ when N == 0 ->
            ok = ssl:send(Socket, <<".\r\n">>),
            file:close(File);
        {ok, Line} when Mode == headers ->
            ok = ssl:send(Socket, Line),
            send_file_lines(Socket, File, Mode, N);
        {ok, <<"\r\n">>} when Mode == headers ->
            ok = ssl:send(Socket, <<"\r\n">>),
            send_file_lines(Socket, File, body, N);
        {ok, Line} when Mode == body ->
            ok = ssl:send(Socket, Line),
            send_file_lines(Socket, File, Mode, N - 1)
    end.

send(Socket, Status)  ->
    ?dbg_log({send, Status}),
    ssl:send(Socket, [format_status(Status), <<"\r\n">>]).

send(Socket, Status, not_set) ->
    send(Socket, Status);
send(Socket, Status, Info) ->
    ?dbg_log({send, Status, Info}),
    ssl:send(Socket, [format_status(Status), <<" ">>, Info, <<"\r\n">>]).

format_status(ok) -> <<"+OK">>;
format_status(err) -> <<"-ERR">>.

send_multi_lines(Socket, Status, Info, Lines) ->
  ?dbg_log({send_multi_lines, Status, Info, Lines}),
  send(Socket, Status, Info),
  send_multi_lines(Socket, Lines).

send_multi_lines(Socket, []) ->
    ok = ssl:send(Socket, <<".\r\n">>);
send_multi_lines(Socket, [Line|Rest]) ->
    ok = ssl:send(Socket, [Line, <<"\r\n">>]),
    send_multi_lines(Socket, Rest).
