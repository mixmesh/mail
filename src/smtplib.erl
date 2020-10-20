-module(smtplib).
-export([start_link/3, stop/1]).

%% https://tools.ietf.org/html/rfc2821
%% https://tools.ietf.org/html/rfc5321

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/serv.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("mail/include/smtplib.hrl").

-record(state,
        {parent ::  pid(),
         options :: #smtplib_options{},
         listen_socket :: ssl:sslsocket(),
         acceptors :: [pid()]}).

%% Exported: start_link

-spec start_link(
        inet:socket_address(), inet:port_number(), #smtplib_options{}) ->
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
         #smtplib_options{
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
               options = Options#smtplib_options{
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
                    {certfile, ?b2l(Options#smtplib_options.cert_filename)},
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

acceptor(Owner, #smtplib_options{
                   greeting = Greeting,
                   authenticate = Authenticate,
                   initial_servlet_state = InitialServletState} = Options,
         ListenSocket) ->
    {ok, Socket} = ssl:transport_accept(ListenSocket),
    case ssl:handshake(Socket) of
        {ok, SSLSocket} ->
            Owner ! accepted,
            ok = send(SSLSocket, 220, Greeting),
            Authenticated = (Authenticate == no),
            read_lines(SSLSocket, Options,
                       #channel{mode = init,
                                authenticated = Authenticated,
                                servlet_state = InitialServletState}),
            ssl:close(SSLSocket);
        {error, _Reason} ->
            Owner ! accepted
    end.

%%
%% Read lines
%%

read_lines(Socket, #smtplib_options{timeout = Timeout} = Options, Channel) ->
    case ssl:recv(Socket, 0, Timeout) of
        {ok, Line} ->
            ?dbg_log({line, Line}),
            case handle_line(Socket, Options, Channel, Line) of
                {data, UpdatedChannel} ->
                    ?dbg_log(data),
                    read_lines(Socket, Options, UpdatedChannel);
                #response{action = break,
                          status = Status,
                          info = Info} = Response ->
                    ?dbg_log({break, Response}),
                    ok = send(Socket, Status, Info);
                #response{
                   action = continue,
                   status = Status,
                   info = Info,
                   replies = Replies,
                   channel = UpdatedChannel} =  Response ->
                    ?dbg_log({continue, Response}),
                    if
                        Replies == not_set ->
                            ok = send(Socket, Status, Info);
                        true ->
                            ok = send(Socket, Replies)
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

handle_line(_Socket, _Options, #channel{mode = Mode}, Line)
  when Mode /= data andalso Line == <<"\r\n">> ->
    #response{};
handle_line(_Socket, #smtplib_options{temp_dir = TempDir} = Options,
            #channel{mode = Mode,
                     authenticated = Authenticated,
                     data = Data} = Channel, Line)
  when Mode /= data ->
    [Command|Args] = string:lexemes(string:chomp(Line), " "),
    case string:uppercase(Command) of
        %% https://tools.ietf.org/html/rfc2821#section-4.1.1.1
        <<"HELO">> ->
            case apply_servlet(helo, Options, Channel, Args) of
                #response{
                   channel = #channel{mode = helo} = NewChannel} = Response ->
                    Response#response{
                      channel = NewChannel#channel{
                                  data = reset_data(TempDir, Data)}};
                Response ->
                    Response
            end;
        %% https://tools.ietf.org/html/rfc2821#section-4.1.1.1
        <<"EHLO">> ->
            case apply_servlet(ehlo, Options, Channel, Args) of
                #response{
                   channel = #channel{mode = helo} = NewChannel} = Response ->
                    Response#response{
                      channel = NewChannel#channel{
                                  data = reset_data(TempDir, Data)}};
                Response ->
                    Response
            end;
        %% https://tools.ietf.org/html/rfc4954
        <<"AUTH">> ->
            if
                Mode /= helo orelse Authenticated ->
                    #response{status = 503, info = <<"bad command sequence">>};
                true ->
                    apply_servlet(auth, Options, Channel, Args)
            end;
        _ when not Authenticated andalso Mode /= helo andalso Mode /= auth ->
            #response{status = 503, info = <<"authentication required">>};
        %% https://tools.ietf.org/html/rfc2821#section-4.1.1.2
        <<"MAIL">> when Mode /= helo ->
            #response{status = 503, info = <<"bad command sequence">>};
        <<"MAIL">> ->
            case apply_servlet(mail, Options, Channel, Args) of
                #response{
                   channel = #channel{mode = mail} = NewChannel} = Response ->
                    Response#response{
                      channel = NewChannel#channel{
                                  data = reset_data(TempDir, Data)}};
                Response ->
                    Response
            end;
        %% https://tools.ietf.org/html/rfc2821#section-4.1.1.3
        <<"RCPT">> when Mode /= mail andalso Mode /= rcpt ->
            #response{status = 503, info = <<"bad command sequence">>};
        <<"RCPT">> ->
            apply_servlet(rcpt, Options, Channel, Args);
        %% https://tools.ietf.org/html/rfc2821#section-4.1.1.4
        <<"DATA">> when Mode /= rcpt ->
            #response{status = 503, info = <<"bad command sequence">>};
        <<"DATA">> ->
            #response{
               status = 354,
               info = <<"OK, Enter data, terminated with \\r\\n.\\r\\n">>,
               channel =
                   Channel#channel{mode = data,
                                    data = reset_data(TempDir, Data)}};
        %% https://tools.ietf.org/html/rfc2821#section-4.1.1.5
        <<"RSET">> ->
            case apply_servlet(rset, Options, Channel, Args) of
                #response{
                   channel = #channel{mode = helo} = NewChannel} =  Response ->
                    Response#response{
                      channel = NewChannel#channel{
                                  data = reset_data(TempDir, Data)}};
                Response ->
                    Response
            end;
        %% https://tools.ietf.org/html/rfc2821#section-4.1.1.6
        <<"VRFY">> ->
            apply_servlet(vrfy, Options, Channel, Args);
        %% https://tools.ietf.org/html/rfc2821#section-4.1.1.7
        <<"EXPN">> ->
            apply_servlet(expn, Options, Channel, Args);
        %% https://tools.ietf.org/html/rfc2821#section-4.1.1.8
        <<"HELP">> ->
            apply_servlet(help, Options, Channel, Args);
        %% https://tools.ietf.org/html/rfc2821#section-4.1.1.9
        <<"NOOP">> ->
            #response{};
        %% https://tools.ietf.org/html/rfc2821#section-4.1.1.10
        <<"QUIT">> ->
            apply_servlet(quit, Options, Channel, Args);
        _ ->
            apply_servlet(any, Options, Channel, Line)
    end;
handle_line(_Socket, #smtplib_options{temp_dir = TempDir} = Options,
            #channel{data = Data} = Channel, Line) when Line == <<".\r\n">> ->
    ?dbg_log({'DATA', Data}),
    case apply_servlet(data, Options, Channel, Data)  of
        #response{channel = #channel{mode = helo} = Channel} = Response ->
            Response#response{channel = Channel#channel{
                                          data = reset_data(TempDir, Data)}};
        Response ->
            Response
    end;
handle_line(_Socket, _Options, #channel{data = Data} = Channel, Line) ->
    case {Line, Data} of
        {<<"\r\n">>, #data{fd = Fd, size = Size}} ->
            ok = file:write(Fd, <<"\r\n">>),
            {data, Channel#channel{
                     data = Data#data{context = letter, size = Size + 2}}};
        {_, #data{context = Context, headers = Headers, fd = Fd, size = Size}}
          when Context == headers ->
            case string:prefix(Line, " ") of
                nomatch ->
                    %% https://tools.ietf.org/html/rfc2822#section-2.2
                    case string:split(Line, ":") of
                        [Name, Value] ->
                            CanonicalName = string:uppercase(string:trim(Name)),
                            CanonicalValue = string:trim(Value),
                            ok = file:write(Fd, Line),
                            {data,
                             Channel#channel{
                               data = Data#data{
                                        headers = [{CanonicalName,
                                                    CanonicalValue}|Headers],
                                        size = Size + size(Line)}}};
                        _ ->
                            %% FIXME: Support multiple part messages
                            %% ala https://www.w3.org/Protocols/rfc1341/7_2_Multipart.html
                            ?error_log({invalid_header, Line}),
                            ok = file:write(Fd, Line),
                            {data, Channel#channel{
                                     data = Data#data{size = Size + size(Line)}}}
                    end;
                _ ->
                    %% https://tools.ietf.org/html/rfc2822#section-2.2.3
                    [{Name, Value}|RemainingHeaders] = Headers,
                    ok = file:write(Fd, Line),
                    {data, Channel#channel{
                             data = Data#data{
                                      headers = [{Name, ?l2b([Value, Line])}|
                                                 RemainingHeaders],
                                      size = Size + size(Line)}}}
            end;
        {_, #data{context = Context, fd = Fd, size = Size}}
          when Context == letter ->
            ok = file:write(Fd, Line),
            {data, Channel#channel{data = Data#data{size = Size + size(Line)}}}
    end.

reset_data(_TempDir, #data{size = 0} = Data) ->
    Data;
reset_data(TempDir, #data{filename = Filename,
                          fd = Fd,
                          size = Size}) when Size /= 0 ->
    _ = file:close(Fd),
    _ = file:delete(Filename),
    create_data(TempDir);
reset_data(TempDir, not_initialized) ->
    create_data(TempDir).

create_data(TempDir) ->
    Filename = mail_util:mktemp(TempDir),
    {ok, Fd} = file:open(Filename, [write, binary]),
    #data{filename = Filename, fd = Fd}.

apply_servlet(Command, #smtplib_options{servlets = Servlets},
              Channel, Args) ->
    case lists:keysearch(Command, #servlet.command, Servlets) of
        {value, #servlet{handler = Handler}} ->
            Handler(Channel, Args);
        false ->
            case lists:keysearch(any, #servlet.command, Servlets) of
                {value, #servlet{handler = Handler}} ->
                    Handler(Channel, Args);
                false ->
                    #response{status = 502,
                              info = <<"command is not implemented">>}
            end
    end.

send(Socket, Status, Info) ->
  ?dbg_log({send, Status, Info}),
  if
      Info == not_set ->
          ssl:send(Socket, [?i2b(Status), <<"\r\n">>]);
      true ->
          ssl:send(
            Socket, [?i2b(Status), <<" ">>, Info, <<"\r\n">>])
  end.

send(Socket, Replies) ->
    ?dbg_log({send_many, Replies}),
    ssl:send(Socket, format_many_replies(Replies)).

format_many_replies(Replies) ->
    case Replies of
        [{Status, Info}] ->
            [?i2b(Status), <<" ">>, Info, <<"\r\n">>];
        [{Status, Info}|Rest] ->
            [?i2b(Status), <<"-">>, Info, <<"\r\n">>, format_many_replies(Rest)]
    end.
