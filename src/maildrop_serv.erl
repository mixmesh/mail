-module(maildrop_serv).
-export([start_link/2, stop/1]).
-export([lock/1, unlock/1]).
-export([read/2, list/1, write/2]).
-export([delete/2, undelete/1, remove/1]).
-export([foldl/3]).
-export([strerror/1]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/serv.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("mail/include/maildrop_serv.hrl").

-define(FILE_CHUNK_SIZE, 8192).

-type message_number() :: integer().

-record(state, {parent :: pid(),
                spooler_dir :: binary(),
                index :: ets:tid(),
                file_index :: dets:tab_name(),
                next_message_number :: message_number(),
                locker = none :: pid() | none}).

-record(meta_info,
        {%% 0 is reserved for meta info
         message_number = 0      :: message_number(),
         next_message_number = 1 :: message_number()}).

%% Exported: start_link

-spec start_link(binary(), boolean()) -> serv:spawn_server_result().

start_link(Dir, true) ->
    ?spawn_server(fun(Parent) -> init(Parent, Dir) end,
                  fun message_handler/1);
start_link(Dir, false) ->
    ?spawn_server_opts(fun(Parent) -> init(Parent, Dir) end,
                       fun message_handler/1,
                       #serv_options{name = ?MODULE}).

%% Exported: stop

-spec stop(pid()) -> ok.

stop(Pid) ->
    serv:cast(Pid, stop).

%% Exported: lock

-spec lock(pid()) -> ok | {error, already_lock_owner | lock_already_taken}.

lock(Pid) ->
    serv:call(Pid, lock).

%% Exported: unlock

-spec unlock(pid()) -> ok | {error, not_locked | not_lock_owner}.

unlock(Pid) ->
  serv:call(Pid, unlock).

%% Exported: read

-spec read(pid(), message_number()) -> {ok, #mail{}} | {error, no_such_mail}.

read(Pid, MessageNumber) ->
    serv:call(Pid, {read, MessageNumber}).

%% Exported: list

-spec list(pid()) -> [#mail{}].

list(Pid) ->
    serv:call(Pid, list).

%% Exported: write

-spec write(pid(), binary()) -> {ok, #mail{}} | {error, inet:posix()}.

write(Pid, SourceFilename) ->
    serv:call(Pid, {write, SourceFilename}).

%% Exported: delete

-spec delete(pid(), message_number()) ->
                    ok | {error, no_such_mail | already_deleted}.

delete(Pid, MessageNumber) ->
    serv:call(Pid, {delete, MessageNumber}).

%% Exported: undelete

-spec undelete(pid()) -> ok.

undelete(Pid) ->
    serv:call(Pid, undelete).

%% Exported: remove

-spec remove(pid()) -> ok.

remove(Pid)  ->
    serv:call(Pid, remove).

%% Exported: foldl

-spec foldl(pid(), fun(), any()) -> any().

foldl(Pid, Do, Acc) ->
    serv:call(Pid, {foldl, Do, Acc}).

%% Exported: strerror

-spec strerror(any()) -> binary().

strerror({file_index_corrupt, FileIndexReason}) ->
    ?error_log({file_index_corrupt, FileIndexReason}),
    <<"maildrop file index is corrupt">>;
strerror(invalid_spooler_dir) ->
    <<"maildrop spooler directory is invalid">>;
strerror(already_lock_owner) ->
    <<"maildrop already locked by this session">>;
strerror(lock_already_taken) ->
    <<"maildrop locked by another session">>;
strerror(not_locked) ->
    <<"maildrop has not been locked">>;
strerror(not_lock_owner) ->
    <<"maildrop lock is not owned by this session">>;
strerror({posix, PosixReason}) ->
    ?l2b(file:format_error(PosixReason));
strerror(no_such_mail) ->
    <<"no such mail">>;
strerror(already_deleted) ->
    <<"mail has already been deleted">>;
strerror(Reason) ->
    ?error_log({unknown_error, Reason}),
    <<"internal error">>.

%%
%% Server
%%

init(Parent, Dir) ->
    case filelib:is_dir(Dir) of
        true ->
            KeyPosition = #mail.message_number,
            FileIndexFilename = filename:join([Dir, "file_index"]),
            case dets:open_file({file_index, self()},
                                [{file, ?b2l(FileIndexFilename)},
                                 {keypos, KeyPosition}]) of
                {ok, FileIndex} ->
                    NextMessageNumber =
                        case dets:lookup(FileIndex, 0) of
                            [] ->
                                MetaInfo = #meta_info{},
                                ok = dets:insert(FileIndex, MetaInfo),
                                MetaInfo#meta_info.next_message_number;
                            [MetaInfo] ->
                                MetaInfo#meta_info.next_message_number
                        end,
                    Index =
                        ets:new(index, [ordered_set, {keypos, KeyPosition}]),
                    true = ets:from_dets(Index, FileIndex),
                    %% Stored in #state{} for convenience
                    true = ets:delete(Index, 0),
                    ?daemon_tag_log(
                       system, "Maildrop server has been started: ~s", [Dir]),
                    {ok, #state{parent = Parent,
                                spooler_dir = Dir,
                                index = Index,
                                file_index = FileIndex,
                                next_message_number = NextMessageNumber}};
                {error, Reason} ->
                    {error, {file_index_corrupt, Reason}}
            end;
        false ->
            {error, invalid_spooler_dir}
    end.

message_handler(#state{parent = Parent,
                       spooler_dir = Dir,
                       index = Index,
                       file_index = FileIndex,
                       next_message_number = NextMessageNumber,
                       locker = Locker} = State) ->
  receive
      {cast, stop} ->
          dets:close(FileIndex),
          stop;
      %%
      %% Note: Calls to lock, unlock and write do not require a lock
      %%
      {call, {Pid, _Ref} = From, lock} ->
          case Locker of
              none ->
                  link(Pid),
                  ok = undelete_all(Index, FileIndex),
                  {reply, From, ok, State#state{locker = Pid}};
              Pid ->
                  {reply, From, {error, already_lock_owner}};
              _ ->
                  {reply, From, {error, lock_already_taken}}
          end;
      {call, {Pid, _Ref} = From, unlock} ->
          case Locker of
              Pid ->
                  unlink(Pid),
                  ok = remove_all(Index, FileIndex),
                  {reply, From, ok, State#state{locker = none}};
              none ->
                  {reply, From, {error, not_locked}};
              _ ->
                  {reply, From, {error, not_lock_owner}}
          end;
      {call, From, {write, SourceFilename}} ->
          TargetFilename =
              filename:join([Dir, ?i2b(NextMessageNumber)]),
          case file:copy(SourceFilename, TargetFilename) of
              {ok, Octets} ->
                  case compute_digest(TargetFilename) of
                      {ok, UniqueId} ->
                          Mail = #mail{message_number = NextMessageNumber,
                                       octets = Octets,
                                       filename = TargetFilename,
                                       unique_id = UniqueId},
                          true = ets:insert(Index, Mail),
                          ok = dets:insert(FileIndex, Mail),
                          UpcomingMessageNumber = NextMessageNumber + 1,
                          ok = dets:insert(
                                 FileIndex,
                                 #meta_info{
                                    next_message_number = UpcomingMessageNumber}),
                          {reply, From, {ok, Mail},
                           State#state{
                             next_message_number = UpcomingMessageNumber}};
                      {error, Reason} ->
                          _ = file:delete(TargetFilename),
                          {reply, From, {error, Reason}}
                  end;
              {error, Reason} ->
                  {reply, From, {error, {posix, Reason}}}
          end;
      {call, From, _Request} when Locker == none ->
          {reply, From, {error, not_locked}};
      {call, {Pid, _Ref} = From, _Request} when Pid /= Locker ->
          {reply, From, {error, not_lock_owner}};
      %%
      %% Note: All other calls require a lock
      %%
      {call, From, {read, MessageNumber}} ->
          case ets:lookup(Index, MessageNumber) of
              [] ->
                  {reply, From, {error, no_such_mail}};
              [Mail] ->
                  {reply, From, {ok, Mail}}
          end;
      {call, From, list} ->
          {reply, From, ets:foldl(fun(#mail{deleted = false} = Mail, Acc) ->
                                          [Mail|Acc];
                                     (_, Acc) ->
                                          Acc
                                  end, [], Index)};
      {call, From, {delete, MessageNumber}} ->
          case ets:lookup(Index, MessageNumber) of
              [] ->
                  {reply, From, {error, no_such_mail}};
              [#mail{deleted = true}] ->
                  {reply, From, {error, already_deleted}};
              [Mail] ->
                  DeletedMail = Mail#mail{deleted = true},
                  true = ets:insert(Index, DeletedMail),
                  ok = dets:insert(FileIndex, DeletedMail),
                  {reply, From, ok}
          end;
      {call, From, undelete} ->
          ok = undelete_all(Index, FileIndex),
          {reply, From, ok};
      {call, From, remove} ->
          ok = remove_all(Index, FileIndex),
          {reply, From, ok};
      {call, From, {foldl, Do, Acc}} ->
          {reply, From, ets:foldl(Do, Acc, Index)};
      {system, From, Request} ->
          {system, From, Request};
      {'EXIT', Locker, _Reason} ->
          ok = undelete_all(Index, FileIndex),
          {noreply, State#state{locker = none}};
      {'EXIT', Parent, Reason} ->
          dets:close(FileIndex),
          exit(Reason);
      UnknownMessage ->
          ?error_log({unknown_message, UnknownMessage}),
          noreply
  end.

compute_digest(Filename) ->
    {ok, File} = file:open(Filename, [read, binary]),
    compute_digest(File, erlang:md5_init()).

compute_digest(File, Context) ->
    case file:read(File, ?FILE_CHUNK_SIZE) of
        eof ->
            {ok, base64:encode(erlang:md5_final(Context))};
        {ok, Chunk} ->
            compute_digest(File, erlang:md5_update(Context, Chunk));
        {error, Reason} ->
            {error, {posix, Reason}}
    end.

undelete_all(Index, FileIndex) ->
    true = ets:foldl(
             fun(#mail{deleted = true} = Mail, true) ->
                     true = ets:insert(Index, Mail#mail{deleted = false});
                (_Mail, true) ->
                     true
             end, true, Index),
    true = dets:foldl(
             fun(#mail{deleted = true} = Mail, true) ->
                     ok == dets:insert(FileIndex,
                                       Mail#mail{deleted = false});
                (_Mail, true) ->
                     true
             end, true, FileIndex),
    ok.

remove_all(Index, FileIndex) ->
    true = ets:foldl(fun(#mail{deleted = true} = Mail, true) ->
                             ok == file:delete(Mail#mail.filename);
                        (_Mail, true) ->
                             true
                     end, true, Index),
    MailPattern =
        #mail{
           message_number = '_',
           octets = '_',
           filename = '_',
           unique_id = '_',
           deleted = true},
    true = ets:match_delete(Index, MailPattern),
    dets:match_delete(FileIndex, MailPattern).
