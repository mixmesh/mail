-module(maildrop_serv).
-export([start_link/1, stop/1]).
-export([lock/1, unlock/1]).
-export([read/2, list/1, write/2]).
-export([delete/2, undelete/1, remove/1]).
-export([foldl/3]).
-export([strerror/1]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/serv.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("mail/include/maildrop.hrl").

-define(FILE_CHUNK_SIZE, 8192).

-record(state, {%% pid()
                parent,
                %% dirname()
                spooler_dir,
                %% tid()
                index,
                %% dets:tab_name()
                file_index,
                %% integer()
                next_message_number,
                %% pid() | none
                locker = none}).

-record(meta_info, {%% 0 (0 is reserved for meta info)
                    message_number = 0,
                    %% integer()
                    next_message_number = 1}).

%% Exported: start_link

start_link(SpoolerDir) ->
    ?spawn_server(fun(Parent) -> init(Parent, SpoolerDir) end,
                  fun message_handler/1).

%% Exported: stop

stop(Pid) ->
    Pid ! stop,
    ok.

%% Exported: lock

lock(Pid) ->
    serv:call(Pid, lock).

%% Exported: unlock

unlock(Pid) ->
  serv:call(Pid, unlock).

%% Exported: read

read(Pid, MessageNumber) ->
    serv:call(Pid, {read, MessageNumber}).

%% Exported: list

list(Pid) ->
    serv:call(Pid, list).

%% Exported: write

write(Pid, SourceFilename) ->
    serv:call(Pid, {write, SourceFilename}).

%% Exported: delete

delete(Pid, MessageNumber) ->
    serv:call(Pid, {delete, MessageNumber}).

%% Exported: undelete

undelete(Pid) ->
    serv:call(Pid, undelete).

%% Exported: remove

remove(Pid)  ->
    serv:call(Pid, remove).

%% Exported: foldl

foldl(Pid, Do, Acc) ->
    serv:call(Pid, {foldl, Do, Acc}).

%% Exported: strerror

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

init(Parent, SpoolerDir) ->
    case filelib:is_dir(SpoolerDir) of
        true ->
            KeyPosition = #mail.message_number,
            FileIndexFilename = filename:join([SpoolerDir, "file_index"]),
            case dets:open_file({file_index, self()},
                                [{file, FileIndexFilename},
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
                       system, "Maildrop server has been started: ~s",
                       [SpoolerDir]),
                    {ok, #state{parent = Parent,
                                spooler_dir = SpoolerDir,
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
                       spooler_dir = SpoolerDir,
                       index = Index,
                       file_index = FileIndex,
                       next_message_number = NextMessageNumber,
                       locker = Locker} = State) ->
  receive
      stop ->
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
              filename:join([SpoolerDir, ?i2b(NextMessageNumber)]),
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