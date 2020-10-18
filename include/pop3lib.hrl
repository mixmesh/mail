-ifndef(POP3LIB_HRL).
-define(POP3LIB_HRL, true).

-record(servlet,
        {command :: stat | list | retr | dele | rset | quit | top | uidl |
                    user | pass | capa | auth | any,
         handler :: fun()}).

-record(pop3lib_options,
        {cert_filename :: binary(),
         timeout :: timeout(),
         greeting :: binary(),
         initial_servlet_state :: any(),
         servlets :: [#servlet{}],
         patch_initial_servlet_state = not_set :: function() | not_set,
         temp_dir :: binary()}).

-record(channel,
        {mode :: authorization | password | transaction,
         authorized = false :: boolean(),
         servlet_state :: any()}).

-record(response,
        {action = continue :: break | continue,
         status = ok :: ok | err,
         info = not_set :: not_set | binary(),
         body = not_set :: not_set |
                           {file, binary()} |
                           {file, binary(), integer()} |
                           [binary()],
         channel = not_set :: not_set | #channel{}}).

-endif.
