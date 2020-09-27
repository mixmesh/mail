-ifndef(SMTPLIB_HRL).
-define(SMTPLIB_HRL, true).

-record(servlet,
        {command :: helo | ehlo | auth | mail | rcpt | data | rset | vrfy |
                    expn | help | quit | any,
         handler :: fun()}).

-record(smtplib_options,
        {timeout                               :: integer(),
         greeting                              :: binary(),
         authenticate                          :: yes | no,
         initial_servlet_state                 :: any(),
         servlets                              :: [#servlet{}],
         patch_initial_servlet_state = not_set :: fun() | not_set,
         temp_dir                              :: binary()}).

-record(data,
        {context = headers :: headers | letter,
         headers = []      :: [{Key :: binary(), Value :: binary()}],
         filename          :: binary(),
         fd                :: file:io_device(),
         size = 0          :: integer()}).

-record(channel,
        {mode :: init | helo | mail | rcpt,
         authenticated :: boolean(),
         data = not_initialized :: not_initialized | #data{},
         servlet_state :: any()}).

-record(response,
        {action = continue :: break | continue,
         status = 250 :: integer(),
         info = <<"OK">> :: binary(),
         replies = not_set ::  not_set | [binary()],
         channel = not_set ::  not_set | #channel{}}).

-endif.
