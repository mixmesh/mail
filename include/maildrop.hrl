-ifndef(MAILDROP_HRL).
-define(MAILDROP_HRL, true).

-record(mail, {%% integer()
               message_number,
               %% integer()
               octets,
               %% filename()
               filename,
               %% binary()
               unique_id,
               %% boolean()
               deleted = false}).

-endif.
