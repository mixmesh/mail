-ifndef(MAILDROP_HRL).
-define(MAILDROP_HRL, true).

-record(mail, {message_number :: integer() | '_',
               octets :: integer() | '_',
               filename :: binary() | '_',
               unique_id :: binary() | '_',
               deleted = false :: boolean()}).

-endif.
