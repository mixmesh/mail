%% -*- erlang -*-
{application, mail,
 [{description, "Mail server support tools"},
  {vsn, "1.0"},
  {modules, [maildrop_serv, mail_util, pop3lib, smtplib]},
  {registered, []},
  {applications, [kernel, stdlib]}
]}.
