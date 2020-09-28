# Mail server support tools 

A mail storage server and plugin based libraries to build POP3 and
SMTP servers. Examples can be found in ./player/src/smtp_proxy_serv.erl
and ./player/src/pop3_proxy_serv.erl.

## Files

<dl>
  <dt>./src/pop3lib.erl</dt>
  <dd>Library which can be used when writing POP3 servers</dd>
  <dt>./src/smtplib.erl</dt>
  <dd>Library which can be used when writing SMTP servers</dd>
  <dt>./src/mail_util.erl</dt>
  <dd>Common code used by the POP3 and SMTP libraries</dd>
  <dt>./src/maildrop_serv.erl</dt>
  <dd>Mail storage suitable for servers built with the POP3 and SMTP libraries</dd>
</dl>

## Unit testing

```
$ ../obscrete/bin/unit_test --config ../obscrete/etc/obscrete-no-players.conf maildrop_serv
```
