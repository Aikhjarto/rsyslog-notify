# rsyslog-notify

Sends selected syslog messages in batches via XMPP
([go-sendxmpp](https://salsa.debian.org/mdosch/go-sendxmpp)) and optionally
by mail. rsyslog's `omprog` starts it once and writes every message to its
stdin; rsyslog-notify keeps the messages that pass its filters in a buffer
and sends the buffer

- after `max_lines` messages (default 20),
- `interval` seconds after the first buffered message (default 300),
- when rsyslog closes the pipe, and on SIGTERM or SIGINT,
- on SIGUSR1.

One XMPP message or mail per batch instead of one per line keeps a burst of
errors from flooding the phone.

## Filters

A message is forwarded if it

1. matches no `exclude` rule, and
2. matches an `include` rule, or has a severity selected by `priority`
   (like `journalctl -p`: `warning` is warning and worse, `err..notice` a
   range; default warning).

A rule is a set of regular expressions (Python `re.search`) on the fields
`host`, `program`, `facility` and `message`, all of which must match:

```yaml
include:
  - {program: '^sshd$', message: 'Accepted \S+ for root'}
exclude:
  - {host: '^printer', program: '^snmpd$'}
```

On the command line: `--include program=^sshd$`, `--exclude 'message=reset by peer'`
(one field per rule).

## Input

rsyslog-notify reads one message per line and recognizes

- `RSYSLOG_SyslogProtocol23Format` (RFC 5424), as in the example below,
- `<PRI>` lines with a BSD or RFC 3339 time stamp, such as
  `RSYSLOG_ForwardFormat`,
- `%jsonmesg%` (a template `"%jsonmesg%\n"`).

Lines it does not recognize have no severity and are forwarded only by an
`include` rule. With `--format text`, every line is such a line.

## rsyslog

`data/rsyslog-notify.conf`:

```
module(load="omprog")

action(type="omprog"
       name="rsyslog-notify"
       binary="/usr/bin/rsyslog-notify -C /etc/rsyslog-notify/config.yaml --confirm"
       template="RSYSLOG_SyslogProtocol23Format"
       confirmMessages="on"
       signalOnClose="on"
       closeTimeout="120000"
       output="/var/log/rsyslog-notify.log"
       queue.type="LinkedList"
       queue.size="10000"
       action.resumeRetryCount="-1")
```

- `confirmMessages="on"` with `--confirm`: rsyslog-notify answers `OK` to
  each message once it is in the buffer, so rsyslog knows it was taken.
- `signalOnClose` and `closeTimeout`: when rsyslog stops or restarts, it
  closes the pipe, sends SIGTERM, and waits up to two minutes before killing
  rsyslog-notify; meanwhile the buffer goes out.
- `output`: rsyslog-notify's error messages, e.g. when go-sendxmpp fails.
- The queue keeps rsyslog's other actions running while a batch is sent.

To spare rsyslog-notify the info and debug messages, wrap the action in
`if $syslogseverity <= 4 then { ... }`; then its `include` rules see only
what passes that filter.

omprog runs the program with rsyslog's privileges, usually root. The
go-sendxmpp configuration holds the XMPP password: make it readable by root
only.

## Delivery

If go-sendxmpp or the mail fails, the messages stay in the buffer and the
next attempt is after 30 seconds, then 60, 120 and so on up to an hour;
new messages are added meanwhile. XMPP and mail keep their own buffers, so
one failing does not resend to the other. A buffer holds at most
`max_buffer` messages (default 1000); beyond that the oldest are dropped,
and the next batch says how many. On exit, rsyslog-notify tries once more
and exits with 1 if that fails.

go-sendxmpp gets the batch on stdin, with the subject as its first line:

```
[rsyslog] web: 2 message(s)

2026-10-05 10:00:00 web nginx[42] err: upstream timed out
2026-10-05 10:00:01 web sshd[7] info: Accepted publickey for root from 10.0.0.5
```

Mail goes to an SMTP server on localhost:25 by default (postfix, exim), or
via `sendmail -t -oi` with `method: sendmail`.

## Usage

```sh
rsyslog-notify -C /etc/rsyslog-notify/config.yaml --confirm
rsyslog-notify --xmpp-to admin@example.org --xmpp-config /etc/rsyslog-notify/sendxmpp.conf -p err
```

| Option | Meaning |
|---|---|
| `-C`, `--config` | YAML configuration file, see `rsyslog-notify.yaml.example` |
| `-p`, `--priority` | Severities to forward (default: warning) |
| `--include`, `--exclude` | `FIELD=REGEX` rules; repeatable |
| `-n`, `--max-lines` | Send after this many messages (default: 20) |
| `-s`, `--interval` | Send this many seconds after the first buffered message (default: 300) |
| `--format` | `auto`, `json`, `syslog` or `text` (default: auto) |
| `--confirm` | Answer `OK` per message, for `confirmMessages="on"` |
| `--xmpp-to`, `--xmpp-config` | XMPP recipients (repeatable) and go-sendxmpp's configuration |
| `--mail-to` | Mail recipients; repeatable |

Exit status: 0, 1 if messages could not be sent at exit, 2 for an invalid
configuration.

## Requirements

- Python 3.7 or newer, PyYAML for a configuration file
- go-sendxmpp for XMPP; an MTA on localhost or `sendmail` for mail

## Tests

```sh
python3 -m unittest -v
```

They use a fake go-sendxmpp and SMTP server, and rsyslogd with omprog if it
is installed.

## License

GPL-2.0-or-later, see [LICENSE](LICENSE).
