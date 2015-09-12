# Spamassassin-AttachHash
Plugin for spamassassin that makes an MD5 sum from attachments in an email for query against a DNSBL

Example

```
attachhashdnsbl EXAMPLE_ATTACHHASH  bl.example.com
body            EXAMPLE_ATTACHHASH  eval:check_attachhash('EXAMPLE_ATTACHHASH')
tflags          EXAMPLE_ATTACHHASH  net
score           EXAMPLE_ATTACHHASH  0.1
```
