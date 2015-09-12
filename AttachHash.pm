package Mail::SpamAssassin::Plugin::AttachHash;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util;
use Digest::SHA qw(sha256_hex);
use Digest::MD5 qw(md5_hex);
use MIME::QuotedPrint;

use strict;
use warnings;
use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->set_config($mailsaobject->{conf});
  $self->register_eval_rule("check_attachhash");

  return $self;
}

sub dbg {
  Mail::SpamAssassin::Plugin::dbg ("AttachHash: @_");
}

sub set_config
{
  my ($self, $conf) = @_;
  my @cmds;

  push (@cmds, {
    setting => 'attachhashdnsbl',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }

      unless ($value =~ /^(\S+)\s+(\S+?)\.?$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      my $rulename = $1;
      my $zone = lc($2).'.';
      $self->{attachhashdnsbls}->{$rulename} = { zone=>$zone };
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub check_attachhash {
  return 0;
}

my %get_details = (
  'file' => sub {
    my ($self, $pms, $part) = @_;

    my $type = $part->{'type'} || 'base64';
    my $data = '';

    if ($type eq 'quoted-printable') {
      $data = decode_qp($data); # use QuotedPrint->decode_qp
    }
    else {
      $data = $part->decode();  # just use built in base64 decoder
    }

    my $md5 = '';
    $md5 = md5_hex($data) if $data;
    $pms->{attachhash_hashes}->{$md5} = 1;
  },
);

sub parsed_metadata {
  my ($self, $opts) = @_;

  my $pms = $opts->{permsgstatus};
  my $conf = $pms->{main}->{conf};

  unless (keys %{$conf->{attachhashdnsbls}}) {
    dbg("no attachhashdnsbls configured");
    return;
  }

  unless ($pms->is_dns_available()) {
    dbg("DNS not available");
    return;
  }

  $pms->{attachhashdnsbl_active_rules} = {};

  foreach my $rulename (keys %{$pms->{conf}->{attachhashdnsbls}}) {
    next unless $pms->{conf}->is_rule_active('body_evals', $rulename);
    $pms->{attachhashdnsbl_active_rules}->{$rulename} = 1;
  }

  return unless scalar keys %{$pms->{attachhashdnsbl_active_rules}};

  foreach my $p ($pms->{msg}->find_parts(qr/./, 1)) {
    my ($ctype, $boundary, $charset, $name) =
      Mail::SpamAssassin::Util::parse_content_type($p->get_header('content-type'));

    $name = lc($name || '');

    my $cte = lc($p->get_header('content-transfer-encoding') || '');
    $ctype = lc $ctype;

    next if ($ctype =~ /text\//);

    dbg("Found attachment with name $name of type $ctype ");

    my $type = 'file';

    next unless ($cte =~ /^(?:base64|quoted\-printable)$/);

    if ($type && exists $get_details{$type}) {
       $get_details{$type}->($self, $pms, $p);
    }

  }

  foreach my $rulename (keys %{$pms->{attachhashdnsbl_active_rules}}) {
    my $zone = $pms->{conf}->{attachhashdnsbls}->{$rulename}->{zone};
    foreach my $hash (keys %{$pms->{attachhash_hashes}}) {
      my $key = "ATTACHHASH:$zone:$hash";
      my $id = $pms->{main}->{resolver}->bgsend($hash.'.'.$zone, 'A', undef, sub {
        my ($pkt, $id, $timestamp) = @_;
        $pms->{async}->set_response_packet($id, $pkt, $key, $timestamp);
        $self->process_dns_result($pms, $pkt, $rulename, $zone, $hash);
      });

      my $ent = { key=>$key, id=>$id, type=>'ATTACHHASH-A', zone=>$zone };
      $pms->{async}->start_lookup($ent);
      $pms->register_async_rule_start($rulename);
    
    }

  }

}

sub process_dns_result
{
    my ($self, $pms, $response, $rulename, $zone, $hash) = @_;

    foreach my $rr ($response->answer) {
        next unless $rr->type eq 'A';
        next unless $rr->address =~ /^127\./;
        dbg("got hit at $zone for $hash ($rr->{address})");
        $pms->got_hit($rulename);
        $pms->register_async_rule_finish($rulename);
    }
}

1;
