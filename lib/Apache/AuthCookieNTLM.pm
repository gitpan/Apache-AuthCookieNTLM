package Apache::AuthCookieNTLM;

# Small wrapper to Apache::AuthenNTLM to store user login details to cookie
# and reduce the number of PDC requests

use strict;
use Data::Dumper;
use Apache::Constants ':common';

use Apache::Request;
use Apache::Cookie;
use Apache::AuthenNTLM;
use base ('Apache::AuthenNTLM');

use vars qw($VERSION);
$VERSION = 0.03;

my $cookie_values = {};

sub handler ($$) {
	my ($self,$r) = @_;
	
	# Get auth type and name
	my ($auth_type, $auth_name) = ($r->auth_type, $r->auth_name);

	# Get server config
	my %config;
	foreach my $var ( qw(Expires Path Domain Secure Name) ) {
		$config{lc($var)} = $r->dir_config("$auth_name$var") || undef;
	}
	
	my $debug = $r->dir_config('ntlmdebug') || 0;
		
	# Set cookie name
	my $cname = $config{name} || $auth_type . '_' . $auth_name;
	print STDERR "AuthCookieNTLM - Cookie Name: $cname\n" if $debug > 0;
	
	# Look for cookie
	my $t = Apache::Request->new($self);
	my %cookiejar = Apache::Cookie->new($t)->parse;
	print STDERR "AuthCookieNTLM - Cookies found: " . Dumper(\%cookiejar) if $debug > 0;
	
	unless ( defined $cookiejar{$cname} ) {
		# Don't have the cookie, try authenticate
		my $v = Apache::AuthenNTLM::handler ($self, $r);
				
		if ($v == 0 && $cookie_values ne {}) {	
			# Set the cookie as we have user details
			my $cookie = Apache::Cookie->new($r,
				-name		=> $cname,
				-value		=> $cookie_values,
				-path		=> $config{'path'}	|| "/",
				);
			$cookie->expires($config{'expires'}) if defined $config{'expires'};
			$cookie->domain($config{'domain'}) if defined $config{'domain'};
			$cookie->secure('1') if defined $config{'secure'};
			
			# Set the cookie to header
			$r->header_out('Set-Cookie' => $cookie->bake());

			if($debug > 0) {
				print STDERR "AuthCookieNTLM - Setting Cookie values: " . Dumper($cookie_values) . "\n" if $debug > 0;
			}			
		}
		# AuthenNTLM loops so have to behave like it does
		# and return $v
		return $v;
	} elsif($debug > 0) {
		print STDERR "AuthCookieNTLM - Found Cookies\n";	
	}
	
	return OK;
}

# This is the method which others could overload to
# set what ever values they want.
sub choose_cookie_values {
	my $self = shift;
	
	# Save to global
	if ($cookie_values eq {} || $cookie_values->{username} ne $self->{username}) {
		$cookie_values->{username} = $self->{username};
		$cookie_values->{'test'} = '123';
	}
}

# Overloaded to allow us to call choose_cookie_values
# and get access to the object.
sub map_user {
    my ($self, $r) = @_ ;
	
	$self->choose_cookie_values();
	
    return lc("$self->{userdomain}\\$self->{username}") ;
}


1;

__END__

=head1 NAME

Apache::AuthCookieNTLM - NTLM (Windows domain) authentication with cookies

=head1 SYNOPSIS

'WhatEver' should be replaced with the AuthName you choose
for this location's authentication.

    <Location />
        PerlAuthenHandler Apache::AuthCookieNTLM

        # NTLM CONFIG
        AuthType ntlm,basic
        AuthName WhatEver
        require valid-user

        #                   domain          pdc               bdc
        PerlAddVar ntdomain "name_domain1   name_of_pdc1"
        PerlAddVar ntdomain "other_domain   pdc_for_domain    bdc_for_domain"

        PerlSetVar defaultdomain default_domain
        PerlSetVar ntlmdebug 1

        # COOKIE CONFIG - all are optional and have defaults
        PerlSetVar WhatEverName cookie_name
        PerlSetVar WhatEverExpires +5h
        PerlSetVar WhatEverPath /
        PerlSetVar WhatEverDomain yourdomain.com
        PerlSetVar WhatEverSecure 1
    </Location>


=head1 DESCRIPTION

As explained in the Apache::AuthenNTLM module, depending on the user's 
config, IE will supply your Windows logon credentials to the web server
when the server asks for NTLM authentication. This saves the user typing in
their windows login and password. 

Apache::AuthCookieNTLM is an interface to Shannon Peevey's 
Apache::AuthenNTLM module. The main aim is to authenticate a user 
using their Windows login and authenticating against the Windows
PDC, but to also store their login name into a cookie. This means
that it can be accessed from other pages and stops the system
having to authenticate for every request.

We did consider using Apache::AuthCookie to store the details in a 
cookie but since using NTLM is so that one can remove the need
to login and is almost exclusively for intranets (as it needs access
to the PDC), we decided it was feasible not to use it.

=head1 APACHE CONFIGURATION

Please consult the Apache::AuthenNTLM documentation for more details on 
the NTLM configuration.

'WhatEver' should be replaced with the AuthName you choose
for this location's authentication.

=head2 PerlSetVar WhatEverName

Sets the cookie name. This will default to 
Apache::AuthCookieNTLM_WhatEver.

=head2 PerlSetVar WhatEverExpires 

Sets the cookie expiry time. This defaults to being 
a session only cookie.

=head2 PerlSetVar WhatEverPath

Sets the path that can retrieve the cookie. The default is /.

=head2 PerlSetVar WhatEverDomain

Defaults to current server name, set to what ever domain
you wish to be able to access the cookie.

=head2 PerlSetVar WhatEverSecure

Not set as default, set to 1 if you wish for cookies to
only be returned to a secure (https) server.

=head2 PerlSetVar ntlmdebug

Setting this value means debugging information is shown in the
apache error log, this value is also used for Apache::AuthenNTLM.
Default to 0, set to 1 or 2 for more debugging info.


=head1 OVERRIDEABLE METHODS

=head2 choose_cookie_values()

The method can be overwritten to set the values stored in the cookie

=head2 Example for overriding

This is an example how to set your cookie values with whatever 
data you what, into our global variable $cookie_values which 
is a hash reference.

  package Apache::AuthCookieNTLM::MYAuthenNTLM;

  use Apache::AuthCookieNTLM;	
  use base ( 'Apache::AuthCookieNTLM' );

  sub choose_cookie_values {
    my $self = shift;

    # Save to global
    if ($cookie_values eq {} || $cookie_values->{username} ne $self->{username}) {
      $cookie_values->{username} = $self->{username};
      # look up from some package
      my $person = MyUserLookup_Package->new($self->{'username'});
      $cookie_values->{'email'} = $person->email();
      $cookie_values->{'shoe_size'} = $person->shoe_size();
    }
  }
  1;
  
=head1 AUTHOR

Leo Lapworth <llap@cuckoo.org>, Francoise Dehinbo

=cut