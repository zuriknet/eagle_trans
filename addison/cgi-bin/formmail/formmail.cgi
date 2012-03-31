#!/usr/bin/perl
##############################################################################
# FormMail                        Version 1.92                               #
# Copyright 1995-2002 Matt Wright mattw@scriptarchive.com                    #
# Created 06/09/95                Last Modified 04/21/02                     #
# Matt's Script Archive, Inc.:    http://www.scriptarchive.com/              #
##############################################################################
# COPYRIGHT NOTICE                                                           #
# Copyright 1995-2002 Matthew M. Wright  All Rights Reserved.                #
#                                                                            #
# FormMail may be used and modified free of charge by anyone so long as this #
# copyright notice and the comments above remain intact.  By using this      #
# code you agree to indemnify Matthew M. Wright from any liability that      #
# might arise from its use.                                                  #
#                                                                            #
# Selling the code for this program without prior written consent is         #
# expressly forbidden.  In other words, please ask first before you try and  #
# make money off of my program.                                              #
#                                                                            #
# Obtain permission before redistributing this software over the Internet or #
# in any other medium. In all cases copyright and header must remain intact. #
##############################################################################
# ACCESS CONTROL FIX: Peter D. Thompson Yezek                                #
#                     http://www.securityfocus.com/archive/1/62033           #
##############################################################################
# Define Variables                                                           #
#      Detailed Information Found In README File.                            #

# $mailprog defines the location of your sendmail program on your unix       #
# system. The flags -i and -t should be passed to sendmail in order to       #
# have it ignore single dots on a line and to read message for recipients    #

$mailprog = '/usr/sbin/sendmail -i -t';

# @referers allows forms to be located only on servers which are defined     #
# in this field.  This security fix from the last version which allowed      #
# anyone on any server to use your FormMail script on their web site.        #

@referers = ('eagleaddison.com');

# @recipients defines the e-mail addresses or domain names that e-mail can   #
# be sent to.  This must be filled in correctly to prevent SPAM and allow    #
# valid addresses to receive e-mail.  Read the documentation to find out how #
# this variable works!!!  It is EXTREMELY IMPORTANT.                         #
@recipients = &fill_recipients(@referers);

# ACCESS CONTROL FIX: Peter D. Thompson Yezek                                #
# @valid_ENV allows the sysadmin to define what environment variables can    #
# be reported via the env_report directive.  This was implemented to fix     #
# the problem reported at http://www.securityfocus.com/bid/1187              #

@valid_ENV = ('REMOTE_HOST','REMOTE_ADDR','REMOTE_USER','HTTP_USER_AGENT');

# Done                                                                       #
##############################################################################

# Check Referring URL
&check_url;

# Retrieve Date
&get_date;

# Parse Form Contents
&parse_form;

# Check Required Fields
&check_required;

# Send E-Mail
&send_mail;

# Return HTML Page or Redirect User
&return_html;

# NOTE rev1.91: This function is no longer intended to stop abuse, that      #
#    functionality is now embedded in the checks made on @recipients and the #
#    recipient form field.                                                   #

sub check_url {

    # Localize the check_referer flag which determines if user is valid.     #
    local($check_referer) = 0;

    # If a referring URL was specified, for each valid referer, make sure    #
    # that a valid referring URL was passed to FormMail.                     #

    if ($ENV{'HTTP_REFERER'}) {
        foreach $referer (@referers) {
            if ($ENV{'HTTP_REFERER'} =~ m|https?://([^/]*)$referer|i) {
                $check_referer = 1;
                last;
            }
        }
    }
    else {
        $check_referer = 1;
    }

    # If the HTTP_REFERER was invalid, send back an error.                   #
    if ($check_referer != 1) { &error('bad_referer') }
}

sub get_date {

    # Define arrays for the day of the week and month of the year.           #
    @days   = ('Sunday','Monday','Tuesday','Wednesday',
               'Thursday','Friday','Saturday');
    @months = ('January','February','March','April','May','June','July',
               'August','September','October','November','December');

    # Get the current time and format the hour, minutes and seconds.  Add    #
    # 1900 to the year to get the full 4 digit year.                         #
    ($sec,$min,$hour,$mday,$mon,$year,$wday) = (localtime(time))[0,1,2,3,4,5,6];
    $time = sprintf("%02d:%02d:%02d",$hour,$min,$sec);
    $year += 1900;

    # Format the date.                                                       #
    $date = "$days[$wday], $months[$mon] $mday, $year at $time";

}

sub parse_form {

    # Define the configuration associative array.                            #
    %Config = ('recipient','',          'subject','',
               'email','',              'realname','',
               'redirect','',           'bgcolor','',
               'background','',         'link_color','',
               'vlink_color','',        'text_color','',
               'alink_color','',        'title','',
               'sort','',               'print_config','',
               'required','',           'env_report','',
               'return_link_title','',  'return_link_url','',
               'print_blank_fields','', 'missing_fields_redirect','');

    # Determine the form's REQUEST_METHOD (GET or POST) and split the form   #
    # fields up into their name-value pairs.  If the REQUEST_METHOD was      #
    # not GET or POST, send an error.                                        #
    if ($ENV{'REQUEST_METHOD'} eq 'GET') {
        # Split the name-value pairs
        @pairs = split(/&/, $ENV{'QUERY_STRING'});
    }
    elsif ($ENV{'REQUEST_METHOD'} eq 'POST') {
        # Get the input
        read(STDIN, $buffer, $ENV{'CONTENT_LENGTH'});
 
        # Split the name-value pairs
        @pairs = split(/&/, $buffer);
    }
    else {
        &error('request_method');
    }

    # For each name-value pair:                                              #
    foreach $pair (@pairs) {

        # Split the pair up into individual variables.                       #
        local($name, $value) = split(/=/, $pair);
 
        # Decode the form encoding on the name and value variables.          #
        # v1.92: remove null bytes                                           #
        $name =~ tr/+/ /;
        $name =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
        $name =~ tr/\0//d;

        $value =~ tr/+/ /;
        $value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
        $value =~ tr/\0//d;

        # If the field name has been specified in the %Config array, it will #
        # return a 1 for defined($Config{$name}}) and we should associate    #
        # this value with the appropriate configuration variable.  If this   #
        # is not a configuration form field, put it into the associative     #
        # array %Form, appending the value with a ', ' if there is already a #
        # value present.  We also save the order of the form fields in the   #
        # @Field_Order array so we can use this order for the generic sort.  #
        if (defined($Config{$name})) {
            $Config{$name} = $value;
        }
        else {
            if ($Form{$name} ne '') {
                $Form{$name} = "$Form{$name}, $value";
            }
            else {
                push(@Field_Order,$name);
                $Form{$name} = $value;
            }
        }
    }

    # The next six lines remove any extra spaces or new lines from the       #
    # configuration variables, which may have been caused if your editor     #
    # wraps lines after a certain length or if you used spaces between field #
    # names or environment variables.                                        #
    $Config{'required'} =~ s/(\s+|\n)?,(\s+|\n)?/,/g;
    $Config{'required'} =~ s/(\s+)?\n+(\s+)?//g;
    $Config{'env_report'} =~ s/(\s+|\n)?,(\s+|\n)?/,/g;
    $Config{'env_report'} =~ s/(\s+)?\n+(\s+)?//g;
    $Config{'print_config'} =~ s/(\s+|\n)?,(\s+|\n)?/,/g;
    $Config{'print_config'} =~ s/(\s+)?\n+(\s+)?//g;

    # Split the configuration variables into individual field names.         #
    @Required = split(/,/,$Config{'required'});
    @Env_Report = split(/,/,$Config{'env_report'});
    @Print_Config = split(/,/,$Config{'print_config'});

    # ACCESS CONTROL FIX: Only allow ENV variables in @valid_ENV in          #
    # @Env_Report for security reasons.                                      #
    foreach $env_item (@Env_Report) {
        foreach $valid_item (@valid_ENV) {
            if ( $env_item eq $valid_item ) { push(@temp_array, $env_item) }
        }
    } 
    @Env_Report = @temp_array;
}

sub check_required {

    # Localize the variables used in this subroutine.                        #
    local($require, @error);

    # The following insures that there were no newlines in any fields which  #
    # will be used in the header.                                            #
    if ($Config{'subject'} =~ /(\n|\r)/m || $Config{'email'} =~ /(\n|\r)/m ||
        $Config{'realname'} =~ /(\n|\r)/m || $Config{'recipient'} =~ /(\n|\r)/m) {
        &error('invalid_headers');
    }

    if (!$Config{'recipient'}) {
        if (!defined(%Form)) { &error('bad_referer') }
        else                 { &error('no_recipient') }
    }
    else {
        # This block of code requires that the recipient address end with    #
        # a valid domain or e-mail address as defined in @recipients.        #
        $valid_recipient = 0;
        foreach $send_to (split(/,/,$Config{'recipient'})) {
            foreach $recipient (@recipients) {
                if ($send_to =~ /$recipient$/i) {
                    push(@send_to,$send_to); last;
                }
            }
        }
        if ($#send_to < 0) { &error('no_recipient') }
        $Config{'recipient'} = join(',',@send_to);
    }

    # For each require field defined in the form:                            #
    foreach $require (@Required) {

        # If the required field is the email field, the syntax of the email  #
        # address if checked to make sure it passes a valid syntax.          #
        if ($require eq 'email' && !&check_email($Config{$require})) {
            push(@error,$require);
        }

        # Otherwise, if the required field is a configuration field and it   #
        # has no value or has been filled in with a space, send an error.    #
        elsif (defined($Config{$require})) {
            if ($Config{$require} eq '') { push(@error,$require); }
        }

        # If it is a regular form field which has not been filled in or      #
        # filled in with a space, flag it as an error field.                 #
        elsif (!defined($Form{$require}) || $Form{$require} eq '') {
            push(@error,$require);
        }
    }

    # If any error fields have been found, send error message to the user.   #
    if (@error) { &error('missing_fields', @error) }
}

sub return_html {
    # Local variables used in this subroutine initialized.                   #
    local($key,$sort_order,$sorted_field);

    # Now that we have finished using form values for any e-mail related     #
    # reasons, we will convert all of the form fields and config values      #
    # to remove any cross-site scripting security holes.                     #
    local($field);
    foreach $field (keys %Config) {
        $safeConfig{$field} = &clean_html($Config{$field});
    }

    foreach $field (keys %Form) {
        $Form{$field} = &clean_html($Form{$field});
    }


    # If redirect option is used, print the redirectional location header.   #
    if ($Config{'redirect'}) {
        print "Location: $safeConfig{'redirect'}\n\n";
    }

    # Otherwise, begin printing the response page.                           #
    else {

        # Print HTTP header and opening HTML tags.                           #
        print "Content-type: text/html\n\n";
        print "<html>\n <head>\n";

        # Print out title of page                                            #
        if ($Config{'title'}) { print "<title>$safeConfig{'title'}</title>\n" }
        else                  { print "<title>Thank You</title>\n"        }

        print " </head>\n <body";

        # Get Body Tag Attributes                                            #
        &body_attributes;

        # Close Body Tag                                                     #
        print ">\n  <center>\n";

        # Print custom or generic title.                                     #
        if ($Config{'title'}) { print "<h1>$safeConfig{'title'}</h1>\n" }
        else { print "<h1>Thank You For Filling Out This Form</h1>\n" }

        print "</center>\n";

        print "Below is what you submitted to $safeConfig{'recipient'} on ";
        print "$date<p><hr size=1 width=75\%><p>\n";

        # If a sort order is specified, sort the form fields based on that.  #
        if ($Config{'sort'} =~ /^order:.*,.*/) {

            # Set the temporary $sort_order variable to the sorting order,   #
            # remove extraneous line breaks and spaces, remove the order:    #
            # directive and split the sort fields into an array.             #
            $sort_order = $Config{'sort'};
            $sort_order =~ s/(\s+|\n)?,(\s+|\n)?/,/g;
            $sort_order =~ s/(\s+)?\n+(\s+)?//g;
            $sort_order =~ s/order://;
            @sorted_fields = split(/,/, $sort_order);

            # For each sorted field, if it has a value or the print blank    #
            # fields option is turned on print the form field and value.     #
            foreach $sorted_field (@sorted_fields) {
                local $sfname = &clean_html($sorted_field);

                if ($Config{'print_blank_fields'} || $Form{$sorted_field} ne '') {
                    print "<b>$sfname:</b> $Form{$sorted_field}<p>\n";
                }
            }
        }

        # Otherwise, use the order the fields were sent, or alphabetic.      #
        else {

            # Sort alphabetically if requested.
            if ($Config{'sort'} eq 'alphabetic') {
                @Field_Order = sort @Field_Order;
            }

            # For each form field, if it has a value or the print blank      #
            # fields option is turned on print the form field and value.     #
            foreach $field (@Field_Order) {
                local $fname = &clean_html($field);

                if ($Config{'print_blank_fields'} || $Form{$field} ne '') {
                    print "<b>$fname:</b> $Form{$field}<p>\n";
                }
            }
        }

        print "<p><hr size=1 width=75%><p>\n";

        # Check for a Return Link and print one if found.                    #
        if ($Config{'return_link_url'} && $Config{'return_link_title'}) {
            print "<ul>\n";
            print "<li><a href=\"$safeConfig{'return_link_url'}\">$safeConfig{'return_link_title'}</a>\n";
            print "</ul>\n";
        }

        # Print the page footer.                                             #
        print <<"(END HTML FOOTER)";
        <hr size=1 width=75%><p> 
        <center><font size=-1><a href="http://www.scriptarchive.com/formmail.html">FormMail</a> V1.92 &copy; 1995 - 2002  Matt Wright<br>
A Free Product of <a href="http://www.scriptarchive.com/">Matt's Script Archive, Inc.</a></font></center>
        </body>
       </html>
(END HTML FOOTER)
    }
}

sub send_mail {
    # Localize variables used in this subroutine.                            #
    local($print_config,$key,$sort_order,$sorted_field,$env_report);

    # Open The Mail Program
    open(MAIL,"|$mailprog");

    print MAIL "To: $Config{'recipient'}\n";
    print MAIL "From: $Config{'email'} ($Config{'realname'})\n";

    # Check for Message Subject
    if ($Config{'subject'}) { print MAIL "Subject: $Config{'subject'}\n\n" }
    else                    { print MAIL "Subject: WWW Form Submission\n\n" }

    print MAIL "Below is the result of your feedback form.  It was submitted by\n";
    print MAIL "$Config{'realname'} ($Config{'email'}) on $date\n";
    print MAIL "-" x 75 . "\n\n";

    if (@Print_Config) {
        foreach $print_config (@Print_Config) {
            if ($Config{$print_config}) {
                print MAIL "$print_config: $Config{$print_config}\n\n";
            }
        }
    }

    # If a sort order is specified, sort the form fields based on that.      #
    if ($Config{'sort'} =~ /^order:.*,.*/) {

        # Remove extraneous line breaks and spaces, remove the order:        #
        # directive and split the sort fields into an array.                 #
        local $sort_order = $Config{'sort'};
        $sort_order =~ s/(\s+|\n)?,(\s+|\n)?/,/g;
        $sort_order =~ s/(\s+)?\n+(\s+)?//g;
        $sort_order =~ s/order://;
        @sorted_fields = split(/,/, $sort_order);

        # For each sorted field, if it has a value or the print blank        #
        # fields option is turned on print the form field and value.         #
        foreach $sorted_field (@sorted_fields) {
            if ($Config{'print_blank_fields'} || $Form{$sorted_field} ne '') {
                print MAIL "$sorted_field: $Form{$sorted_field}\n\n";
            }
        }
    }

    # Otherwise, print fields in order they were sent or alphabetically.     #
    else {

        # Sort alphabetically if specified:                                  #
        if ($Config{'sort'} eq 'alphabetic') {
            @Field_Order = sort @Field_Order;
        }

        # For each form field, if it has a value or the print blank          #
        # fields option is turned on print the form field and value.         #
        foreach $field (@Field_Order) {
            if ($Config{'print_blank_fields'} || $Form{$field} ne '') {
                print MAIL "$field: $Form{$field}\n\n";
            }
        }
    }

    print MAIL "-" x 75 . "\n\n";

    # Send any specified Environment Variables to recipient.                 #
    foreach $env_report (@Env_Report) {
        if ($ENV{$env_report}) {
            print MAIL "$env_report: $ENV{$env_report}\n";
        }
    }

    close (MAIL);
}

sub check_email {
    # Initialize local email variable with input to subroutine.              #
    $email = $_[0];

    # If the e-mail address contains:                                        #
    if ($email =~ /(@.*@)|(\.\.)|(@\.)|(\.@)|(^\.)/ ||

        # the e-mail address contains an invalid syntax.  Or, if the         #
        # syntax does not match the following regular expression pattern     #
        # it fails basic syntax verification.                                #

        $email !~ /^.+\@(\[?)[a-zA-Z0-9\-\.]+\.([a-zA-Z0-9]+)(\]?)$/) {

        # Basic syntax requires:  one or more characters before the @ sign,  #
        # followed by an optional '[', then any number of letters, numbers,  #
        # dashes or periods (valid domain/IP characters) ending in a period  #
        # and then 2 or 3 letters (for domain suffixes) or 1 to 3 numbers    #
        # (for IP addresses).  An ending bracket is also allowed as it is    #
        # valid syntax to have an email address like: user@[255.255.255.0]   #

        # Return a false value, since the e-mail address did not pass valid  #
        # syntax.                                                            #
        return 0;
    }

    else {

        # Return a true value, e-mail verification passed.                   #
        return 1;
    }
}

# This was added into v1.91 to further secure the recipients array.  Now, by #
# default it will assume that valid recipients include only users with       #
# usernames A-Z, a-z, 0-9, _ and - that match your domain exactly.  If this  #
# is not what you want, you should read more detailed instructions regarding #
# the configuration of the @recipients variable in the documentation.        #
sub fill_recipients {
    local(@domains) = @_;
    local($domain,@return_recips);

    foreach $domain (@domains) {
        if ($domain =~ /^\d+\.\d+\.\d+\.\d+$/) {
            $domain =~ s/\./\\\./g;
            push(@return_recips,'^[\w\-\.]+\@\[' . $domain . '\]');
        }
        else {
            $domain =~ s/\./\\\./g;
            $domain =~ s/\-/\\\-/g;
            push(@return_recips,'^[\w\-\.]+\@' . $domain);
        }
    }

    return @return_recips;
}

# This function will convert <, >, & and " to their HTML equivalents.        #
sub clean_html {
    local $value = $_[0];
    $value =~ s/\&/\&amp;/g;
    $value =~ s/</\&lt;/g;
    $value =~ s/>/\&gt;/g;
    $value =~ s/"/\&quot;/g;
    return $value;
}

sub body_attributes {
    # Check for Background Color
    if ($Config{'bgcolor'}) { print " bgcolor=\"$safeConfig{'bgcolor'}\"" }

    # Check for Background Image
    if ($Config{'background'}) { print " background=\"$safeConfig{'background'}\"" }

    # Check for Link Color
    if ($Config{'link_color'}) { print " link=\"$safeConfig{'link_color'}\"" }

    # Check for Visited Link Color
    if ($Config{'vlink_color'}) { print " vlink=\"$safeConfig{'vlink_color'}\"" }

    # Check for Active Link Color
    if ($Config{'alink_color'}) { print " alink=\"$safeConfig{'alink_color'}\"" }

    # Check for Body Text Color
    if ($Config{'text_color'}) { print " text=\"$safeConfig{'text_color'}\"" }
}

sub error { 
    # Localize variables and assign subroutine input.                        #
    local($error,@error_fields) = @_;
    local($host,$missing_field,$missing_field_list);

    if ($error eq 'bad_referer') {
        if ($ENV{'HTTP_REFERER'} =~ m|^https?://([\w\.]+)|i) {
            $host = $1;
            my $referer = &clean_html($ENV{'HTTP_REFERER'});
            print <<"(END ERROR HTML)";
Content-type: text/html

<html>
 <head>
  <title>Bad Referrer - Access Denied</title>
 </head>
 <body bgcolor=#FFFFFF text=#000000>
  <center>
   <table border=0 width=600 bgcolor=#9C9C9C>
    <tr><th><font size=+2>Bad Referrer - Access Denied</font></th></tr>
   </table>
   <table border=0 width=600 bgcolor=#CFCFCF>
    <tr><td>The form attempting to use
     <a href="http://www.scriptarchive.com/formmail.html">FormMail</a>
     resides at <tt>$referer</tt>, which is not allowed to access
     this cgi script.<p>

     If you are attempting to configure FormMail to run with this form, you need
     to add the following to \@referers, explained in detail in the 
     <a href="http://www.scriptarchive.com/readme/formmail.html">README</a> file.<p>

     Add <tt>'$host'</tt> to your <tt><b>\@referers</b></tt> array.<hr size=1>
     <center><font size=-1>
      <a href="http://www.scriptarchive.com/formmail.html">FormMail</a> V1.92 &copy; 1995 - 2002  Matt Wright<br>
      A Free Product of <a href="http://www.scriptarchive.com/">Matt's Script Archive, Inc.</a>
     </font></center>
    </td></tr>
   </table>
  </center>
 </body>
</html>
(END ERROR HTML)
        }
        else {
            print <<"(END ERROR HTML)";
Content-type: text/html

<html>
 <head>
  <title>FormMail v1.92</title>
 </head>
 <body bgcolor=#FFFFFF text=#000000>
  <center>
   <table border=0 width=600 bgcolor=#9C9C9C>
    <tr><th><font size=+2>FormMail</font></th></tr>
   </table>
   <table border=0 width=600 bgcolor=#CFCFCF>
    <tr><th><tt><font size=+1>Copyright 1995 - 2002 Matt Wright<br>
        Version 1.92 - Released April 21, 2002<br>
        A Free Product of <a href="http://www.scriptarchive.com/">Matt's Script Archive,
        Inc.</a></font></tt></th></tr>
   </table>
  </center>
 </body>
</html>
(END ERROR HTML)
        }
    }

    elsif ($error eq 'request_method') {
            print <<"(END ERROR HTML)";
Content-type: text/html

<html>
 <head>
  <title>Error: Request Method</title>
 </head>
 <body bgcolor=#FFFFFF text=#000000>
  <center>
   <table border=0 width=600 bgcolor=#9C9C9C>
    <tr><th><font size=+2>Error: Request Method</font></th></tr>
   </table>
   <table border=0 width=600 bgcolor=#CFCFCF>
    <tr><td>The Request Method of the Form you submitted did not match
     either <tt>GET</tt> or <tt>POST</tt>.  Please check the form and make sure the
     <tt>method=</tt> statement is in upper case and matches <tt>GET</tt> or <tt>POST</tt>.<p>

     <center><font size=-1>
      <a href="http://www.scriptarchive.com/formmail.html">FormMail</a> V1.92 &copy; 1995 - 2002  Matt Wright<br>
      A Free Product of <a href="http://www.scriptarchive.com/">Matt's Script Archive, Inc.</a>
     </font></center>
    </td></tr>
   </table>
  </center>
 </body>
</html>
(END ERROR HTML)
    }

    elsif ($error eq 'no_recipient') {
            print <<"(END ERROR HTML)";
Content-type: text/html

<html>
 <head>
  <title>Error: Bad/No Recipient</title>
 </head>
 <body bgcolor=#FFFFFF text=#000000>
  <center>
   <table border=0 width=600 bgcolor=#9C9C9C>
    <tr><th><font size=+2>Error: Bad/No Recipient</font></th></tr>
   </table>
   <table border=0 width=600 bgcolor=#CFCFCF>
    <tr><td>There was no recipient or an invalid recipient specified in the data sent to FormMail.  Please
     make sure you have filled in the <tt>recipient</tt> form field with an e-mail
     address that has been configured in <tt>\@recipients</tt>.  More information on filling in <tt>recipient</tt> form fields and variables can be
     found in the <a href="http://www.scriptarchive.com/readme/formmail.html">README</a> file.<hr size=1>

     <center><font size=-1>
      <a href="http://www.scriptarchive.com/formmail.html">FormMail</a> V1.92 &copy; 1995 - 2002  Matt Wright<br>
      A Free Product of <a href="http://www.scriptarchive.com/">Matt's Script Archive, Inc.</a>
     </font></center>
    </td></tr>
   </table>
  </center>
 </body>
</html>
(END ERROR HTML)
    }

    elsif ($error eq 'invalid_headers') {
            print <<"(END ERROR HTML)";
Content-type: text/html
<html>
 <head>
  <title>Error: Bad/No Recipient</title>
 </head>
 <body bgcolor=#FFFFFF text=#000000>
  <center>
   <table border=0 width=600 bgcolor=#9C9C9C>
    <tr><th><font size=+2>Error: Bad/No Recipient</font></th></tr>
   </table>
   <table border=0 width=600 bgcolor=#CFCFCF>
    <tr><td>There was no recipient or an invalid recipient specified in the data sent to FormMail.  Please
     make sure you have filled in the <tt>recipient</tt> form field with an e-mail
     address that has been configured in <tt>\@recipients</tt>.  More information on filling in <tt>recipient</tt> form fields and variables can be
     found in the <a href="http://www.scriptarchive.com/readme/formmail.html">README</a> file.<hr size=1>

     <center><font size=-1>
      <a href="http://www.scriptarchive.com/formmail.html">FormMail</a> V1.92 &copy; 1995 - 2002  Matt Wright<br>
      A Free Product of <a href="http://www.scriptarchive.com/">Matt's Script Archive, Inc.</a>
     </font></center>
    </td></tr>
   </table>
  </center>
 </body>
</html>
(END ERROR HTML)
    }

    elsif ($error eq 'invalid_headers') {
            print <<"(END ERROR HTML)";
Content-type: text/html

<html>
 <head>
  <title>Error: Bad Header Fields</title>
 </head>
 <body bgcolor=#FFFFFF text=#000000>
  <center>
   <table border=0 width=600 bgcolor=#9C9C9C>
    <tr><th><font size=+2>Error: Bad Header Fields</font></th></tr>
   </table>
   <table border=0 width=600 bgcolor=#CFCFCF>
    <tr><td>The header fields, which include <tt>recipient</tt>, <tt>email</tt>, <tt>realname</tt> and <tt>subject</tt> were
     filled in with invalid values. You may not include any newline characters in these parameters.
     More information on filling in these form fields and variables can be
     found in the <a href="http://www.scriptarchive.com/readme/formmail.html">README</a> file.<hr size=1>

     <center><font size=-1>
      <a href="http://www.scriptarchive.com/formmail.html">FormMail</a> V1.92 &copy; 1995 - 2002  Matt Wright<br>
      A Free Product of <a href="http://www.scriptarchive.com/">Matt's Script Archive, Inc.</a>
     </font></center>
    </td></tr>
   </table>
  </center>
 </body>
</html>
(END ERROR HTML)
    }

    elsif ($error eq 'missing_fields') {
        if ($Config{'missing_fields_redirect'}) {
            print "Location: " . &clean_html($Config{'missing_fields_redirect'}) . "\n\n";
        }
        else {
            foreach $missing_field (@error_fields) {
                $missing_field_list .= "<li>" . &clean_html($missing_field) . "\n";
            }

            print <<"(END ERROR HTML)";
Content-type: text/html

<HTML xmlns="http://www.w3.org/1999/xhtml"><HEAD>

<title>Dallas Electrician - Leading online source for people seeking
electricians in Dallas Fort Worth and the surrounding areas.</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" /><style type="text/css">
<!--
.line {background:url(images/dotted_div_hor.gif;
	height:1px;
	background: url(img/dotted_div_hor.gif);
	width: 167px;
}
body {
	margin-left: 0px;
	margin-top: 0px;
	margin-right: 0px;
	margin-bottom: 0px;
}
.style3 {font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 11px; font-weight: bold; color: #969696; }
.style4 {
	font-family: Arial, Helvetica, sans-serif;
	font-style: italic;
	font-weight: bold;
	color: #990000;
	font-size: 15px;
}
.style7 {font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 11px; font-weight: bold; color: #333333; }
a:link {
	color: #999999;
	text-decoration: none;
}
a:visited {
	color: #999999;
	text-decoration: none;
}
a:hover {
	color: #003399;
	text-decoration: underline;
}
a:active {
	color: #003399;
	text-decoration: none;
}
.style8 {font-size: 4px}
#Layer1 {
	position:absolute;
	width:280px;
	height:90px;
	z-index:1;
	left: 610px;
	top: 331px;
}
.style38 {	font-family: Verdana, Arial, Helvetica, sans-serif;
	font-size: 10px;
}
.style53 {font-size: 11px; font-family: Verdana, Arial, Helvetica, sans-serif; font-weight: bold; color: #000000; }
.style59 {font-size: 12px; color: #333333; font-family: Verdana, Arial, Helvetica, sans-serif;}
.style63 {font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 16px; font-weight: bold; color: #2D5E99; }
.style64 {font-size: 11px}
.style65 {font-family: Verdana, Arial, Helvetica, sans-serif}
.style66 {
	font-size: 14px;
	font-weight: bold;
	color: #666666;
}
.style78 {font-family: Arial, Helvetica, sans-serif;
	font-style: italic;
	font-size: 14px;
	color: #990000;
	font-weight: bold;
}
-->
</style>
</head>

<body>
 <br />
<table width="770" border="0" align="center" cellpadding="0" cellspacing="0">
  <tr>
    <td width="219" valign="top"><a href="index.html"><img src="img/top_logo.jpg" alt="Dallas Electrician" width="214" height="84" border="0" /></a></td>
    <td width="556" valign="top"><table width="100%" border="0" cellspacing="0" cellpadding="0">
      <tr>
        <td colspan="12">&nbsp;</td>
      </tr>
      <tr>
        <td width="47" rowspan="2">&nbsp;</td>
        <td width="47" rowspan="2" valign="middle"><span class="style3"><a href="index.html">HOME</a></span></td>
        <td width="2" rowspan="2" valign="middle" bgcolor="#FFFFFF"><img src="img/div.jpg" width="2" height="38" /></td>
        <td width="11" rowspan="2" valign="middle">&nbsp;</td>
        <td width="105" rowspan="2" valign="middle"><span class="style3"><a href="services.htm">OUR SERVICES</a></span></td>
        <td width="8" rowspan="2" valign="middle"><img src="img/div.jpg" width="2" height="38" /></td>
        <td width="94" rowspan="2" valign="middle"><span class="style3"><a href="employment.htm">EMPLOYMENT</a></span></td>
        <td width="9" rowspan="2" valign="middle"><img src="img/div.jpg" width="2" height="38" /></td>
        <td width="76" rowspan="2" valign="middle"><span class="style3"><a href="about.htm">ABOUT US</a> </span></td>
        <td width="19" rowspan="2" valign="middle"><img src="img/div.jpg" width="2" height="38" /></td>
        <td width="21" valign="middle"><img src="img/mail.jpg" width="15" height="9" /></td>
        <td width="117" valign="top"><p><span class="style3"><a href="contact.htm">Contact Us</a></span></p>          </td>
      </tr>
      <tr>
        <td valign="middle"><img src="img/phone.jpg" width="15" height="13" /></td>
        <td width="117" valign="middle"><span class="style7">          972.636.3911</span></td>
      </tr>
      <tr>
        <td height="4" colspan="12"><span class="style8">&nbsp;</span></td>
      </tr>
      <tr>
        <td colspan="12"><div align="right" class="style4"><span class="style78">&quot;Your Trusted Neighborhood Electrician That Is Clean   And Shows Up On Time!&quot; </span></div></td>
      </tr>
    </table>      </td>
  </tr>
  <tr>
    <td colspan="2" valign="top"><a href="http://www.bbbonline.org/cks.asp?id=105092685459"><img src="http://www.milestoneservice.com/new/img/toplogo.jpg" width="770" height="205" border="0" usemap="#MapMap2" />
        <map name="MapMap2" id="MapMap2">
          <area shape="rect" coords="667,11,763,110" href="http://www.bbbonline.org/cks.asp?id=105092685459" />
        </map>
    </a></td>
  </tr>
  <tr>
    <td colspan="2" valign="top"><table width="100%" border="0" cellspacing="2" cellpadding="2">
        <tr>
          <td width="66%" valign="top"><p align="left"><form name="Contact Form" method="post" action="http://www.milestoneservice.com/cgi-bin/formmail/formmail.cgi">
          <p><font face="Arial" color="#41444B" style="font-size: 9pt"><strong><span class="style13"></span></strong></font>
<input type="hidden" name="recipient" value="gus@milestoneservice.com,eric@milestoneservice.com,mark@milestoneservice.com,ccr@milestoneservice.com,james@milestoneservice.com,sondra@milestoneservice.com" />
              <input type="hidden" name="redirect" value="http://www.milestoneserive.com/new/thankyou.htm">
              <input type="hidden" name="subject" value="Milestone Service">
              <font class="style7"><small></small></font><font class="style7"><small></small></font>  
              <input type="hidden" name="required" value="realname, email, Phone, Concerning, For, Comments">
              <font class="style7"><small><A 
                  href="http://www.mapquest.com/maps/map.adp?searchtype=address&amp;country=US&amp;addtohistory=&amp;searchtab=home&amp;address=6005+Dalrock+Rd&amp;city=Rowlett&amp;state=TX&amp;zipcode=75088" 
                  target=_blank></A><A name=admin><span class="style59"><b><b><b><span class="style63">One or more fields have been left blank:  </span><br />
              <img src="http://www.milestoneservice.com/new/img/bottom.jpg" width="495" height="2" vspace="5" /><br />
              <p></font><font face="arial" color="#DF0102" style="font-size:12px">     <ul>
$missing_field_list
  
     </ul></font><br>
<font face="arial" color="#000000" style="font-size:12px"
     These fields must be filled in before you can successfully submit the form.<p>
     Please use your browser's back button to return to the form and try again.</font></td>
    </tr>
   </table>					
                  </FORM>
            </b></b></b></span></p>
          </td>
          <td width="34%" valign="top">&nbsp;</td>
        </tr>
      </table>      </td>
  </tr>
  <tr>
    <td colspan="2" valign="top"><div align="right"><img src="img/bottom.jpg" width="770" height="1" vspace="5" /><br />
      <span class="style38"><a href="index.html">home</a> / <a href="privacy.htm">privacy</a> / <a href="contact.htm">contact us</a> / <a href="about.htm">about us</a> / <a href="links.htm">helpful links</a> / <a href="sitemap.htm">sitemap</a><br />
      <img src="img/bottom.jpg" width="770" height="1" vspace="5" /><br />
      <br />
    </span></div></td>
  </tr>
  <tr>
    <td valign="bottom" bordercolor="#FFFFFF" bgcolor="#EDEDED">&nbsp;</td>
    <td bgcolor="#EDEDED"><div align="right"><a href="http://www.statcounter.com/" target="_blank"><span class="style53">Web Visitors:</span></a><!-- Start of StatCounter Code -->
        <script type="text/javascript" language="javascript">var sc_project=603887; 
var sc_invisible=0; 
var sc_partition=4; 
var sc_security="349edbf7"; 
</script>

<script type="text/javascript" language="javascript" src="http://www.statcounter.com/counter/counter.js"></script><noscript><a href="http://www.statcounter.com/" target="_blank"><img  src="http://c5.statcounter.com/counter.php?sc_project=603887&amp;java=0&amp;security=349edbf7&amp;invisible=0" alt="counter free hit invisible" border="0" align="absmiddle"></a> 
</noscript>
<!-- End of StatCounter Code -->
    </div></td>
  </tr>
  <tr>
    <td colspan="2" valign="top"><div align="center"><img src="img/bottom_bott.jpg" width="770" height="17" vspace="5" /></div></td>
  </tr>
</table>

<p>&nbsp;</p>
<p>
  <map name="Map" id="Map">
    <area shape="rect" coords="72,80,172,108" href="#" />
  </map>
  <map name="Map2" id="Map2">
    <area shape="rect" coords="111,126,177,145" href="#" />
  </map>
  <map name="Map3" id="Map3">
    <area shape="rect" coords="103,120,169,143" href="#" />
  </map></p>

<map name="Map5" id="Map5"><area shape="rect" coords="1,28,195,93" href="http://www.mrluckylawn.com" target="_blank" alt="Mr Lucky Lawn and Landscape" />
<area shape="rect" coords="217,25,358,91" href="http://www.readyroofing.com" target="_blank" alt="Ready Roofing" />
<area shape="rect" coords="376,22,570,93" href="http://www.abralawn.com" target="_blank" alt="Abracadabra Lawn Pest &amp; Weed Control" />
</map>
</body>
</html>


(END ERROR HTML)
        }
    }

    exit;
}